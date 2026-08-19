"""Tests for the Marketplace CI/CD watch loop: version-change detection
against a fake MarketplaceClient, automatic redeploy through the real
MarketplaceDeploymentRunner, state persistence, and watch_forever's error
handling — the Marketplace-flow counterpart to test_watcher.py.
"""

import hashlib
import hmac
import io
import zipfile
from pathlib import Path

import pytest
import yaml

from xcore_agent.agent.errors import ArtifactError
from xcore_agent.agent.marketplace_client import FetchedArtifact
from xcore_agent.agent.marketplace_watcher import MarketplaceWatcher
from xcore_agent.agent.state_store import StateStore

SLUG = "demo-plugin"
SECRET = b"the-developers-signing-secret"


class FakeMarketplaceClient:
    """Structural stand-in for MarketplaceClient — no network access."""

    def __init__(
        self,
        *,
        latest_version: str,
        zip_bytes: bytes,
        signature_hex: str,
        plugin_header: str,
    ) -> None:
        self.latest_version = latest_version
        self._zip_bytes = zip_bytes
        self._signature_hex = signature_hex
        self._plugin_header = plugin_header
        self.get_latest_calls = 0
        self.fetch_calls: list[tuple[str, str, str]] = []
        self.report_calls: list[dict] = []

    async def get_latest_version(self, *, slug: str, kind: str = "plugin") -> str:
        self.get_latest_calls += 1
        return self.latest_version

    async def fetch_artifact(self, *, slug: str, version: str = "latest", kind: str = "plugin"):
        self.fetch_calls.append((slug, version, kind))
        return FetchedArtifact(
            data=self._zip_bytes,
            signature_header=self._signature_hex,
            plugin_header=self._plugin_header,
            repo_header=f"acme/{SLUG}@{self.latest_version}",
        )

    async def report_deployment(self, **kwargs):
        self.report_calls.append(kwargs)


class FailingMarketplaceClient(FakeMarketplaceClient):
    async def get_latest_version(self, *, slug: str, kind: str = "plugin") -> str:
        raise RuntimeError("marketplace unreachable")


def _build_zipball(*, version: str, root_dir_name: str = "acme-demo-plugin-abc1234") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(f"{root_dir_name}/plugin.yaml", f"name: demo\nversion: {version}\n")
        zf.writestr(f"{root_dir_name}/main.py", "# demo plugin\n")
    return buf.getvalue()


def _sign(data: bytes) -> str:
    return "hmac_sha256:" + hmac.new(SECRET, data, hashlib.sha256).hexdigest()


def _write_install_plan(path: Path, *, version: str) -> None:
    plan = {
        "format_version": "1",
        "project_id": SLUG,
        "version": version,
        "steps": [
            {"id": "prepare", "action": "prepare"},
            {"id": "install_demo", "action": "install_plugin", "plugin": SLUG},
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(plan))


def _make_client(tmp_path: Path, *, version: str) -> FakeMarketplaceClient:
    zip_bytes = _build_zipball(version=version)
    return FakeMarketplaceClient(
        latest_version=version,
        zip_bytes=zip_bytes,
        signature_hex=_sign(zip_bytes),
        plugin_header=f"{SLUG}@{version}",
    )


def _make_watcher(tmp_path: Path, client) -> MarketplaceWatcher:
    plan_path = tmp_path / "install.yaml"
    _write_install_plan(plan_path, version=client.latest_version)
    return MarketplaceWatcher(
        client=client,
        slug=SLUG,
        trusted_signer_secret=SECRET,
        install_plan_path=plan_path,
        workdir_root=tmp_path / "work",
        project_root=tmp_path / "deployed",
    )


async def test_check_once_skips_when_version_unchanged(tmp_path):
    client = _make_client(tmp_path, version="1.0.0")
    project_root = tmp_path / "deployed"
    StateStore(project_root).write(project_id=SLUG, version="1.0.0")

    watcher = _make_watcher(tmp_path, client)
    result = await watcher.check_once()

    assert result.deployed is False
    assert result.checked_version == "1.0.0"
    assert client.fetch_calls == []


async def test_check_once_deploys_new_version_and_persists_state(tmp_path):
    client = _make_client(tmp_path, version="1.0.0")
    watcher = _make_watcher(tmp_path, client)

    result = await watcher.check_once()

    assert result.deployed is True
    assert result.report.status == "success"
    assert (tmp_path / "deployed" / "plugins" / SLUG / "plugin.yaml").is_file()

    state = StateStore(tmp_path / "deployed").read()
    assert state.version == "1.0.0"
    assert state.project_id == SLUG

    # The outcome was also reported to the Hub.
    assert len(client.report_calls) == 1
    assert client.report_calls[0]["status"] == "success"


async def test_check_once_is_idempotent_on_repeated_calls(tmp_path):
    client = _make_client(tmp_path, version="1.0.0")
    watcher = _make_watcher(tmp_path, client)

    first = await watcher.check_once()
    second = await watcher.check_once()

    assert first.deployed is True
    assert second.deployed is False
    assert len(client.fetch_calls) == 1


async def test_check_once_runs_gc_and_restarts_the_plugin(tmp_path):
    client = _make_client(tmp_path, version="1.0.0")

    class RecordingSupervisor:
        def __init__(self):
            self.restarted: list[str] = []

        def restart(self, plugin_id: str) -> None:
            self.restarted.append(plugin_id)

        def start(self, plugin_id: str) -> None:  # pragma: no cover - unused here
            pass

        def stop(self, plugin_id: str) -> None:  # pragma: no cover - unused here
            pass

        def healthcheck(self, plugin_id: str, *, timeout_seconds: int, retries: int) -> None:
            pass  # pragma: no cover - unused here

    supervisor = RecordingSupervisor()
    plan_path = tmp_path / "install.yaml"
    _write_install_plan(plan_path, version="1.0.0")
    watcher = MarketplaceWatcher(
        client=client,
        slug=SLUG,
        trusted_signer_secret=SECRET,
        install_plan_path=plan_path,
        workdir_root=tmp_path / "work",
        project_root=tmp_path / "deployed",
        supervisor=supervisor,
    )

    await watcher.check_once()

    assert supervisor.restarted == [SLUG]


async def test_watch_forever_reports_each_tick_and_stops(tmp_path):
    client = _make_client(tmp_path, version="1.0.0")
    watcher = _make_watcher(tmp_path, client)

    results = []
    tick_count = {"n": 0}

    async def stop_after_two():
        tick_count["n"] += 1
        return tick_count["n"] >= 2

    await watcher.watch_forever(
        interval_seconds=0, on_result=results.append, stop_after=stop_after_two
    )

    assert len(results) == 2
    assert results[0].deployed is True
    assert results[1].deployed is False


async def test_watch_forever_reports_errors_without_crashing(tmp_path):
    client = FailingMarketplaceClient(
        latest_version="1.0.0", zip_bytes=b"", signature_hex="", plugin_header=""
    )
    watcher = _make_watcher(tmp_path, client)

    errors = []
    tick_count = {"n": 0}

    async def stop_after_two():
        tick_count["n"] += 1
        return tick_count["n"] >= 2

    await watcher.watch_forever(
        interval_seconds=0, on_error=errors.append, stop_after=stop_after_two
    )

    assert len(errors) == 2
    assert all(isinstance(e, RuntimeError) for e in errors)


async def test_check_once_propagates_deployment_failure(tmp_path):
    client = _make_client(tmp_path, version="1.0.0")
    watcher = _make_watcher(tmp_path, client)
    watcher._trusted_signer_secret = b"wrong-secret"

    with pytest.raises(ArtifactError, match="HMAC"):
        await watcher.check_once()
