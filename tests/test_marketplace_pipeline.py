"""End-to-end tests for MarketplaceDeploymentRunner against a FakeMarketplaceClient
standing in for the real xcore-team/marketplace API. Builds a real GitHub-zipball
-shaped ZIP (single top-level directory, like GitHub's zipball API produces) and
signs it with real HMAC-SHA256, so extraction, flattening, signature
verification, install.yaml dispatch, and rollback are all exercised for real —
only the network transport is faked.
"""

import hashlib
import hmac
import io
import zipfile
from pathlib import Path

import pytest
import yaml

from xcore_agent.agent.errors import ArtifactError, DeploymentError
from xcore_agent.agent.marketplace_client import FetchedArtifact
from xcore_agent.agent.marketplace_pipeline import MarketplaceDeploymentRunner
from xcore_agent.agent.marketplace_state import MarketplaceDeploymentState

SLUG = "demo-plugin"
SECRET = b"the-developers-signing-secret"


class FakeMarketplaceClient:
    """Structural stand-in for MarketplaceClient — no network access."""

    def __init__(
        self, *, zip_bytes: bytes, signature_hex: str, plugin_header: str, fail_report: bool = False
    ) -> None:
        self._zip_bytes = zip_bytes
        self._signature_hex = signature_hex
        self._plugin_header = plugin_header
        self._fail_report = fail_report
        self.fetch_calls: list[tuple[str, str, str]] = []
        self.report_calls: list[dict] = []

    async def fetch_artifact(self, *, slug: str, version: str = "latest", kind: str = "plugin"):
        self.fetch_calls.append((slug, version, kind))
        return FetchedArtifact(
            data=self._zip_bytes,
            signature_header=self._signature_hex,
            plugin_header=self._plugin_header,
            repo_header="acme/demo-plugin@1.0.0",
        )

    async def report_deployment(self, **kwargs):
        self.report_calls.append(kwargs)
        if self._fail_report:
            raise ArtifactError("hub is down")


def _build_zipball(*, root_dir_name: str = "acme-demo-plugin-abc1234") -> bytes:
    """A ZIP shaped like GitHub's zipball API: one top-level directory wrapping
    the repo's actual files."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(f"{root_dir_name}/plugin.yaml", "name: demo\nversion: 1.0.0\n")
        zf.writestr(f"{root_dir_name}/main.py", "# demo plugin\n")
        zf.writestr(f"{root_dir_name}/.env.template", "DEMO_API_KEY=\n")
    return buf.getvalue()


def _sign(data: bytes) -> str:
    return "hmac_sha256:" + hmac.new(SECRET, data, hashlib.sha256).hexdigest()


def _write_install_plan(path: Path, *, extra_steps: list[dict] | None = None) -> None:
    steps = [
        {"id": "prepare", "action": "prepare"},
        {"id": "install_demo", "action": "install_plugin", "plugin": SLUG, "snapshot": True},
        {
            "id": "write_env",
            "action": "write_env",
            "plugin": SLUG,
            "from": f"plugins/{SLUG}/.env.template",
            "depends_on": ["install_demo"],
        },
        {"id": "start", "action": "start", "depends_on": ["write_env"]},
    ]
    if extra_steps:
        steps.extend(extra_steps)
    plan = {"format_version": "1", "project_id": SLUG, "version": "1.0.0", "steps": steps}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(plan))


def _make_runner(tmp_path: Path, client, *, install_plan_path: Path | None = None):
    plan_path = install_plan_path or tmp_path / "install.yaml"
    if install_plan_path is None:
        _write_install_plan(plan_path)
    return MarketplaceDeploymentRunner(
        client=client,
        slug=SLUG,
        workdir=tmp_path / "work",
        project_root=tmp_path / "deployed",
        trusted_signer_secret=SECRET,
        install_plan_path=plan_path,
        version="1.0.0",
    )


async def test_full_pipeline_succeeds(tmp_path):
    zip_bytes = _build_zipball()
    client = FakeMarketplaceClient(
        zip_bytes=zip_bytes, signature_hex=_sign(zip_bytes), plugin_header="demo-plugin@1.0.0"
    )
    runner = _make_runner(tmp_path, client)

    report = await runner.run()

    assert report.status == "success"
    assert report.resolved_version == "1.0.0"
    assert report.repo == "acme/demo-plugin@1.0.0"
    assert runner.state == MarketplaceDeploymentState.SUCCEEDED
    assert client.fetch_calls == [(SLUG, "1.0.0", "plugin")]

    plugin_dir = runner.project_root / "plugins" / SLUG
    assert (plugin_dir / "plugin.yaml").is_file()
    assert (plugin_dir / "main.py").is_file()

    env_file = runner.project_root / "plugins" / f"{SLUG}.env"
    assert env_file.is_file()
    assert oct(env_file.stat().st_mode)[-3:] == "600"

    # Local report was written, and the same outcome was reported to the Hub.
    reports = list((tmp_path / "work" / "reports").glob("*.json"))
    assert len(reports) == 1
    assert len(client.report_calls) == 1
    reported = client.report_calls[0]
    assert reported["status"] == "success"
    assert reported["slug"] == SLUG
    assert reported["version"] == "1.0.0"
    assert reported["host_id"] == "default"


async def test_report_to_hub_uses_configured_host_id(tmp_path):
    zip_bytes = _build_zipball()
    client = FakeMarketplaceClient(
        zip_bytes=zip_bytes, signature_hex=_sign(zip_bytes), plugin_header="demo-plugin@1.0.0"
    )
    runner = _make_runner(tmp_path, client)
    runner.host_id = "vps-prod-1"

    await runner.run()

    assert client.report_calls[0]["host_id"] == "vps-prod-1"


async def test_hub_reporting_failure_does_not_fail_a_successful_deployment(tmp_path):
    zip_bytes = _build_zipball()
    client = FakeMarketplaceClient(
        zip_bytes=zip_bytes,
        signature_hex=_sign(zip_bytes),
        plugin_header="demo-plugin@1.0.0",
        fail_report=True,
    )
    runner = _make_runner(tmp_path, client)

    report = await runner.run()  # must not raise despite report_deployment failing

    assert report.status == "success"
    assert runner.state == MarketplaceDeploymentState.SUCCEEDED
    assert len(client.report_calls) == 1  # it was attempted


async def test_failed_deployment_reports_failure_status_and_error_message(tmp_path):
    zip_bytes = _build_zipball()
    client = FakeMarketplaceClient(
        zip_bytes=zip_bytes, signature_hex=_sign(zip_bytes), plugin_header="demo-plugin@1.0.0"
    )
    runner = _make_runner(tmp_path, client)
    runner.trusted_signer_secret = b"wrong-secret"

    with pytest.raises(ArtifactError):
        await runner.run()

    assert len(client.report_calls) == 1
    reported = client.report_calls[0]
    assert reported["status"] == "failed"
    assert "HMAC" in reported["error_message"]


async def test_wrong_secret_is_rejected(tmp_path):
    zip_bytes = _build_zipball()
    client = FakeMarketplaceClient(
        zip_bytes=zip_bytes, signature_hex=_sign(zip_bytes), plugin_header="demo-plugin@1.0.0"
    )
    runner = _make_runner(tmp_path, client)
    runner.trusted_signer_secret = b"wrong-secret"

    with pytest.raises(ArtifactError, match="HMAC"):
        await runner.run()
    assert runner.state == MarketplaceDeploymentState.FAILED

    # Failure report still gets written for audit purposes.
    reports = list((tmp_path / "work" / "reports").glob("*.json"))
    assert len(reports) == 1


async def test_tampered_zip_is_rejected(tmp_path):
    zip_bytes = _build_zipball()
    tampered = zip_bytes + b"\x00"
    client = FakeMarketplaceClient(
        zip_bytes=tampered, signature_hex=_sign(zip_bytes), plugin_header="demo-plugin@1.0.0"
    )
    runner = _make_runner(tmp_path, client)

    with pytest.raises(ArtifactError, match="HMAC"):
        await runner.run()


async def test_missing_install_plan_raises(tmp_path):
    zip_bytes = _build_zipball()
    client = FakeMarketplaceClient(
        zip_bytes=zip_bytes, signature_hex=_sign(zip_bytes), plugin_header="demo-plugin@1.0.0"
    )
    missing_path = tmp_path / "does-not-exist.yaml"
    runner = _make_runner(tmp_path, client, install_plan_path=missing_path)

    with pytest.raises(ArtifactError, match="not found"):
        await runner.run()


async def test_install_plan_project_id_mismatch_raises(tmp_path):
    zip_bytes = _build_zipball()
    client = FakeMarketplaceClient(
        zip_bytes=zip_bytes, signature_hex=_sign(zip_bytes), plugin_header="demo-plugin@1.0.0"
    )
    plan_path = tmp_path / "install.yaml"
    plan_path.write_text(
        yaml.safe_dump(
            {
                "format_version": "1",
                "project_id": "some-other-plugin",
                "version": "1.0.0",
                "steps": [{"id": "prepare", "action": "prepare"}],
            }
        )
    )
    runner = _make_runner(tmp_path, client, install_plan_path=plan_path)

    with pytest.raises(ArtifactError, match="does not match"):
        await runner.run()


async def test_install_failure_triggers_rollback(tmp_path):
    zip_bytes = _build_zipball()
    client = FakeMarketplaceClient(
        zip_bytes=zip_bytes, signature_hex=_sign(zip_bytes), plugin_header="demo-plugin@1.0.0"
    )
    plan_path = tmp_path / "install.yaml"
    _write_install_plan(
        plan_path,
        extra_steps=[
            {
                "id": "write_env_missing",
                "action": "write_env",
                "plugin": "other-plugin",  # no prior env file for this one, and no template ships
                "from": "plugins/nonexistent/.env.template",
                "depends_on": ["start"],
            }
        ],
    )
    runner = _make_runner(tmp_path, client, install_plan_path=plan_path)

    with pytest.raises(DeploymentError, match="install failed"):
        await runner.run()

    assert runner.state == MarketplaceDeploymentState.ROLLED_BACK
    # install_demo's snapshot=true means the fresh plugin dir gets rolled back away.
    assert not (runner.project_root / "plugins" / SLUG).exists()
    assert client.report_calls[0]["status"] == "rolled_back"


async def test_flattens_single_top_level_directory(tmp_path):
    zip_bytes = _build_zipball(root_dir_name="totally-different-name-xyz")
    client = FakeMarketplaceClient(
        zip_bytes=zip_bytes, signature_hex=_sign(zip_bytes), plugin_header="demo-plugin@1.0.0"
    )
    runner = _make_runner(tmp_path, client)

    await runner.run()

    plugin_dir = runner.project_root / "plugins" / SLUG
    assert (plugin_dir / "plugin.yaml").is_file()
    assert not (runner.project_root / "plugins" / SLUG / "totally-different-name-xyz").exists()


async def test_path_traversal_in_zip_is_rejected(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../etc/evil", "pwned")
    zip_bytes = buf.getvalue()
    client = FakeMarketplaceClient(
        zip_bytes=zip_bytes, signature_hex=_sign(zip_bytes), plugin_header="demo-plugin@1.0.0"
    )
    runner = _make_runner(tmp_path, client)

    with pytest.raises(ArtifactError, match="unsafe path"):
        await runner.run()
