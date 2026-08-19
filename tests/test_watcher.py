"""Tests for the CI/CD watch loop: version-change detection against a fake
Hub, automatic redeploy through the real packer + pipeline, state
persistence, and the watch_forever loop's error handling.
"""

from pathlib import Path

import pytest
import yaml

from xcore_agent.agent.hub_client import ArtifactLocation, DeploymentReport, Session
from xcore_agent.agent.pipeline import DeploymentCredentials
from xcore_agent.agent.state_store import StateStore
from xcore_agent.agent.watcher import Watcher
from xcore_agent.packer.builder import seal_directory, write_manifest

PROJECT_ID = "prj_test0000001"


class FakeHubClient:
    def __init__(self, *, latest_version: str, artifacts: dict[str, dict] | None = None) -> None:
        self.latest_version = latest_version
        self._artifacts = artifacts or {}
        self.download_calls = 0
        self.notified: list[DeploymentReport] = []

    async def authenticate(self, *, xdevkey, project_id):
        return Session(project_id=project_id, access_token="fake-token")

    async def get_latest_version(self, session, *, project_id):
        return self.latest_version

    async def request_artifact(self, session, *, version):
        sealed = self._artifacts[version]
        return ArtifactLocation(
            download_url="fake://artifact",
            signature=sealed["signature"],
            signer_public_key=sealed["public_key"],
        )

    async def download(self, location):
        self.download_calls += 1
        for sealed in self._artifacts.values():
            if sealed["public_key"] == location.signer_public_key:
                return sealed["encrypted"]
        raise AssertionError("no matching artifact for this location")

    async def obtain_deployment_key(self, session, *, deployment_credential, artifact_signature):
        for sealed in self._artifacts.values():
            if sealed["signature"] == artifact_signature:
                return sealed["dek"]
        raise AssertionError("no matching artifact for this signature")

    async def notify(self, session, report):
        self.notified.append(report)


class FailingAuthHub(FakeHubClient):
    async def authenticate(self, *, xdevkey, project_id):
        raise RuntimeError("hub unreachable")


def _build_source_tree(root: Path, *, version: str) -> None:
    (root / "plugins" / "demo").mkdir(parents=True)
    (root / "deployment").mkdir(parents=True)
    (root / "integration.yaml").write_text("services: {}\n")
    (root / "plugins" / "demo" / "plugin.yaml").write_text(f"name: demo\nversion: {version}\n")
    (root / "plugins" / "demo" / "main.py").write_text("# demo\n")
    install_plan = {
        "format_version": "1",
        "project_id": PROJECT_ID,
        "version": version,
        "steps": [
            {"id": "prepare", "action": "prepare"},
            {"id": "install_demo", "action": "install_plugin", "plugin": "demo"},
        ],
    }
    (root / "deployment" / "install.yaml").write_text(yaml.safe_dump(install_plan))


def _seal(root: Path, *, version: str) -> dict:
    write_manifest(root, project_id=PROJECT_ID, project_name="demo-project", version=version)
    ciphertext, dek, signature, public_key = seal_directory(root)
    return {"encrypted": ciphertext, "dek": dek, "signature": signature, "public_key": public_key}


@pytest.fixture
def sealed_v1(tmp_path):
    src = tmp_path / "src-v1"
    src.mkdir()
    _build_source_tree(src, version="1.0.0")
    return _seal(src, version="1.0.0")


def _make_watcher(tmp_path, hub, sealed) -> Watcher:
    return Watcher(
        hub=hub,
        credentials=DeploymentCredentials(
            xdevkey="xdev_test", project_id=PROJECT_ID, deployment_credential="xdpk_test"
        ),
        workdir_root=tmp_path / "work",
        project_root=tmp_path / "deployed",
        trusted_signer_public_key=sealed["public_key"],
    )


async def test_check_once_skips_when_version_unchanged(tmp_path, sealed_v1):
    hub = FakeHubClient(latest_version="1.0.0", artifacts={"1.0.0": sealed_v1})
    project_root = tmp_path / "deployed"
    StateStore(project_root).write(project_id=PROJECT_ID, version="1.0.0")

    watcher = _make_watcher(tmp_path, hub, sealed_v1)
    result = await watcher.check_once()

    assert result.deployed is False
    assert result.checked_version == "1.0.0"
    assert hub.download_calls == 0


async def test_check_once_deploys_new_version_and_persists_state(tmp_path, sealed_v1):
    hub = FakeHubClient(latest_version="1.0.0", artifacts={"1.0.0": sealed_v1})
    watcher = _make_watcher(tmp_path, hub, sealed_v1)

    result = await watcher.check_once()

    assert result.deployed is True
    assert result.report.status == "success"
    assert (tmp_path / "deployed" / "plugins" / "demo" / "plugin.yaml").is_file()

    state = StateStore(tmp_path / "deployed").read()
    assert state.version == "1.0.0"
    assert state.project_id == PROJECT_ID


async def test_check_once_is_idempotent_on_repeated_calls(tmp_path, sealed_v1):
    hub = FakeHubClient(latest_version="1.0.0", artifacts={"1.0.0": sealed_v1})
    watcher = _make_watcher(tmp_path, hub, sealed_v1)

    first = await watcher.check_once()
    second = await watcher.check_once()

    assert first.deployed is True
    assert second.deployed is False
    assert hub.download_calls == 1


async def test_watch_forever_reports_each_tick_and_stops(tmp_path, sealed_v1):
    hub = FakeHubClient(latest_version="1.0.0", artifacts={"1.0.0": sealed_v1})
    watcher = _make_watcher(tmp_path, hub, sealed_v1)

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


async def test_watch_forever_reports_errors_without_crashing(tmp_path, sealed_v1):
    hub = FailingAuthHub(latest_version="1.0.0", artifacts={"1.0.0": sealed_v1})
    watcher = _make_watcher(tmp_path, hub, sealed_v1)

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
