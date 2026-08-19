"""End-to-end pipeline tests using InMemoryHubClient in place of XCore Hub
(which has no real API yet — see agent/hub_client.py) and the real packer
(xcore_agent.packer) to build test artifacts, instead of hand-rolling the
sealing logic. Everything except the network transport is exercised for
real: manifest/content-hash generation, signature verification, AES-GCM
decryption, zstd decompression, tar extraction with path-traversal
guarding, dependency resolution, filesystem install, and rollback.
"""

import io
import subprocess
import tarfile
from pathlib import Path

import pytest
import yaml
import zstandard
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from xcore_agent.agent.errors import ArtifactError, DeploymentError
from xcore_agent.agent.hub_client import InMemoryHubClient
from xcore_agent.agent.pipeline import DeploymentCredentials, DeploymentRunner
from xcore_agent.agent.state import DeploymentState
from xcore_agent.packer.builder import seal_directory, write_manifest
from xcore_agent.plugin_resolver import PluginResolver

PROJECT_ID = "prj_test0000001"


def _build_source_tree(root: Path, *, extra_steps: list[dict] | None = None) -> None:
    (root / "plugins" / "demo").mkdir(parents=True)
    (root / "deployment").mkdir(parents=True)

    (root / "integration.yaml").write_text("services: {}\n")
    (root / "plugins" / "demo" / "plugin.yaml").write_text("name: demo\nversion: 1.0.0\n")
    (root / "plugins" / "demo" / "main.py").write_text("# demo plugin\n")
    (root / "plugins" / "demo" / ".env.template").write_text("DEMO_API_KEY=\n")

    steps = [
        {"id": "prepare", "action": "prepare"},
        {"id": "install_demo", "action": "install_plugin", "plugin": "demo", "snapshot": True},
        {
            "id": "write_env",
            "action": "write_env",
            "plugin": "demo",
            "from": "plugins/demo/.env.template",
            "depends_on": ["install_demo"],
        },
        {"id": "start", "action": "start", "depends_on": ["write_env"]},
    ]
    if extra_steps:
        steps.extend(extra_steps)

    install_plan = {
        "format_version": "1",
        "project_id": PROJECT_ID,
        "version": "1.0.0",
        "steps": steps,
    }
    (root / "deployment" / "install.yaml").write_text(yaml.safe_dump(install_plan))


def _seal(root: Path) -> dict:
    """Write manifest.json and seal `root` with the real packer."""
    write_manifest(root, project_id=PROJECT_ID, project_name="demo-project", version="1.0.0")
    ciphertext, dek, signature, public_key = seal_directory(root)
    return {"encrypted": ciphertext, "dek": dek, "signature": signature, "public_key": public_key}


def _make_runner(
    tmp_path: Path, sealed: dict, *, plugin_resolver=None
) -> tuple[DeploymentRunner, InMemoryHubClient]:
    hub = InMemoryHubClient(
        ciphertext=sealed["encrypted"],
        dek=sealed["dek"],
        signature=sealed["signature"],
        signer_public_key=sealed["public_key"],
    )
    runner = DeploymentRunner(
        hub=hub,
        credentials=DeploymentCredentials(
            xdevkey="xdev_test", project_id=PROJECT_ID, deployment_credential="xdpk_test"
        ),
        version="1.0.0",
        workdir=tmp_path / "work",
        project_root=tmp_path / "deployed",
        trusted_signer_public_key=sealed["public_key"],
        plugin_resolver=plugin_resolver,
    )
    return runner, hub


@pytest.fixture
def sealed_artifact(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _build_source_tree(src)
    return _seal(src)


async def test_full_pipeline_succeeds(tmp_path, sealed_artifact):
    runner, hub = _make_runner(tmp_path, sealed_artifact)
    report = await runner.run()

    assert report.status == "success"
    assert runner.state == DeploymentState.SUCCEEDED
    assert len(hub.notified) == 1
    assert hub.notified[0].plugins[0]["id"] == "demo"

    plugin_dir = runner.project_root / "plugins" / "demo"
    assert (plugin_dir / "plugin.yaml").is_file()

    env_file = runner.project_root / "plugins" / "demo.env"
    assert env_file.is_file()
    assert oct(env_file.stat().st_mode)[-3:] == "600"


async def test_full_pipeline_installs_extension(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _build_source_tree(
        src,
        extra_steps=[
            {
                "id": "install_mail",
                "action": "install_extension",
                "extension": "mail",
                "snapshot": True,
                "depends_on": ["start"],
            }
        ],
    )
    (src / "extensions" / "mail").mkdir(parents=True)
    (src / "extensions" / "mail" / "client.py").write_text("# mail extension\n")

    sealed = _seal(src)
    runner, hub = _make_runner(tmp_path, sealed)
    report = await runner.run()

    assert report.status == "success"
    assert runner.state == DeploymentState.SUCCEEDED
    installed = runner.project_root / "extensions" / "mail" / "client.py"
    assert installed.is_file()
    assert installed.read_text() == "# mail extension\n"

    # The manifest embeds the extension's own content hash, separate from
    # `plugins` — see schema/manifest.py's ExtensionRef.
    manifest_extensions = {e.id: e.sha256 for e in runner.manifest.extensions}
    assert "mail" in manifest_extensions
    assert len(manifest_extensions["mail"]) == 64
    assert hub.notified[0].plugins[0]["id"] == "demo"


async def test_wrong_signer_key_is_rejected(tmp_path, sealed_artifact):
    other_key = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    runner, _hub = _make_runner(tmp_path, sealed_artifact)
    runner.trusted_signer_public_key = other_key

    with pytest.raises(ArtifactError, match="untrusted key"):
        await runner.run()
    assert runner.state == DeploymentState.FAILED


async def test_tampered_ciphertext_is_rejected(tmp_path, sealed_artifact):
    # Tampering the ciphertext also invalidates the outer signature (it
    # covers the whole encrypted blob), so this is caught at the signature
    # stage — the agent never attempts to decrypt a tampered payload.
    tampered = bytearray(sealed_artifact["encrypted"])
    tampered[-1] ^= 0xFF
    sealed_artifact = {**sealed_artifact, "encrypted": bytes(tampered)}
    runner, _hub = _make_runner(tmp_path, sealed_artifact)

    with pytest.raises(ArtifactError):
        await runner.run()
    assert runner.state == DeploymentState.FAILED


async def test_content_hash_mismatch_is_rejected(tmp_path):
    # A manifest whose declared content_sha256 doesn't match the actual
    # extracted tree must be rejected even though signature and decryption
    # both succeeded — this is exactly the "compromised signing key
    # re-encrypting substituted content" scenario from the design notes.
    src = tmp_path / "src"
    src.mkdir()
    _build_source_tree(src)
    write_manifest(src, project_id=PROJECT_ID, project_name="demo-project", version="1.0.0")
    # Mutate a file *after* the manifest hash was computed, then seal as-is
    # (seal_directory doesn't touch manifest.json, so this simulates a
    # substituted payload behind a still-valid outer signature).
    (src / "plugins" / "demo" / "main.py").write_text("# tampered after hashing\n")

    ciphertext, dek, signature, public_key = seal_directory(src)
    sealed = {"encrypted": ciphertext, "dek": dek, "signature": signature, "public_key": public_key}
    runner, _hub = _make_runner(tmp_path, sealed)

    with pytest.raises(ArtifactError, match="content hash mismatch"):
        await runner.run()
    assert runner.state == DeploymentState.FAILED


async def test_project_id_mismatch_is_rejected(tmp_path, sealed_artifact):
    runner, _hub = _make_runner(tmp_path, sealed_artifact)
    runner.credentials = DeploymentCredentials(
        xdevkey="xdev_test", project_id="prj_someOtherProject", deployment_credential="xdpk_test"
    )
    with pytest.raises(ArtifactError, match="does not match"):
        await runner.run()
    assert runner.state == DeploymentState.FAILED


async def test_install_failure_triggers_rollback(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _build_source_tree(
        src,
        extra_steps=[
            {
                "id": "install_missing",
                "action": "install_plugin",
                "plugin": "does-not-exist",
                "depends_on": ["start"],
            }
        ],
    )
    sealed = _seal(src)
    runner, _hub = _make_runner(tmp_path, sealed)

    with pytest.raises(DeploymentError, match="install failed"):
        await runner.run()

    assert runner.state == DeploymentState.ROLLED_BACK
    # "demo" installed successfully before the failing step; rollback must
    # undo it since it had `snapshot: true` and did not exist beforehand.
    assert not (runner.project_root / "plugins" / "demo").exists()


async def test_path_traversal_in_archive_is_rejected(tmp_path, sealed_artifact):
    # Build a hostile tar directly (bypassing the packer's directory-based
    # sealing) with a member that tries to escape the extraction directory —
    # this deliberately does not go through the packer, simulating an
    # attacker-crafted artifact that only needs a valid-looking envelope.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        data = b"pwned"
        info = tarfile.TarInfo(name="../../etc/passwd")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    compressed = zstandard.ZstdCompressor(level=19).compress(buf.getvalue())

    dek = AESGCM.generate_key(bit_length=256)
    nonce = b"\x00" * 12
    encrypted = nonce + AESGCM(dek).encrypt(nonce, compressed, None)
    private_key = Ed25519PrivateKey.generate()
    signature = private_key.sign(encrypted)
    public_key = private_key.public_key().public_bytes_raw()

    sealed = {"encrypted": encrypted, "dek": dek, "signature": signature, "public_key": public_key}
    runner, _hub = _make_runner(tmp_path, sealed)

    with pytest.raises(ArtifactError, match="unsafe path"):
        await runner.run()
    assert runner.state == DeploymentState.FAILED


def _git(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True)


def _build_source_based_project(tmp_path: Path) -> tuple[Path, str]:
    """A real local git repo (standing in for a marketplace/registry link)
    plus a project source tree whose 'demo' plugin resolves from it instead
    of embedding its code. Returns (project_source_root, commit_sha)."""
    repo = tmp_path / "plugin-repo"
    repo.mkdir()
    _git("init", "--quiet", cwd=repo)
    _git("config", "user.email", "test@test.com", cwd=repo)
    _git("config", "user.name", "test", cwd=repo)
    (repo / "main.py").write_text("# demo plugin fetched from git\n")
    _git("add", "-A", cwd=repo)
    _git("commit", "--quiet", "-m", "initial", cwd=repo)
    sha = _git("rev-parse", "HEAD", cwd=repo).stdout.strip()

    src = tmp_path / "src"
    (src / "plugins" / "demo").mkdir(parents=True)
    (src / "deployment").mkdir(parents=True)
    (src / "integration.yaml").write_text("services: {}\n")
    (src / "plugins" / "demo" / "plugin.yaml").write_text(
        f"name: demo\nversion: 1.0.0\nsource:\n  url: file://{repo}\n  ref: {sha}\n"
    )
    (src / "plugins" / "demo" / ".env.template").write_text("DEMO_API_KEY=\n")
    install_plan = {
        "format_version": "1",
        "project_id": PROJECT_ID,
        "version": "1.0.0",
        "steps": [
            {"id": "prepare", "action": "prepare"},
            {"id": "install_demo", "action": "install_plugin", "plugin": "demo"},
            {
                "id": "write_env",
                "action": "write_env",
                "plugin": "demo",
                "from": "plugins/demo/.env.template",
                "depends_on": ["install_demo"],
            },
        ],
    }
    (src / "deployment" / "install.yaml").write_text(yaml.safe_dump(install_plan))
    return src, sha


async def test_source_based_plugin_is_resolved_from_git(tmp_path):
    src, _sha = _build_source_based_project(tmp_path)
    sealed = _seal(src)

    resolver = PluginResolver(cache_root=tmp_path / "plugin-cache")
    runner, hub = _make_runner(tmp_path, sealed, plugin_resolver=resolver)
    report = await runner.run()

    assert report.status == "success"
    installed = runner.project_root / "plugins" / "demo" / "main.py"
    assert installed.is_file()
    assert "fetched from git" in installed.read_text()
    assert hub.notified[0].plugins[0]["sha256"] is None
    assert hub.notified[0].plugins[0]["source"]["ref"] == _sha


async def test_source_based_plugin_resolved_plugin_yaml_overwrites_build_time_stub(tmp_path):
    # A real plugin repo ships its own plugin.yaml (execution_mode,
    # permissions, resources — the actual runtime privilege grant), distinct
    # from the thin build-time stub in plugins/<id>/plugin.yaml whose only
    # required job is declaring `source:`. That stub must not survive the
    # merge — see the comment in pipeline.py's _resolve_plugins for why.
    repo = tmp_path / "plugin-repo"
    repo.mkdir()
    _git("init", "--quiet", cwd=repo)
    _git("config", "user.email", "test@test.com", cwd=repo)
    _git("config", "user.name", "test", cwd=repo)
    (repo / "plugin.yaml").write_text(
        "name: demo\n"
        "version: 1.0.0\n"
        "execution_mode: trusted\n"
        "permissions:\n"
        "  - resource: demo.*\n"
        "    actions: ['*']\n"
        "    effect: allow\n"
    )
    (repo / "main.py").write_text("# demo plugin fetched from git\n")
    _git("add", "-A", cwd=repo)
    _git("commit", "--quiet", "-m", "initial", cwd=repo)
    sha = _git("rev-parse", "HEAD", cwd=repo).stdout.strip()

    src = tmp_path / "src"
    (src / "plugins" / "demo").mkdir(parents=True)
    (src / "deployment").mkdir(parents=True)
    (src / "integration.yaml").write_text("services: {}\n")
    # The build-time stub: thin, no execution_mode/permissions at all.
    (src / "plugins" / "demo" / "plugin.yaml").write_text(
        f"name: demo\nversion: 1.0.0\nsource:\n  url: file://{repo}\n  ref: {sha}\n"
    )
    install_plan = {
        "format_version": "1",
        "project_id": PROJECT_ID,
        "version": "1.0.0",
        "steps": [
            {"id": "prepare", "action": "prepare"},
            {"id": "install_demo", "action": "install_plugin", "plugin": "demo"},
        ],
    }
    (src / "deployment" / "install.yaml").write_text(yaml.safe_dump(install_plan))
    sealed = _seal(src)

    resolver = PluginResolver(cache_root=tmp_path / "plugin-cache")
    runner, _hub = _make_runner(tmp_path, sealed, plugin_resolver=resolver)
    report = await runner.run()

    assert report.status == "success"
    installed_yaml = (runner.project_root / "plugins" / "demo" / "plugin.yaml").read_text()
    assert "execution_mode: trusted" in installed_yaml
    assert "permissions:" in installed_yaml
    # The build-time stub's own `source: {url: file://..., ref: ...}` block
    # is gone, not merged in alongside the resolved repo's real content.
    assert "url: file://" not in installed_yaml


async def test_source_based_plugin_without_resolver_raises(tmp_path):
    src, _sha = _build_source_based_project(tmp_path)
    sealed = _seal(src)

    runner, _hub = _make_runner(tmp_path, sealed)  # no plugin_resolver configured

    with pytest.raises(ArtifactError, match="no plugin_resolver was configured"):
        await runner.run()
    assert runner.state == DeploymentState.FAILED


async def test_source_based_extension_is_resolved_from_git(tmp_path):
    repo = tmp_path / "ext-repo"
    repo.mkdir()
    _git("init", "--quiet", cwd=repo)
    _git("config", "user.email", "test@test.com", cwd=repo)
    _git("config", "user.name", "test", cwd=repo)
    (repo / "client.py").write_text("# mail extension fetched from git\n")
    _git("add", "-A", cwd=repo)
    _git("commit", "--quiet", "-m", "initial", cwd=repo)
    sha = _git("rev-parse", "HEAD", cwd=repo).stdout.strip()

    src = tmp_path / "src"
    _build_source_tree(src)
    (src / "extensions" / "mail").mkdir(parents=True)
    (src / "extensions" / "mail" / "extension.yaml").write_text(
        f"source:\n  url: file://{repo}\n  ref: {sha}\n"
    )
    install_plan = yaml.safe_load((src / "deployment" / "install.yaml").read_text())
    install_plan["steps"].append(
        {"id": "install_mail", "action": "install_extension", "extension": "mail"}
    )
    (src / "deployment" / "install.yaml").write_text(yaml.safe_dump(install_plan))

    sealed = _seal(src)
    resolver = PluginResolver(cache_root=tmp_path / "plugin-cache")
    runner, _hub = _make_runner(tmp_path, sealed, plugin_resolver=resolver)
    report = await runner.run()

    assert report.status == "success"
    installed = runner.project_root / "extensions" / "mail" / "client.py"
    assert installed.is_file()
    assert "fetched from git" in installed.read_text()
    assert runner.manifest.extension("mail").source.ref == sha
    assert runner.manifest.extension("mail").sha256 is None


async def test_source_based_plugin_pinned_hash_mismatch_is_rejected(tmp_path):
    src, sha = _build_source_based_project(tmp_path)

    # Simulate a build-time-pinned hash (packer doesn't do this today, but
    # the agent must still honor one if present) that doesn't match what the
    # repo actually resolves to.
    from xcore_agent.schema.manifest import PluginRef, PluginSource, ProjectManifest

    manifest = ProjectManifest(
        format_version="1",
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        built_at="2026-08-18T10:00:00Z",
        plugins=[
            PluginRef(
                id="demo",
                version="1.0.0",
                sha256="f" * 64,  # deliberately wrong
                source=PluginSource(url=f"file://{tmp_path / 'plugin-repo'}", ref=sha),
            )
        ],
        content_sha256="0" * 64,  # patched below to the real value
    )
    from xcore_agent import crypto

    manifest_path = src / "manifest.json"
    manifest_path.write_text(manifest.model_dump_json())
    content_sha256 = crypto.compute_tree_digest(src, exclude=frozenset({"manifest.json"}))
    manifest = manifest.model_copy(update={"content_sha256": content_sha256})
    manifest_path.write_text(manifest.model_dump_json())

    ciphertext, dek, signature, public_key = seal_directory(src)
    sealed = {"encrypted": ciphertext, "dek": dek, "signature": signature, "public_key": public_key}

    resolver = PluginResolver(cache_root=tmp_path / "plugin-cache")
    runner, _hub = _make_runner(tmp_path, sealed, plugin_resolver=resolver)

    with pytest.raises(ArtifactError, match="resolved content hash mismatch"):
        await runner.run()
    assert runner.state == DeploymentState.FAILED
