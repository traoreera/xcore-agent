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
from xcore_agent.packer.builder import build_artifact, seal_directory, write_manifest
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
    """Build+seal `root` via the real, complete `build_artifact` entry
    point — NOT a hand-rolled write_manifest()+seal_directory() shortcut.
    That used to skip `_prepare_packaging_view`'s pruning of source-based
    plugins/extensions down to just their manifest file, which let
    content_sha256 and the actually-sealed tree agree for the wrong
    reason (both silently included files a real build would have pruned,
    instead of both correctly excluding them) — invisible until
    content_sha256 started accounting for that pruning for real. See
    test_source_based_plugin_is_resolved_from_git."""
    output_path = root.parent / f"{root.name}-sealed.xdeploy.enc"
    result = build_artifact(
        root,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=output_path,
    )
    return {
        "encrypted": output_path.read_bytes(),
        "dek": result.dek,
        "signature": result.signature,
        "public_key": result.signer_public_key,
    }


def _make_runner(
    tmp_path: Path, sealed: dict, *, plugin_resolver=None, notifiers=None
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
        notifiers=notifiers,
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


async def test_full_pipeline_dispatches_notify_step(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _build_source_tree(
        src,
        extra_steps=[
            {
                "id": "notify_ops",
                "action": "notify",
                "event": "deploy_success",
                "message": "demo deployed",
                "depends_on": ["start"],
            }
        ],
    )
    sealed = _seal(src)

    calls = []
    runner, hub = _make_runner(tmp_path, sealed, notifiers={"deploy_success": calls.append})
    report = await runner.run()

    assert report.status == "success"
    assert len(calls) == 1
    assert calls[0].event == "deploy_success"
    assert calls[0].message == "demo deployed"


async def test_full_pipeline_with_custom_plugins_directory(tmp_path):
    """A project whose integration.yaml declares `plugins: {directory: ./app}`
    (Marketplace's own convention) builds and deploys correctly end to end —
    plugins are read from `app/` at build time and installed back under
    `app/` on the target host, not the "plugins" default."""
    src = tmp_path / "src"
    (src / "app" / "demo").mkdir(parents=True)
    (src / "deployment").mkdir(parents=True)
    src.joinpath("integration.yaml").write_text("plugins:\n  directory: ./app\n")
    (src / "app" / "demo" / "plugin.yaml").write_text("name: demo\nversion: 1.0.0\n")
    (src / "app" / "demo" / "main.py").write_text("# demo plugin\n")
    install_plan = {
        "format_version": "1",
        "project_id": PROJECT_ID,
        "version": "1.0.0",
        "steps": [
            {"id": "prepare", "action": "prepare"},
            {"id": "install_demo", "action": "install_plugin", "plugin": "demo", "snapshot": True},
            {"id": "start", "action": "start", "depends_on": ["install_demo"]},
        ],
    }
    (src / "deployment" / "install.yaml").write_text(yaml.safe_dump(install_plan))

    sealed = _seal(src)
    runner, hub = _make_runner(tmp_path, sealed)
    report = await runner.run()

    assert report.status == "success"
    assert runner.manifest.plugins_dirname == "app"
    plugin_dir = runner.project_root / "app" / "demo"
    assert (plugin_dir / "plugin.yaml").is_file()
    # Not installed under the "plugins" default.
    assert not (runner.project_root / "plugins").exists()


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
    # Deliberately bypasses _seal() (real build_artifact): an install.yaml
    # step referencing a plugin absent from plugins/ is now rejected at
    # BUILD time (_validate_source_tree) — exactly the safety net that
    # SHOULD stop a well-behaved packer from ever producing this artifact.
    # What this test actually exercises is the AGENT's defensive handling
    # (install_driver.install_plugin's "not found in extracted artifact")
    # for the case where one somehow reaches it anyway — a hand-assembled
    # manifest/install.yaml combination that skips that build-time check,
    # same reasoning as test_path_traversal_in_archive_is_rejected
    # deliberately not going through the packer at all.
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
    write_manifest(src, project_id=PROJECT_ID, project_name="demo-project", version="1.0.0")
    ciphertext, dek, signature, public_key = seal_directory(src)
    sealed = {"encrypted": ciphertext, "dek": dek, "signature": signature, "public_key": public_key}
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


async def test_retried_deploy_after_partial_resolve_failure_reextracts_cleanly(tmp_path):
    # Real prod bug, hit deploying a multi-plugin artifact for the first
    # time: a deploy that resolves plugin A fine, then fails resolving
    # plugin B (a transient marketplace/git error), leaves A's real merged
    # code sitting in the reused workdir's extracted/ tree. _extract() used
    # to only ever ADD to that directory (tar extraction never deletes what
    # it doesn't overwrite) — so a retried deploy's _verify_manifest (which
    # runs BEFORE _resolve_plugins) saw A's leftover files and rejected the
    # artifact with a content hash mismatch, even though the artifact
    # itself was perfectly fine.
    good_repo = tmp_path / "good-repo"
    good_repo.mkdir()
    _git("init", "--quiet", cwd=good_repo)
    _git("config", "user.email", "test@test.com", cwd=good_repo)
    _git("config", "user.name", "test", cwd=good_repo)
    (good_repo / "main.py").write_text("# good plugin\n")
    _git("add", "-A", cwd=good_repo)
    _git("commit", "--quiet", "-m", "initial", cwd=good_repo)
    good_sha = _git("rev-parse", "HEAD", cwd=good_repo).stdout.strip()

    src = tmp_path / "src"
    # "good" sorts before "zzz_flaky" — write_manifest lists plugins/
    # alphabetically, and _resolve_plugins processes them in that order, so
    # "good" resolves (and merges real files) before "zzz_flaky" fails.
    (src / "plugins" / "good").mkdir(parents=True)
    (src / "plugins" / "zzz_flaky").mkdir(parents=True)
    (src / "deployment").mkdir(parents=True)
    (src / "integration.yaml").write_text("services: {}\n")
    (src / "plugins" / "good" / "plugin.yaml").write_text(
        f"name: good\nversion: 1.0.0\nsource:\n  url: file://{good_repo}\n  ref: {good_sha}\n"
    )
    (src / "plugins" / "zzz_flaky" / "plugin.yaml").write_text(
        f"name: zzz_flaky\nversion: 1.0.0\nsource:\n  url: file://{good_repo}\n  ref: {good_sha}\n"
    )
    install_plan = {
        "format_version": "1",
        "project_id": PROJECT_ID,
        "version": "1.0.0",
        "steps": [
            {"id": "prepare", "action": "prepare"},
            {"id": "install_good", "action": "install_plugin", "plugin": "good"},
            {"id": "install_flaky", "action": "install_plugin", "plugin": "zzz_flaky"},
        ],
    }
    (src / "deployment" / "install.yaml").write_text(yaml.safe_dump(install_plan))
    sealed = _seal(src)

    class _FlakyResolver:
        """Fails resolving "zzz_flaky" exactly once, succeeds every other
        call (including for "good", and for "zzz_flaky" on retry) —
        delegates to a real PluginResolver so resolution genuinely happens."""

        def __init__(self, cache_root: Path) -> None:
            self._real = PluginResolver(cache_root=cache_root)
            self.flaky_calls = 0

        async def resolve(self, plugin_id: str, source):
            if plugin_id == "zzz_flaky":
                self.flaky_calls += 1
                if self.flaky_calls == 1:
                    raise ArtifactError("simulated transient resolution failure")
            return await self._real.resolve(plugin_id, source)

    resolver = _FlakyResolver(tmp_path / "plugin-cache")

    runner1, _hub1 = _make_runner(tmp_path, sealed, plugin_resolver=resolver)
    with pytest.raises(ArtifactError, match="simulated transient"):
        await runner1.run()

    # Confirm the setup actually reproduces the bug precondition: "good"'s
    # real code is sitting in the (reused) workdir's extracted tree.
    leftover = runner1.workdir / "extracted" / "plugins" / "good" / "main.py"
    assert leftover.is_file()

    runner2, _hub2 = _make_runner(tmp_path, sealed, plugin_resolver=resolver)
    report = await runner2.run()

    assert report.status == "success"


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
