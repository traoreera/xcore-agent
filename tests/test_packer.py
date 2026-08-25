import io
import tarfile
from pathlib import Path

import pytest
import yaml
import zstandard
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from xcore_agent import crypto
from xcore_agent.packer.builder import BuildError, build_artifact

PROJECT_ID = "prj_test0000001"


def _minimal_source_tree(root: Path) -> None:
    (root / "plugins" / "demo").mkdir(parents=True)
    (root / "deployment").mkdir(parents=True)
    (root / "integration.yaml").write_text("services: {}\n")
    (root / "plugins" / "demo" / "plugin.yaml").write_text("name: demo\nversion: 1.0.0\n")
    (root / "plugins" / "demo" / "main.py").write_text("# demo plugin\n")
    install_plan = {
        "format_version": "1",
        "project_id": PROJECT_ID,
        "version": "1.0.0",
        "steps": [
            {"id": "prepare", "action": "prepare"},
            {"id": "install_demo", "action": "install_plugin", "plugin": "demo"},
        ],
    }
    (root / "deployment" / "install.yaml").write_text(yaml.safe_dump(install_plan))


def test_build_artifact_succeeds(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)

    result = build_artifact(
        src,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=tmp_path / "out" / "demo.xdeploy.enc",
    )

    assert result.output_path.is_file()
    assert result.manifest.project_name == "demo-project"
    assert result.manifest.plugins[0].id == "demo"
    assert len(result.dek) == 32
    assert len(result.signer_public_key) == 32

    # manifest.json was written into the source tree for the caller to inspect
    assert (src / "manifest.json").is_file()

    # The artifact is a real, decryptable, verifiable envelope: signature over
    # ciphertext, AES-256-GCM decrypt, zstd decompress, then a tar containing
    # the manifest whose content_sha256 matches the (manifest-excluded) tree.
    ciphertext = result.output_path.read_bytes()
    crypto.verify_signature(
        public_key=result.signer_public_key, signature=result.signature, payload=ciphertext
    )
    nonce, body = ciphertext[:12], ciphertext[12:]
    compressed = crypto.decrypt_aes_gcm(key=result.dek, nonce=nonce, ciphertext=body)
    plaintext_tar = zstandard.ZstdDecompressor().decompress(compressed)
    assert len(plaintext_tar) > 0


def test_build_artifact_reads_plugin_environment_block(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)
    (src / "plugins" / "demo" / "plugin.yaml").write_text(
        "name: demo\n"
        "version: 1.0.0\n"
        "environment:\n"
        "  required: [DEMO_API_KEY]\n"
        "  optional: [DEMO_LOG_LEVEL]\n"
    )

    result = build_artifact(
        src,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=tmp_path / "out.xdeploy.enc",
    )

    env = result.manifest.plugins[0].environment
    assert env is not None
    assert env.required == ["DEMO_API_KEY"]
    assert env.optional == ["DEMO_LOG_LEVEL"]


def test_build_artifact_without_environment_block_leaves_it_none(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)

    result = build_artifact(
        src,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=tmp_path / "out.xdeploy.enc",
    )

    assert result.manifest.plugins[0].environment is None


def test_build_artifact_with_explicit_signing_key(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)
    key = Ed25519PrivateKey.generate()

    result = build_artifact(
        src,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=tmp_path / "demo.xdeploy.enc",
        signing_key=key,
    )

    assert result.signer_public_key == key.public_key().public_bytes_raw()


def test_missing_integration_yaml_is_rejected(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)
    (src / "integration.yaml").unlink()

    with pytest.raises(BuildError, match="integration.yaml"):
        build_artifact(
            src,
            project_id=PROJECT_ID,
            project_name="x",
            version="1.0.0",
            output_path=tmp_path / "out.xdeploy.enc",
        )


def test_empty_plugins_dir_is_rejected(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)
    import shutil

    shutil.rmtree(src / "plugins" / "demo")

    with pytest.raises(BuildError, match="plugins/"):
        build_artifact(
            src,
            project_id=PROJECT_ID,
            project_name="x",
            version="1.0.0",
            output_path=tmp_path / "out.xdeploy.enc",
        )


def test_install_yaml_referencing_missing_plugin_is_rejected(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)
    plan = yaml.safe_load((src / "deployment" / "install.yaml").read_text())
    plan["steps"].append({"id": "ghost", "action": "install_plugin", "plugin": "does-not-exist"})
    (src / "deployment" / "install.yaml").write_text(yaml.safe_dump(plan))

    with pytest.raises(BuildError, match="does-not-exist"):
        build_artifact(
            src,
            project_id=PROJECT_ID,
            project_name="x",
            version="1.0.0",
            output_path=tmp_path / "out.xdeploy.enc",
        )


def test_project_id_mismatch_between_call_and_install_yaml_is_rejected(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)

    with pytest.raises(BuildError, match="does not match"):
        build_artifact(
            src,
            project_id="prj_someOtherProject",
            project_name="x",
            version="1.0.0",
            output_path=tmp_path / "out.xdeploy.enc",
        )


def test_version_mismatch_between_call_and_install_yaml_is_rejected(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)

    with pytest.raises(BuildError, match="does not match"):
        build_artifact(
            src,
            project_id=PROJECT_ID,
            project_name="x",
            version="9.9.9",
            output_path=tmp_path / "out.xdeploy.enc",
        )


def test_plugin_missing_plugin_yaml_is_rejected(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)
    (src / "plugins" / "demo" / "plugin.yaml").unlink()

    with pytest.raises(BuildError, match="plugin.yaml"):
        build_artifact(
            src,
            project_id=PROJECT_ID,
            project_name="x",
            version="1.0.0",
            output_path=tmp_path / "out.xdeploy.enc",
        )


def test_plugin_declaring_env_inject_without_template_is_rejected(tmp_path):
    # Real incident this guards against: xauth's plugin.yaml declared
    # envconfiguration.inject: true with no .env.template anywhere in the
    # published repo — invisible at build time, only surfaced as a
    # ManifestError when a real host tried to start the plugin.
    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)
    (src / "plugins" / "demo" / "plugin.yaml").write_text(
        "name: demo\nversion: 1.0.0\n" "envconfiguration:\n  inject: true\n  env_file: .env\n"
    )

    with pytest.raises(BuildError, match=r"\.env\.template"):
        build_artifact(
            src,
            project_id=PROJECT_ID,
            project_name="x",
            version="1.0.0",
            output_path=tmp_path / "out.xdeploy.enc",
        )


def test_plugin_declaring_env_inject_with_template_present_succeeds(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)
    (src / "plugins" / "demo" / "plugin.yaml").write_text(
        "name: demo\nversion: 1.0.0\n" "envconfiguration:\n  inject: true\n  env_file: .env\n"
    )
    (src / "plugins" / "demo" / ".env.template").write_text("SOME_SECRET=${SOME_SECRET}\n")

    result = build_artifact(
        src,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=tmp_path / "out.xdeploy.enc",
    )

    assert result.manifest.plugins[0].id == "demo"


def test_env_template_check_skipped_for_source_based_plugin(tmp_path):
    # Nothing to check on disk for a plugin resolved from git at deploy
    # time — same reasoning as sha256 being optional for source-based
    # plugins (see _read_plugin_source).
    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)
    (src / "plugins" / "demo" / "plugin.yaml").write_text(
        "name: demo\nversion: 1.0.0\n"
        "envconfiguration:\n  inject: true\n  env_file: .env\n"
        "source:\n  url: https://github.com/acme/demo.git\n"
        f"  ref: {'a' * 40}\n"
    )

    result = build_artifact(
        src,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=tmp_path / "out.xdeploy.enc",
    )

    assert result.manifest.plugins[0].source is not None


def test_plugin_resolved_from_xcli_registry_marketplace_source(tmp_path):
    # .xcore-registry.json is written by `xcli plugin install --source
    # marketplace|git` (xcoreCli) as a sibling of every plugin directory —
    # a plugin with no source: of its own in plugin.yaml should still be
    # resolved at deploy time if the registry says how it got here.
    # Marketplace is the PRIMARY origin (see PluginSource's docstring):
    # `slug`/`kind`/`version` drive resolution, not the courtesy `X-Repo`
    # coordinates also recorded alongside them.
    import json

    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)
    (src / "plugins" / ".xcore-registry.json").write_text(
        json.dumps(
            {
                "demo": {
                    "source": "marketplace",
                    "slug": "demo",
                    "kind": "plugin",
                    "version": "1.0.0",
                    "repository": "https://github.com/acme/demo",
                    "ref": "b" * 40,
                }
            }
        )
    )

    result = build_artifact(
        src,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=tmp_path / "out.xdeploy.enc",
    )

    plugin = result.manifest.plugins[0]
    assert plugin.source is not None
    assert plugin.source.marketplace_slug == "demo"
    assert plugin.source.marketplace_version == "1.0.0"
    assert plugin.source.marketplace_kind == "plugin"
    assert plugin.source.url is None
    assert plugin.sha256 is None  # source-based, nothing embedded to hash


def test_plugin_resolved_from_xcli_registry_git_source(tmp_path):
    # A plugin installed with `xcli plugin install --source git` (never
    # published to the marketplace) — the fallback origin, see PluginSource.
    import json

    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)
    (src / "plugins" / ".xcore-registry.json").write_text(
        json.dumps(
            {
                "demo": {
                    "source": "git",
                    "slug": "demo",
                    "kind": "plugin",
                    "version": None,
                    "repository": "https://github.com/acme/demo",
                    "ref": "b" * 40,
                }
            }
        )
    )

    result = build_artifact(
        src,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=tmp_path / "out.xdeploy.enc",
    )

    plugin = result.manifest.plugins[0]
    assert plugin.source is not None
    assert plugin.source.marketplace_slug is None
    assert plugin.source.url == "https://github.com/acme/demo"
    assert plugin.source.ref == "b" * 40
    assert plugin.sha256 is None  # source-based, nothing embedded to hash


def test_explicit_plugin_yaml_source_wins_over_registry(tmp_path):
    import json

    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)
    (src / "plugins" / "demo" / "plugin.yaml").write_text(
        "name: demo\nversion: 1.0.0\nsource:\n  url: https://github.com/explicit/demo.git\n"
        f"  ref: {'c' * 40}\n"
    )
    (src / "plugins" / ".xcore-registry.json").write_text(
        json.dumps(
            {
                "demo": {
                    "source": "marketplace",
                    "repository": "https://github.com/registry/demo",
                    "ref": "d" * 40,
                }
            }
        )
    )

    result = build_artifact(
        src,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=tmp_path / "out.xdeploy.enc",
    )

    assert result.manifest.plugins[0].source.url == "https://github.com/explicit/demo.git"


def test_registry_entry_missing_slug_falls_back_to_embedding(tmp_path):
    # A 'marketplace' entry with no `slug` — the only field that actually
    # drives marketplace resolution — has nothing to resolve from.
    import json

    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)
    (src / "plugins" / ".xcore-registry.json").write_text(
        json.dumps(
            {"demo": {"source": "marketplace", "repository": "https://github.com/acme/demo"}}
        )
    )

    result = build_artifact(
        src,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=tmp_path / "out.xdeploy.enc",
    )

    plugin = result.manifest.plugins[0]
    assert plugin.source is None
    assert plugin.sha256 is not None  # embedded, hashed normally


def test_registry_entry_missing_ref_falls_back_to_embedding(tmp_path):
    # A 'git' entry with no `ref` — its only origin needs one — has nothing
    # to resolve from either.
    import json

    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)
    (src / "plugins" / ".xcore-registry.json").write_text(
        json.dumps({"demo": {"source": "git", "repository": "https://github.com/acme/demo"}})
    )

    result = build_artifact(
        src,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=tmp_path / "out.xdeploy.enc",
    )

    plugin = result.manifest.plugins[0]
    assert plugin.source is None
    assert plugin.sha256 is not None  # embedded, hashed normally


def test_registry_entry_from_local_zip_install_is_ignored(tmp_path):
    # source: "zip" (a one-off local zip install, no stable origin to
    # re-resolve from) must not be trusted the way marketplace/git are.
    import json

    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)
    (src / "plugins" / ".xcore-registry.json").write_text(
        json.dumps(
            {
                "demo": {
                    "source": "zip",
                    "repository": "https://example.com/demo.zip",
                    "ref": "e" * 40,
                }
            }
        )
    )

    result = build_artifact(
        src,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=tmp_path / "out.xdeploy.enc",
    )

    assert result.manifest.plugins[0].source is None


def test_build_artifact_without_extensions_dir_leaves_manifest_extensions_empty(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)

    result = build_artifact(
        src,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=tmp_path / "out.xdeploy.enc",
    )

    assert result.manifest.extensions == []


def test_build_artifact_hashes_extensions_dir(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)
    (src / "extensions" / "mail").mkdir(parents=True)
    (src / "extensions" / "mail" / "client.py").write_text("# mail extension\n")
    (src / "deployment" / "install.yaml").write_text(
        yaml.safe_dump(
            {
                "format_version": "1",
                "project_id": PROJECT_ID,
                "version": "1.0.0",
                "steps": [
                    {"id": "prepare", "action": "prepare"},
                    {"id": "install_demo", "action": "install_plugin", "plugin": "demo"},
                    {"id": "install_mail", "action": "install_extension", "extension": "mail"},
                ],
            }
        )
    )

    result = build_artifact(
        src,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=tmp_path / "out.xdeploy.enc",
    )

    assert len(result.manifest.extensions) == 1
    ext = result.manifest.extensions[0]
    assert ext.id == "mail"
    assert len(ext.sha256) == 64


def _extracted_member_names(result) -> set[str]:
    """Decrypt+decompress+list a built artifact's tar members — lets a test
    assert on what actually got embedded, not just on the manifest."""
    ciphertext = result.output_path.read_bytes()
    nonce, body = ciphertext[:12], ciphertext[12:]
    compressed = crypto.decrypt_aes_gcm(key=result.dek, nonce=nonce, ciphertext=body)
    plaintext_tar = zstandard.ZstdDecompressor().decompress(compressed)
    with tarfile.open(fileobj=io.BytesIO(plaintext_tar)) as tf:
        return {m.name for m in tf.getmembers()}


def test_source_based_plugin_is_pruned_to_manifest_only_even_if_code_present(tmp_path):
    # The operator's local plugins/billing/ happens to have real code sitting
    # there too (e.g. cloned to poke around) — build_artifact must still
    # embed only plugin.yaml for a `source:`-declared plugin, not the code,
    # since it's resolved from git at deploy time (see pipeline.py).
    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)
    (src / "plugins" / "billing").mkdir(parents=True)
    (src / "plugins" / "billing" / "plugin.yaml").write_text(
        "name: billing\nversion: 1.0.0\nsource:\n  url: https://github.com/acme/billing.git\n"
        f"  ref: {'a' * 40}\n"
    )
    (src / "plugins" / "billing" / "main.py").write_text("# should NOT end up in the artifact\n")
    (src / "deployment" / "install.yaml").write_text(
        yaml.safe_dump(
            {
                "format_version": "1",
                "project_id": PROJECT_ID,
                "version": "1.0.0",
                "steps": [
                    {"id": "prepare", "action": "prepare"},
                    {"id": "install_demo", "action": "install_plugin", "plugin": "demo"},
                    {"id": "install_billing", "action": "install_plugin", "plugin": "billing"},
                ],
            }
        )
    )

    result = build_artifact(
        src,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=tmp_path / "out.xdeploy.enc",
    )

    members = _extracted_member_names(result)
    assert "./plugins/billing/plugin.yaml" in members
    assert "./plugins/billing/main.py" not in members
    # The embedded plugin (demo) is untouched by pruning.
    assert "./plugins/demo/main.py" in members
    # source_root itself was never mutated — pruning happened on a temp copy.
    assert (src / "plugins" / "billing" / "main.py").is_file()


def test_source_based_extension_is_pruned_to_manifest_only(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)
    (src / "extensions" / "mail").mkdir(parents=True)
    (src / "extensions" / "mail" / "extension.yaml").write_text(
        "source:\n  url: https://github.com/acme/mail-ext.git\n  ref: " + "b" * 40 + "\n"
    )
    (src / "extensions" / "mail" / "client.py").write_text("# should NOT end up in the artifact\n")
    (src / "deployment" / "install.yaml").write_text(
        yaml.safe_dump(
            {
                "format_version": "1",
                "project_id": PROJECT_ID,
                "version": "1.0.0",
                "steps": [
                    {"id": "prepare", "action": "prepare"},
                    {"id": "install_demo", "action": "install_plugin", "plugin": "demo"},
                    {"id": "install_mail", "action": "install_extension", "extension": "mail"},
                ],
            }
        )
    )

    result = build_artifact(
        src,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=tmp_path / "out.xdeploy.enc",
    )

    assert result.manifest.extensions[0].sha256 is None
    assert result.manifest.extensions[0].source.ref == "b" * 40

    members = _extracted_member_names(result)
    assert "./extensions/mail/extension.yaml" in members
    assert "./extensions/mail/client.py" not in members
    assert (src / "extensions" / "mail" / "client.py").is_file()  # source_root untouched


def test_install_extension_step_referencing_missing_extension_dir_is_rejected(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)
    (src / "deployment" / "install.yaml").write_text(
        yaml.safe_dump(
            {
                "format_version": "1",
                "project_id": PROJECT_ID,
                "version": "1.0.0",
                "steps": [
                    {"id": "prepare", "action": "prepare"},
                    {"id": "install_demo", "action": "install_plugin", "plugin": "demo"},
                    # No extensions/mail/ on disk at all.
                    {"id": "install_mail", "action": "install_extension", "extension": "mail"},
                ],
            }
        )
    )

    with pytest.raises(BuildError, match="extensions/mail"):
        build_artifact(
            src,
            project_id=PROJECT_ID,
            project_name="x",
            version="1.0.0",
            output_path=tmp_path / "out.xdeploy.enc",
        )


def test_build_artifact_reads_custom_plugins_directory_from_integration_yaml(tmp_path):
    """A project whose integration.yaml declares `plugins: {directory: ./app}`
    (Marketplace's own convention — see backends/integration.yaml) builds
    from `app/` instead of requiring a `plugins/` directory that doesn't
    exist in that layout."""
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
            {"id": "install_demo", "action": "install_plugin", "plugin": "demo"},
        ],
    }
    (src / "deployment" / "install.yaml").write_text(yaml.safe_dump(install_plan))

    result = build_artifact(
        src,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=tmp_path / "out.xdeploy.enc",
    )

    assert result.manifest.plugins_dirname == "app"
    assert result.manifest.plugins[0].id == "demo"
    members = _extracted_member_names(result)
    assert "./app/demo/plugin.yaml" in members
    assert "./plugins" not in members


def test_build_artifact_without_plugins_directory_setting_defaults_to_plugins(tmp_path):
    """integration.yaml with no `plugins:` block at all (or one that omits
    `directory`) keeps the prior hardcoded "plugins" behavior."""
    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)

    result = build_artifact(
        src,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=tmp_path / "out.xdeploy.enc",
    )

    assert result.manifest.plugins_dirname == "plugins"


def test_preexisting_manifest_is_rejected(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)
    (src / "manifest.json").write_text("{}")

    with pytest.raises(BuildError, match="already exists"):
        build_artifact(
            src,
            project_id=PROJECT_ID,
            project_name="x",
            version="1.0.0",
            output_path=tmp_path / "out.xdeploy.enc",
        )


# ── _PACKAGING_EXCLUDE_PATTERNS: secrets/bloat must never reach the artifact ──


def test_venv_git_and_secret_files_never_reach_the_artifact(tmp_path):
    # A real private key + populated .env + sqlite DB were once copied into
    # a sealed artifact via plain `shutil.copytree(source_root, ...)` before
    # this exclusion existed — this is the regression test for that.
    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)

    (src / ".venv" / "lib" / "site-packages").mkdir(parents=True)
    (src / ".venv" / "lib" / "site-packages" / "somepkg.py").write_text("# huge, irrelevant\n")
    (src / ".git" / "objects").mkdir(parents=True)
    (src / ".git" / "objects" / "pack").write_text("binary git internals\n")
    (src / "node_modules" / "somedep").mkdir(parents=True)
    (src / "node_modules" / "somedep" / "index.js").write_text("//\n")
    (src / "__pycache__").mkdir(parents=True)
    (src / "__pycache__" / "main.cpython-312.pyc").write_text("bytecode\n")
    (src / "conf").mkdir(parents=True)
    (src / "conf" / ".env").write_text("SECRET_KEY=super-secret-value\n")
    (src / "conf" / ".env.template").write_text("SECRET_KEY=\n")  # must survive
    (src / "conf" / "private.pem").write_text("-----BEGIN PRIVATE KEY-----\nFAKE\n")
    (src / "marketplace.db").write_text("sqlite binary content\n")

    result = build_artifact(
        src,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=tmp_path / "out.xdeploy.enc",
    )

    members = _extracted_member_names(result)
    assert not any(".venv" in name for name in members)
    assert not any(".git" in name for name in members)
    assert not any("node_modules" in name for name in members)
    assert not any("__pycache__" in name for name in members)
    assert not any(name.endswith("conf/.env") for name in members)
    assert not any(name.endswith("private.pem") for name in members)
    assert not any(name.endswith("marketplace.db") for name in members)
    # the template is a legitimate deployment artifact, not a secret
    assert any(name.endswith("conf/.env.template") for name in members)


def test_content_sha256_ignores_excluded_files(tmp_path):
    # content_sha256 must describe the tree that's actually sealed
    # (packaging_root, post-exclusion) — not source_root verbatim, or the
    # agent's post-extraction re-verification would never match anything
    # real once a project has a .venv/.env/etc. sitting next to its plugins.
    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)

    result_without_bloat = build_artifact(
        src,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=tmp_path / "out1.xdeploy.enc",
    )
    (src / "manifest.json").unlink()

    (src / ".venv").mkdir()
    (src / ".venv" / "whatever.py").write_text("# irrelevant to content_sha256\n")
    (src / "secret.pem").write_text("-----BEGIN PRIVATE KEY-----\nFAKE\n")

    result_with_bloat = build_artifact(
        src,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=tmp_path / "out2.xdeploy.enc",
    )

    assert result_without_bloat.manifest.content_sha256 == result_with_bloat.manifest.content_sha256


# ── source: declared in install.yaml — plugin.yaml/extension.yaml untouched ──


def test_source_declared_in_install_yaml_marketplace(tmp_path):
    # plugin.yaml has no source: of its own — the operator centralizes
    # every plugin's origin in install.yaml instead, see
    # InstallPluginStep.source's docstring.
    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)
    (src / "deployment" / "install.yaml").write_text(
        yaml.safe_dump(
            {
                "format_version": "1",
                "project_id": PROJECT_ID,
                "version": "1.0.0",
                "steps": [
                    {"id": "prepare", "action": "prepare"},
                    {
                        "id": "install_demo",
                        "action": "install_plugin",
                        "plugin": "demo",
                        "source": {"marketplace_slug": "demo", "marketplace_version": "2.0.0"},
                    },
                ],
            }
        )
    )

    result = build_artifact(
        src,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=tmp_path / "out.xdeploy.enc",
    )

    plugin = result.manifest.plugins[0]
    assert plugin.source is not None
    assert plugin.source.marketplace_slug == "demo"
    assert plugin.source.marketplace_version == "2.0.0"
    assert plugin.sha256 is None  # source-based, nothing embedded to hash
    # plugin.yaml itself never had to declare a source: at all
    assert "source" not in yaml.safe_load((src / "plugins" / "demo" / "plugin.yaml").read_text())


def test_source_declared_in_install_yaml_git_fallback(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)
    (src / "deployment" / "install.yaml").write_text(
        yaml.safe_dump(
            {
                "format_version": "1",
                "project_id": PROJECT_ID,
                "version": "1.0.0",
                "steps": [
                    {"id": "prepare", "action": "prepare"},
                    {
                        "id": "install_demo",
                        "action": "install_plugin",
                        "plugin": "demo",
                        "source": {
                            "url": "https://github.com/acme/demo.git",
                            "ref": "a" * 40,
                        },
                    },
                ],
            }
        )
    )

    result = build_artifact(
        src,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=tmp_path / "out.xdeploy.enc",
    )

    plugin = result.manifest.plugins[0]
    assert plugin.source is not None
    assert plugin.source.url == "https://github.com/acme/demo.git"
    assert plugin.source.ref == "a" * 40


def test_install_yaml_source_wins_over_plugin_yaml_source(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)
    (src / "plugins" / "demo" / "plugin.yaml").write_text(
        "name: demo\nversion: 1.0.0\nsource:\n  url: https://github.com/from-plugin-yaml/demo.git\n"
        f"  ref: {'b' * 40}\n"
    )
    (src / "deployment" / "install.yaml").write_text(
        yaml.safe_dump(
            {
                "format_version": "1",
                "project_id": PROJECT_ID,
                "version": "1.0.0",
                "steps": [
                    {"id": "prepare", "action": "prepare"},
                    {
                        "id": "install_demo",
                        "action": "install_plugin",
                        "plugin": "demo",
                        "source": {"marketplace_slug": "demo"},
                    },
                ],
            }
        )
    )

    result = build_artifact(
        src,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=tmp_path / "out.xdeploy.enc",
    )

    plugin = result.manifest.plugins[0]
    assert plugin.source.marketplace_slug == "demo"  # install.yaml wins
    assert plugin.source.url is None


def test_install_yaml_source_for_extension(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)
    (src / "extensions" / "mail").mkdir(parents=True)
    # extension.yaml is entirely absent — install.yaml is the only place
    # this extension's origin is declared.
    (src / "deployment" / "install.yaml").write_text(
        yaml.safe_dump(
            {
                "format_version": "1",
                "project_id": PROJECT_ID,
                "version": "1.0.0",
                "steps": [
                    {"id": "prepare", "action": "prepare"},
                    {"id": "install_demo", "action": "install_plugin", "plugin": "demo"},
                    {
                        "id": "install_mail",
                        "action": "install_extension",
                        "extension": "mail",
                        "source": {
                            "marketplace_slug": "mail",
                            "marketplace_kind": "service",
                        },
                    },
                ],
            }
        )
    )

    result = build_artifact(
        src,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=tmp_path / "out.xdeploy.enc",
    )

    ext = result.manifest.extensions[0]
    assert ext.source is not None
    assert ext.source.marketplace_slug == "mail"
    assert ext.source.marketplace_kind == "service"
    assert ext.sha256 is None
    assert not (src / "extensions" / "mail" / "extension.yaml").exists()


# ── Pruning a source-based plugin/extension: .env.template must survive it ──


def test_source_based_plugin_env_template_survives_pruning(tmp_path):
    # A source-based plugin's local .env.template (build-time-only, no
    # counterpart in the resolved repo — see agent.pipeline._resolve_
    # plugins) must still ship, even though the plugin's real code doesn't:
    # write_env reads it at deploy time before the plugin is even resolved.
    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)
    (src / "plugins" / "demo" / "plugin.yaml").write_text(
        "name: demo\nversion: 1.0.0\nsource:\n  url: https://github.com/acme/demo.git\n"
        f"  ref: {'a' * 40}\n"
    )
    (src / "plugins" / "demo" / ".env.template").write_text("DEMO_API_KEY=\n")
    (src / "plugins" / "demo" / "main.py").write_text("# leftover local code, should be pruned\n")

    result = build_artifact(
        src,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=tmp_path / "out.xdeploy.enc",
    )

    members = _extracted_member_names(result)
    demo_members = {m for m in members if m.startswith("./plugins/demo/")}
    assert demo_members == {"./plugins/demo/plugin.yaml", "./plugins/demo/.env.template"}


def test_source_based_extension_env_template_survives_pruning(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)
    (src / "extensions" / "mail").mkdir(parents=True)
    (src / "extensions" / "mail" / "extension.yaml").write_text(
        f"source:\n  url: https://github.com/acme/mail.git\n  ref: {'a' * 40}\n"
    )
    (src / "extensions" / "mail" / ".env.template").write_text("SMTP_HOST=\n")
    (src / "extensions" / "mail" / "main.py").write_text("# leftover, should be pruned\n")
    (src / "deployment" / "install.yaml").write_text(
        yaml.safe_dump(
            {
                "format_version": "1",
                "project_id": PROJECT_ID,
                "version": "1.0.0",
                "steps": [
                    {"id": "prepare", "action": "prepare"},
                    {"id": "install_demo", "action": "install_plugin", "plugin": "demo"},
                    {"id": "install_mail", "action": "install_extension", "extension": "mail"},
                ],
            }
        )
    )

    result = build_artifact(
        src,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=tmp_path / "out.xdeploy.enc",
    )

    members = _extracted_member_names(result)
    mail_members = {m for m in members if m.startswith("./extensions/mail/")}
    assert mail_members == {"./extensions/mail/extension.yaml", "./extensions/mail/.env.template"}


def test_content_sha256_excludes_pruned_source_based_plugin_leftovers(tmp_path):
    # The regression this whole section guards against: content_sha256 must
    # describe the SEALED tree (post-pruning), not source_root as it
    # happens to look right now — otherwise the agent's post-extraction
    # re-verification (compute_tree_digest over the actually-extracted
    # tree, which never had the leftover files to begin with) can never
    # match, for any project where a source-based plugin/extension still
    # has its old embedded code sitting next to a newly-added `source:`.
    src = tmp_path / "src"
    src.mkdir()
    _minimal_source_tree(src)
    (src / "plugins" / "demo" / "plugin.yaml").write_text(
        "name: demo\nversion: 1.0.0\nsource:\n  url: https://github.com/acme/demo.git\n"
        f"  ref: {'a' * 40}\n"
    )

    result_thin = build_artifact(
        src,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=tmp_path / "out1.xdeploy.enc",
    )
    (src / "manifest.json").unlink()

    # Add leftover local code that will be pruned away — content_sha256
    # must come out identical, since it's never actually sealed.
    (src / "plugins" / "demo" / "main.py").write_text("# leftover local code\n")
    (src / "plugins" / "demo" / "helpers.py").write_text("# more leftover code\n")

    result_with_leftovers = build_artifact(
        src,
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        output_path=tmp_path / "out2.xdeploy.enc",
    )

    assert result_thin.manifest.content_sha256 == result_with_leftovers.manifest.content_sha256
