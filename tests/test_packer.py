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
