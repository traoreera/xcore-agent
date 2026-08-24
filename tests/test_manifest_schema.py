import pytest
from pydantic import ValidationError

from xcore_agent.schema.manifest import ProjectManifest

VALID_MANIFEST = {
    "format_version": "1",
    "project_id": "prj_01JXYZABCDEF",
    "project_name": "my-erp",
    "version": "1.0.0",
    "built_at": "2026-08-18T10:00:00Z",
    "plugins": [
        {"id": "xcore.auth", "version": "2.1.0", "sha256": "a" * 64},
        {"id": "xcore.database", "version": "1.4.2", "sha256": "b" * 64},
    ],
    "content_sha256": "c" * 64,
}


def test_valid_manifest_parses():
    manifest = ProjectManifest.model_validate(VALID_MANIFEST)
    assert manifest.project_name == "my-erp"
    assert len(manifest.plugins) == 2


def test_plugin_lookup():
    manifest = ProjectManifest.model_validate(VALID_MANIFEST)
    assert manifest.plugin("xcore.auth").version == "2.1.0"
    with pytest.raises(KeyError):
        manifest.plugin("does-not-exist")


def test_invalid_project_id_is_rejected():
    bad = {**VALID_MANIFEST, "project_id": "not-a-project-id"}
    with pytest.raises(ValidationError):
        ProjectManifest.model_validate(bad)


def test_invalid_sha256_is_rejected():
    bad = {**VALID_MANIFEST, "content_sha256": "not-a-hash"}
    with pytest.raises(ValidationError):
        ProjectManifest.model_validate(bad)


def test_invalid_semver_is_rejected():
    bad = {**VALID_MANIFEST, "version": "v1"}
    with pytest.raises(ValidationError):
        ProjectManifest.model_validate(bad)


def test_empty_plugins_list_is_rejected():
    bad = {**VALID_MANIFEST, "plugins": []}
    with pytest.raises(ValidationError):
        ProjectManifest.model_validate(bad)


def test_extra_fields_are_rejected():
    bad = {**VALID_MANIFEST, "unexpected_field": 1}
    with pytest.raises(ValidationError):
        ProjectManifest.model_validate(bad)


def test_plugins_dirname_defaults_to_plugins():
    manifest = ProjectManifest.model_validate(VALID_MANIFEST)
    assert manifest.plugins_dirname == "plugins"


def test_plugins_dirname_accepts_a_custom_value():
    manifest = ProjectManifest.model_validate({**VALID_MANIFEST, "plugins_dirname": "app"})
    assert manifest.plugins_dirname == "app"


@pytest.mark.parametrize("bad_value", ["", "/absolute", "../escape", "has space", "trailing/"])
def test_invalid_plugins_dirname_is_rejected(bad_value):
    bad = {**VALID_MANIFEST, "plugins_dirname": bad_value}
    with pytest.raises(ValidationError):
        ProjectManifest.model_validate(bad)


def test_extensions_default_to_empty_list():
    # A project with no extensions/ directory at all is the common case,
    # not an error — unlike `plugins`, which is rejected if empty.
    manifest = ProjectManifest.model_validate(VALID_MANIFEST)
    assert manifest.extensions == []


def test_extension_lookup():
    with_ext = {
        **VALID_MANIFEST,
        "extensions": [{"id": "xmailler", "sha256": "d" * 64}],
    }
    manifest = ProjectManifest.model_validate(with_ext)
    assert manifest.extension("xmailler").sha256 == "d" * 64
    with pytest.raises(KeyError):
        manifest.extension("does-not-exist")


def test_extension_missing_sha256_without_source_is_rejected():
    # sha256 is required for an EMBEDDED extension (no `source:`) — same
    # rule as PluginRef.
    bad = {
        **VALID_MANIFEST,
        "extensions": [{"id": "xmailler"}],
    }
    with pytest.raises(ValidationError):
        ProjectManifest.model_validate(bad)


def test_extension_with_source_does_not_require_sha256():
    with_ext = {
        **VALID_MANIFEST,
        "extensions": [
            {
                "id": "xmailler",
                "source": {"url": "https://github.com/acme/xmailler.git", "ref": "a" * 40},
            }
        ],
    }
    manifest = ProjectManifest.model_validate(with_ext)
    ext = manifest.extension("xmailler")
    assert ext.sha256 is None
    assert ext.source.ref == "a" * 40


def test_extension_with_source_and_pinned_sha256_is_allowed():
    # Mirrors PluginRef: a source-based extension MAY still pin a hash for
    # the agent to re-verify after resolving — it's just not required.
    with_ext = {
        **VALID_MANIFEST,
        "extensions": [
            {
                "id": "xmailler",
                "sha256": "e" * 64,
                "source": {"url": "https://github.com/acme/xmailler.git", "ref": "a" * 40},
            }
        ],
    }
    manifest = ProjectManifest.model_validate(with_ext)
    assert manifest.extension("xmailler").sha256 == "e" * 64
