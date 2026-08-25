"""Direct tests for InstallDriver's provisioner registry, required
environment variable validation, and extension install/rollback — the
behaviors not already exercised indirectly through the full pipeline in
test_pipeline.py (which does cover install_extension end-to-end via a real
built artifact — this file tests InstallDriver.install_extension/rollback
in isolation instead)."""

import json

import pytest

from xcore_agent.agent.errors import InstallError
from xcore_agent.agent.install_driver import InstallDriver, Layout
from xcore_agent.agent.plugin_signing import SIG_FILENAME
from xcore_agent.schema.install import (
    InstallExtensionStep,
    InstallPluginStep,
    NotifyStep,
    ProvisionStep,
    WriteEnvStep,
)
from xcore_agent.schema.manifest import EnvironmentSpec, PluginRef, ProjectManifest

PROJECT_ID = "prj_test0000001"


def _layout(tmp_path):
    return Layout(project_root=tmp_path / "project", extracted_root=tmp_path / "extracted")


def _manifest(*, environment: EnvironmentSpec | None) -> ProjectManifest:
    return ProjectManifest(
        format_version="1",
        project_id=PROJECT_ID,
        project_name="demo-project",
        version="1.0.0",
        built_at="2026-08-18T10:00:00Z",
        plugins=[PluginRef(id="demo", version="1.0.0", sha256="0" * 64, environment=environment)],
        content_sha256="1" * 64,
    )


def test_provision_without_registered_provisioner_raises(tmp_path):
    driver = InstallDriver(_layout(tmp_path))
    step = ProvisionStep(id="provision_demo", action="provision", plugin="demo")

    with pytest.raises(InstallError, match="no provisioner registered"):
        driver.provision(step)


def test_provision_calls_registered_provisioner(tmp_path):
    calls = []
    driver = InstallDriver(_layout(tmp_path), provisioners={"demo": calls.append})
    step = ProvisionStep(id="provision_demo", action="provision", plugin="demo")

    driver.provision(step)

    assert calls == [step]


def test_notify_without_registered_notifier_is_a_silent_no_op(tmp_path):
    # Unlike provision (infra-critical, fails hard), a missing notifier
    # must never fail the deployment — notifying is a side channel.
    driver = InstallDriver(_layout(tmp_path))
    step = NotifyStep(id="notify_demo", action="notify", event="deploy_success")

    driver.notify(step)  # must not raise


def test_notify_calls_registered_notifier(tmp_path):
    calls = []
    driver = InstallDriver(_layout(tmp_path), notifiers={"deploy_success": calls.append})
    step = NotifyStep(id="notify_demo", action="notify", event="deploy_success", message="ok")

    driver.notify(step)

    assert calls == [step]


def test_notify_swallows_a_failing_notifier(tmp_path):
    def _boom(step: NotifyStep) -> None:
        raise InstallError("webhook unreachable")

    driver = InstallDriver(_layout(tmp_path), notifiers={"deploy_success": _boom})
    step = NotifyStep(id="notify_demo", action="notify", event="deploy_success")

    driver.notify(step)  # must not raise despite the notifier failing


def test_write_env_skips_validation_without_manifest(tmp_path):
    layout = _layout(tmp_path)
    (layout.extracted_root / "plugins" / "demo").mkdir(parents=True)
    template = layout.extracted_root / "plugins" / "demo" / ".env.template"
    template.write_text("REQUIRED_KEY=\n")

    driver = InstallDriver(layout)  # no manifest attached
    step = WriteEnvStep(
        id="write_env", action="write_env", plugin="demo", **{"from": "plugins/demo/.env.template"}
    )

    driver.write_env(step)  # must not raise — nothing to validate against

    assert layout.plugin_env_file("demo").is_file()


def test_write_env_raises_when_required_var_missing(tmp_path):
    layout = _layout(tmp_path)
    (layout.extracted_root / "plugins" / "demo").mkdir(parents=True)
    template = layout.extracted_root / "plugins" / "demo" / ".env.template"
    template.write_text("DEMO_API_KEY=\n")

    driver = InstallDriver(
        layout, manifest=_manifest(environment=EnvironmentSpec(required=["DEMO_API_KEY"]))
    )
    step = WriteEnvStep(
        id="write_env", action="write_env", plugin="demo", **{"from": "plugins/demo/.env.template"}
    )

    with pytest.raises(InstallError, match="DEMO_API_KEY"):
        driver.write_env(step)


def test_write_env_passes_when_required_var_present(tmp_path):
    layout = _layout(tmp_path)
    (layout.extracted_root / "plugins" / "demo").mkdir(parents=True)
    template = layout.extracted_root / "plugins" / "demo" / ".env.template"
    template.write_text("DEMO_API_KEY=\n")
    # Simulate a host operator having already filled the file in.
    layout.plugins_dir.mkdir(parents=True)
    layout.plugin_env_file("demo").write_text("DEMO_API_KEY=super-secret\n")

    driver = InstallDriver(
        layout, manifest=_manifest(environment=EnvironmentSpec(required=["DEMO_API_KEY"]))
    )
    step = WriteEnvStep(
        id="write_env", action="write_env", plugin="demo", **{"from": "plugins/demo/.env.template"}
    )

    driver.write_env(step)  # must not raise, and must not overwrite the host file

    assert "super-secret" in layout.plugin_env_file("demo").read_text()


def test_write_env_seeds_from_os_environ_when_key_present(tmp_path, monkeypatch):
    layout = _layout(tmp_path)
    (layout.extracted_root / "plugins" / "demo").mkdir(parents=True)
    template = layout.extracted_root / "plugins" / "demo" / ".env.template"
    template.write_text("# comment kept as-is\nDEMO_API_KEY=\nDEMO_LOG_LEVEL=info\n")
    monkeypatch.setenv("DEMO_API_KEY", "real-value-from-os-env")

    driver = InstallDriver(layout)
    step = WriteEnvStep(
        id="write_env", action="write_env", plugin="demo", **{"from": "plugins/demo/.env.template"}
    )
    driver.write_env(step)

    written = layout.plugin_env_file("demo").read_text()
    assert "DEMO_API_KEY=real-value-from-os-env" in written
    # Key not in os.environ: falls back to the template's own value untouched.
    assert "DEMO_LOG_LEVEL=info" in written
    assert "# comment kept as-is" in written


def test_write_env_still_never_overwrites_an_existing_host_file(tmp_path, monkeypatch):
    layout = _layout(tmp_path)
    (layout.extracted_root / "plugins" / "demo").mkdir(parents=True)
    template = layout.extracted_root / "plugins" / "demo" / ".env.template"
    template.write_text("DEMO_API_KEY=\n")
    monkeypatch.setenv("DEMO_API_KEY", "should-not-be-used")
    layout.plugins_dir.mkdir(parents=True)
    layout.plugin_env_file("demo").write_text("DEMO_API_KEY=already-configured-by-operator\n")

    driver = InstallDriver(layout)
    step = WriteEnvStep(
        id="write_env", action="write_env", plugin="demo", **{"from": "plugins/demo/.env.template"}
    )
    driver.write_env(step)

    assert "already-configured-by-operator" in layout.plugin_env_file("demo").read_text()


def test_write_env_skips_validation_when_no_environment_spec(tmp_path):
    layout = _layout(tmp_path)
    (layout.extracted_root / "plugins" / "demo").mkdir(parents=True)
    template = layout.extracted_root / "plugins" / "demo" / ".env.template"
    template.write_text("")

    driver = InstallDriver(layout, manifest=_manifest(environment=None))
    step = WriteEnvStep(
        id="write_env", action="write_env", plugin="demo", **{"from": "plugins/demo/.env.template"}
    )

    driver.write_env(step)  # must not raise


def test_install_plugin_signs_trusted_plugin_when_secret_key_configured(tmp_path):
    layout = _layout(tmp_path)
    (layout.extracted_root / "plugins" / "demo" / "src").mkdir(parents=True)
    (layout.extracted_root / "plugins" / "demo" / "plugin.yaml").write_text(
        "name: demo\nversion: 1.0.0\nexecution_mode: trusted\nentry_point: src/main.py\n"
    )
    (layout.extracted_root / "plugins" / "demo" / "src" / "main.py").write_text("# demo\n")

    driver = InstallDriver(layout, plugin_secret_key=b"host-secret")
    driver.install_plugin(
        InstallPluginStep(id="install_demo", action="install_plugin", plugin="demo")
    )

    sig_path = layout.plugin_dir("demo") / SIG_FILENAME
    assert sig_path.is_file()
    assert json.loads(sig_path.read_text())["plugin"] == "demo"


def test_install_plugin_does_not_sign_without_secret_key_configured(tmp_path):
    # No plugin_secret_key passed to InstallDriver at all — a deployment
    # targeting a host with no strict_trusted to satisfy pays nothing.
    layout = _layout(tmp_path)
    (layout.extracted_root / "plugins" / "demo" / "src").mkdir(parents=True)
    (layout.extracted_root / "plugins" / "demo" / "plugin.yaml").write_text(
        "name: demo\nversion: 1.0.0\nexecution_mode: trusted\nentry_point: src/main.py\n"
    )
    (layout.extracted_root / "plugins" / "demo" / "src" / "main.py").write_text("# demo\n")

    driver = InstallDriver(layout)  # plugin_secret_key defaults to None
    driver.install_plugin(
        InstallPluginStep(id="install_demo", action="install_plugin", plugin="demo")
    )

    assert not (layout.plugin_dir("demo") / SIG_FILENAME).exists()


def test_install_plugin_uses_custom_plugins_dirname(tmp_path):
    # Layout.plugins_dirname set as DeploymentRunner._verify_manifest does
    # from a manifest with plugins_dirname="app" — the extracted source AND
    # the installed target should both live under "app/", not "plugins/".
    layout = Layout(
        project_root=tmp_path / "project",
        extracted_root=tmp_path / "extracted",
        plugins_dirname="app",
    )
    (layout.extracted_root / "app" / "demo").mkdir(parents=True)
    (layout.extracted_root / "app" / "demo" / "plugin.yaml").write_text(
        "name: demo\nversion: 1.0.0\n"
    )

    driver = InstallDriver(layout)
    driver.install_plugin(
        InstallPluginStep(id="install_demo", action="install_plugin", plugin="demo")
    )

    assert (tmp_path / "project" / "app" / "demo" / "plugin.yaml").is_file()
    assert not (tmp_path / "project" / "plugins").exists()


def test_install_extension_missing_from_extracted_artifact_raises(tmp_path):
    driver = InstallDriver(_layout(tmp_path))
    step = InstallExtensionStep(id="install_mail", action="install_extension", extension="mail")

    with pytest.raises(InstallError, match="not found in extracted artifact"):
        driver.install_extension(step)


def test_install_extension_copies_into_project_root_extensions(tmp_path):
    layout = _layout(tmp_path)
    (layout.extracted_root / "extensions" / "mail").mkdir(parents=True)
    (layout.extracted_root / "extensions" / "mail" / "client.py").write_text("# mail\n")

    driver = InstallDriver(layout)
    step = InstallExtensionStep(id="install_mail", action="install_extension", extension="mail")

    driver.install_extension(step)

    installed = layout.extension_dir("mail") / "client.py"
    assert installed.is_file()
    assert installed.read_text() == "# mail\n"


def test_install_extension_snapshot_and_rollback_deletes_fresh_install(tmp_path):
    # Mirrors install_plugin's rollback semantics (test_install_failure_
    # triggers_rollback in test_pipeline.py): no prior state means rollback
    # deletes what this step created, rather than restoring a copy that
    # never existed.
    layout = _layout(tmp_path)
    (layout.extracted_root / "extensions" / "mail").mkdir(parents=True)
    (layout.extracted_root / "extensions" / "mail" / "client.py").write_text("# mail\n")

    driver = InstallDriver(layout)
    step = InstallExtensionStep(
        id="install_mail", action="install_extension", extension="mail", snapshot=True
    )
    driver.install_extension(step)
    assert layout.extension_dir("mail").exists()

    driver.rollback()

    assert not layout.extension_dir("mail").exists()
