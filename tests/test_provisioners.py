"""Tests for ShellCommandProvisioner and load_provisioners_from_config,
using real subprocess calls (a tiny shell script per test) rather than
mocking subprocess — cheap and proves the actual argv/env/error handling.
"""

import stat

import pytest

from xcore_agent.agent.errors import InstallError
from xcore_agent.agent.provisioners import ShellCommandProvisioner, load_provisioners_from_config
from xcore_agent.schema.install import ProvisionStep


def _make_script(tmp_path, name: str, body: str):
    path = tmp_path / name
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


def test_provisioner_runs_command_with_plugin_id_and_env(tmp_path):
    log = tmp_path / "log.txt"
    script = _make_script(
        tmp_path,
        "provision.sh",
        f'echo "arg=$1 env=$PROVISION_PLUGIN_ID extra=$MY_VAR" > {log}',
    )
    provisioner = ShellCommandProvisioner(command=[str(script)], env={"MY_VAR": "hello"})
    step = ProvisionStep(id="provision_demo", action="provision", plugin="demo")

    provisioner(step)  # must not raise

    assert log.read_text().strip() == "arg=demo env=demo extra=hello"


def test_provisioner_raises_on_nonzero_exit(tmp_path):
    script = _make_script(tmp_path, "fail.sh", "echo 'boom' >&2; exit 3")
    provisioner = ShellCommandProvisioner(command=[str(script)])
    step = ProvisionStep(id="provision_demo", action="provision", plugin="demo")

    with pytest.raises(InstallError, match="boom"):
        provisioner(step)


def test_provisioner_raises_on_timeout(tmp_path):
    script = _make_script(tmp_path, "slow.sh", "sleep 5")
    provisioner = ShellCommandProvisioner(command=[str(script)], timeout_seconds=0.1)
    step = ProvisionStep(id="provision_demo", action="provision", plugin="demo")

    with pytest.raises(InstallError, match="timed out"):
        provisioner(step)


def test_load_provisioners_from_config(tmp_path):
    config = tmp_path / "provisioners.yaml"
    config.write_text(
        "demo:\n"
        "  command: ['/usr/local/bin/provision-demo.sh']\n"
        "  env:\n"
        "    PGHOST: localhost\n"
        "  timeout: 60\n"
        "auth:\n"
        "  command: ['/usr/local/bin/provision-auth.sh']\n"
    )

    provisioners = load_provisioners_from_config(config)

    assert set(provisioners) == {"demo", "auth"}
    demo = provisioners["demo"]
    assert isinstance(demo, ShellCommandProvisioner)
    assert demo.command == ["/usr/local/bin/provision-demo.sh"]
    assert demo.env == {"PGHOST": "localhost"}
    assert demo.timeout_seconds == 60
    assert provisioners["auth"].timeout_seconds == 300  # default


def test_load_provisioners_from_config_rejects_missing_command(tmp_path):
    config = tmp_path / "provisioners.yaml"
    config.write_text("demo:\n  env:\n    FOO: bar\n")

    with pytest.raises(InstallError, match="invalid provisioner config"):
        load_provisioners_from_config(config)


def test_load_provisioners_from_config_rejects_non_mapping(tmp_path):
    config = tmp_path / "provisioners.yaml"
    config.write_text("- not\n- a\n- mapping\n")

    with pytest.raises(InstallError, match="expected a mapping"):
        load_provisioners_from_config(config)


def test_loaded_provisioner_is_usable_end_to_end(tmp_path):
    log = tmp_path / "log.txt"
    script = _make_script(tmp_path, "provision.sh", f'echo "provisioned $1" > {log}')
    config = tmp_path / "provisioners.yaml"
    config.write_text(f"demo:\n  command: ['{script}']\n")

    provisioners = load_provisioners_from_config(config)
    step = ProvisionStep(id="provision_demo", action="provision", plugin="demo")
    provisioners["demo"](step)

    assert log.read_text().strip() == "provisioned demo"
