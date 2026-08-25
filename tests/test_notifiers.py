"""Tests for ShellCommandNotifier and load_notifiers_from_config — mirrors
test_provisioners.py's approach (real subprocess calls via a tiny shell
script per test, no mocking) and its structure, since notifiers.py is
deliberately the same pattern applied to a different, best-effort action.
"""

import stat

import pytest

from xcore_agent.agent.errors import InstallError
from xcore_agent.agent.notifiers import ShellCommandNotifier, load_notifiers_from_config
from xcore_agent.schema.install import NotifyStep


def _make_script(tmp_path, name: str, body: str):
    path = tmp_path / name
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


def test_notifier_runs_command_with_event_message_and_env(tmp_path):
    log = tmp_path / "log.txt"
    script = _make_script(
        tmp_path,
        "notify.sh",
        f'echo "arg1=$1 arg2=$2 env=$NOTIFY_EVENT msg=$NOTIFY_MESSAGE extra=$MY_VAR" > {log}',
    )
    notifier = ShellCommandNotifier(command=[str(script)], env={"MY_VAR": "hello"})
    step = NotifyStep(id="notify_demo", action="notify", event="deploy_success", message="ok")

    notifier(step)  # must not raise

    assert (
        log.read_text().strip()
        == "arg1=deploy_success arg2=ok env=deploy_success msg=ok extra=hello"
    )


def test_notifier_defaults_message_to_empty_string(tmp_path):
    log = tmp_path / "log.txt"
    script = _make_script(tmp_path, "notify.sh", f'echo "[$2]" > {log}')
    notifier = ShellCommandNotifier(command=[str(script)])
    step = NotifyStep(id="notify_demo", action="notify", event="deploy_success")

    notifier(step)

    assert log.read_text().strip() == "[]"


def test_notifier_raises_on_nonzero_exit(tmp_path):
    script = _make_script(tmp_path, "fail.sh", "echo 'boom' >&2; exit 3")
    notifier = ShellCommandNotifier(command=[str(script)])
    step = NotifyStep(id="notify_demo", action="notify", event="deploy_failed")

    with pytest.raises(InstallError, match="boom"):
        notifier(step)


def test_notifier_raises_on_timeout(tmp_path):
    script = _make_script(tmp_path, "slow.sh", "sleep 5")
    notifier = ShellCommandNotifier(command=[str(script)], timeout_seconds=0.1)
    step = NotifyStep(id="notify_demo", action="notify", event="deploy_success")

    with pytest.raises(InstallError, match="timed out"):
        notifier(step)


def test_load_notifiers_from_config(tmp_path):
    config = tmp_path / "notifiers.yaml"
    config.write_text(
        "deploy_success:\n"
        "  command: ['/usr/local/bin/notify-slack.sh']\n"
        "  env:\n"
        "    SLACK_CHANNEL: deploys\n"
        "  timeout: 15\n"
        "deploy_failed:\n"
        "  command: ['/usr/local/bin/notify-slack.sh', '--urgent']\n"
    )

    notifiers = load_notifiers_from_config(config)

    assert set(notifiers) == {"deploy_success", "deploy_failed"}
    success = notifiers["deploy_success"]
    assert isinstance(success, ShellCommandNotifier)
    assert success.command == ["/usr/local/bin/notify-slack.sh"]
    assert success.env == {"SLACK_CHANNEL": "deploys"}
    assert success.timeout_seconds == 15
    assert notifiers["deploy_failed"].timeout_seconds == 30  # default


def test_load_notifiers_from_config_rejects_missing_command(tmp_path):
    config = tmp_path / "notifiers.yaml"
    config.write_text("deploy_success:\n  env:\n    FOO: bar\n")

    with pytest.raises(InstallError, match="invalid notifier config"):
        load_notifiers_from_config(config)


def test_load_notifiers_from_config_rejects_non_mapping(tmp_path):
    config = tmp_path / "notifiers.yaml"
    config.write_text("- not\n- a\n- mapping\n")

    with pytest.raises(InstallError, match="expected a mapping"):
        load_notifiers_from_config(config)


def test_loaded_notifier_is_usable_end_to_end(tmp_path):
    log = tmp_path / "log.txt"
    script = _make_script(tmp_path, "notify.sh", f'echo "notified $1" > {log}')
    config = tmp_path / "notifiers.yaml"
    config.write_text(f"deploy_success:\n  command: ['{script}']\n")

    notifiers = load_notifiers_from_config(config)
    step = NotifyStep(id="notify_demo", action="notify", event="deploy_success")
    notifiers["deploy_success"](step)

    assert log.read_text().strip() == "notified deploy_success"
