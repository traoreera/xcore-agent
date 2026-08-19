import subprocess
from unittest.mock import patch

import pytest

from xcore_agent.agent.errors import HealthcheckError
from xcore_agent.agent.systemd_supervisor import SystemdCommandError, SystemdSupervisor


def _completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def test_start_uses_user_scope_by_default():
    supervisor = SystemdSupervisor()
    with patch("subprocess.run", return_value=_completed()) as mock_run:
        supervisor.start("demo")
    assert mock_run.call_args[0][0] == ["systemctl", "--user", "start", "xcore-plugin-demo.service"]


def test_start_without_user_scope_omits_flag():
    supervisor = SystemdSupervisor(user_scope=False)
    with patch("subprocess.run", return_value=_completed()) as mock_run:
        supervisor.start("demo")
    assert mock_run.call_args[0][0] == ["systemctl", "start", "xcore-plugin-demo.service"]


def test_no_plugin_id_targets_the_project_unit():
    supervisor = SystemdSupervisor()
    with patch("subprocess.run", return_value=_completed()) as mock_run:
        supervisor.start(None)
    assert mock_run.call_args[0][0][-1] == "xcore-project.service"


def test_custom_unit_prefix_is_used():
    supervisor = SystemdSupervisor(unit_prefix="myproj-")
    with patch("subprocess.run", return_value=_completed()) as mock_run:
        supervisor.stop("demo")
    assert mock_run.call_args[0][0][-1] == "myproj-demo.service"


def test_stop_and_restart_dispatch_correct_verb():
    supervisor = SystemdSupervisor()
    with patch("subprocess.run", return_value=_completed()) as mock_run:
        supervisor.stop("demo")
        supervisor.restart("demo")
    assert mock_run.call_args_list[0][0][0][-2] == "stop"
    assert mock_run.call_args_list[1][0][0][-2] == "restart"


def test_failed_systemctl_call_raises_with_stderr(monkeypatch):
    supervisor = SystemdSupervisor()
    with patch("subprocess.run", return_value=_completed(returncode=1, stderr="unit not found")):
        with pytest.raises(SystemdCommandError, match="unit not found"):
            supervisor.restart("demo")


def test_missing_systemctl_binary_raises_command_error():
    supervisor = SystemdSupervisor()
    with patch("subprocess.run", side_effect=FileNotFoundError()):
        with pytest.raises(SystemdCommandError, match="not found"):
            supervisor.start("demo")


def test_is_active_reports_true_when_active():
    supervisor = SystemdSupervisor()
    with patch("subprocess.run", return_value=_completed(stdout="active\n")):
        assert supervisor.is_active("demo") is True


def test_is_active_reports_false_when_inactive():
    supervisor = SystemdSupervisor()
    with patch("subprocess.run", return_value=_completed(stdout="inactive\n")):
        assert supervisor.is_active("demo") is False


def test_healthcheck_succeeds_immediately_when_active():
    supervisor = SystemdSupervisor()
    with patch("subprocess.run", return_value=_completed(stdout="active\n")) as mock_run:
        supervisor.healthcheck("demo", timeout_seconds=5, retries=2)
    assert mock_run.call_count == 1


def test_healthcheck_retries_then_raises(monkeypatch):
    supervisor = SystemdSupervisor(healthcheck_poll_interval_seconds=0)
    calls = {"n": 0}

    def fake_run(cmd, capture_output=True, text=True, timeout=None):
        calls["n"] += 1
        return _completed(stdout="activating\n")

    with patch("subprocess.run", side_effect=fake_run):
        with pytest.raises(HealthcheckError, match="did not become active"):
            supervisor.healthcheck("demo", timeout_seconds=1, retries=2)

    assert calls["n"] == 3  # initial attempt + 2 retries
