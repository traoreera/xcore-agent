import subprocess
from unittest.mock import patch

import pytest

from xcore_agent.agent.docker_supervisor import DockerCommandError, DockerSupervisor
from xcore_agent.agent.errors import HealthcheckError


def _completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def test_start_targets_prefixed_container():
    supervisor = DockerSupervisor()
    with patch("subprocess.run", return_value=_completed()) as mock_run:
        supervisor.start("demo")
    assert mock_run.call_args[0][0] == ["docker", "start", "xcore-plugin-demo"]


def test_no_plugin_id_targets_the_project_container():
    supervisor = DockerSupervisor()
    with patch("subprocess.run", return_value=_completed()) as mock_run:
        supervisor.stop(None)
    assert mock_run.call_args[0][0][-1] == "xcore-project"


def test_custom_container_prefix_is_used():
    supervisor = DockerSupervisor(container_prefix="myproj-")
    with patch("subprocess.run", return_value=_completed()) as mock_run:
        supervisor.restart("demo")
    assert mock_run.call_args[0][0][-1] == "myproj-demo"


def test_failed_docker_call_raises_with_stderr():
    supervisor = DockerSupervisor()
    with patch("subprocess.run", return_value=_completed(returncode=1, stderr="no such container")):
        with pytest.raises(DockerCommandError, match="no such container"):
            supervisor.start("demo")


def test_missing_docker_binary_raises_command_error():
    supervisor = DockerSupervisor()
    with patch("subprocess.run", side_effect=FileNotFoundError()):
        with pytest.raises(DockerCommandError, match="not found"):
            supervisor.start("demo")


def test_is_running_true():
    supervisor = DockerSupervisor()
    with patch("subprocess.run", return_value=_completed(stdout="true\n")):
        assert supervisor.is_running("demo") is True


def test_is_running_false_when_inspect_fails():
    supervisor = DockerSupervisor()
    with patch("subprocess.run", return_value=_completed(returncode=1, stderr="no such container")):
        assert supervisor.is_running("demo") is False


def test_healthcheck_succeeds_immediately_when_running():
    supervisor = DockerSupervisor()
    with patch("subprocess.run", return_value=_completed(stdout="running\n")) as mock_run:
        supervisor.healthcheck("demo", timeout_seconds=5, retries=2)
    assert mock_run.call_count == 1


def test_healthcheck_retries_then_raises():
    supervisor = DockerSupervisor(healthcheck_poll_interval_seconds=0)
    calls = {"n": 0}

    def fake_run(cmd, capture_output=True, text=True, timeout=None):
        calls["n"] += 1
        return _completed(stdout="created\n")

    with patch("subprocess.run", side_effect=fake_run):
        with pytest.raises(HealthcheckError, match="did not become running"):
            supervisor.healthcheck("demo", timeout_seconds=1, retries=2)

    assert calls["n"] == 3
