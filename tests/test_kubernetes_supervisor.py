import subprocess
from unittest.mock import patch

import pytest

from xcore_agent.agent.errors import HealthcheckError
from xcore_agent.agent.kubernetes_supervisor import KubectlCommandError, KubernetesSupervisor


def _completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def test_start_scales_the_prefixed_deployment_to_one_replica():
    supervisor = KubernetesSupervisor()
    with patch("subprocess.run", return_value=_completed()) as mock_run:
        supervisor.start("demo")
    cmd = mock_run.call_args[0][0]
    assert cmd == [
        "kubectl",
        "--namespace",
        "default",
        "scale",
        "deployment/xcore-plugin-demo",
        "--replicas=1",
    ]


def test_stop_scales_to_zero_replicas():
    supervisor = KubernetesSupervisor()
    with patch("subprocess.run", return_value=_completed()) as mock_run:
        supervisor.stop("demo")
    assert mock_run.call_args[0][0][-2:] == ["deployment/xcore-plugin-demo", "--replicas=0"]


def test_restart_uses_rollout_restart():
    supervisor = KubernetesSupervisor()
    with patch("subprocess.run", return_value=_completed()) as mock_run:
        supervisor.restart("demo")
    cmd = mock_run.call_args[0][0]
    assert cmd[-3:] == ["rollout", "restart", "deployment/xcore-plugin-demo"]


def test_no_plugin_id_targets_the_project_deployment():
    supervisor = KubernetesSupervisor()
    with patch("subprocess.run", return_value=_completed()) as mock_run:
        supervisor.stop(None)
    assert mock_run.call_args[0][0][-2] == "deployment/xcore-project"


def test_custom_deployment_prefix_is_used():
    supervisor = KubernetesSupervisor(deployment_prefix="myproj-")
    with patch("subprocess.run", return_value=_completed()) as mock_run:
        supervisor.restart("demo")
    assert mock_run.call_args[0][0][-1] == "deployment/myproj-demo"


def test_custom_namespace_is_passed():
    supervisor = KubernetesSupervisor(namespace="prod")
    with patch("subprocess.run", return_value=_completed()) as mock_run:
        supervisor.start("demo")
    assert mock_run.call_args[0][0][:3] == ["kubectl", "--namespace", "prod"]


def test_kubeconfig_and_context_are_passed_when_set():
    supervisor = KubernetesSupervisor(kubeconfig="/tmp/kc.yaml", context="my-ctx")
    with patch("subprocess.run", return_value=_completed()) as mock_run:
        supervisor.start("demo")
    cmd = mock_run.call_args[0][0]
    assert "--kubeconfig" in cmd and cmd[cmd.index("--kubeconfig") + 1] == "/tmp/kc.yaml"
    assert "--context" in cmd and cmd[cmd.index("--context") + 1] == "my-ctx"


def test_failed_kubectl_call_raises_with_stderr():
    supervisor = KubernetesSupervisor()
    with patch("subprocess.run", return_value=_completed(returncode=1, stderr="not found")):
        with pytest.raises(KubectlCommandError, match="not found"):
            supervisor.start("demo")


def test_missing_kubectl_binary_raises_command_error():
    supervisor = KubernetesSupervisor()
    with patch("subprocess.run", side_effect=FileNotFoundError()):
        with pytest.raises(KubectlCommandError, match="not found"):
            supervisor.start("demo")


def test_is_running_true_when_ready_replicas_positive():
    supervisor = KubernetesSupervisor()
    with patch("subprocess.run", return_value=_completed(stdout="2")):
        assert supervisor.is_running("demo") is True


def test_is_running_false_when_ready_replicas_zero():
    supervisor = KubernetesSupervisor()
    with patch("subprocess.run", return_value=_completed(stdout="0")):
        assert supervisor.is_running("demo") is False


def test_is_running_false_when_get_fails():
    supervisor = KubernetesSupervisor()
    with patch("subprocess.run", return_value=_completed(returncode=1, stderr="not found")):
        assert supervisor.is_running("demo") is False


def test_is_running_false_when_field_is_empty():
    # readyReplicas is omitted from the status entirely when it's zero.
    supervisor = KubernetesSupervisor()
    with patch("subprocess.run", return_value=_completed(stdout="")):
        assert supervisor.is_running("demo") is False


def test_healthcheck_succeeds_immediately_on_successful_rollout():
    supervisor = KubernetesSupervisor()
    with patch("subprocess.run", return_value=_completed()) as mock_run:
        supervisor.healthcheck("demo", timeout_seconds=5, retries=2)
    assert mock_run.call_count == 1
    cmd = mock_run.call_args[0][0]
    assert cmd[-4:] == ["rollout", "status", "deployment/xcore-plugin-demo", "--timeout=5s"]


def test_healthcheck_retries_then_raises():
    supervisor = KubernetesSupervisor(healthcheck_poll_interval_seconds=0)
    calls = {"n": 0}

    def fake_run(cmd, capture_output=True, text=True, timeout=None):
        calls["n"] += 1
        return _completed(returncode=1, stderr="waiting for rollout")

    with patch("subprocess.run", side_effect=fake_run):
        with pytest.raises(HealthcheckError, match="did not become ready"):
            supervisor.healthcheck("demo", timeout_seconds=1, retries=2)

    assert calls["n"] == 3
