"""A `Supervisor` (see install_driver.py) backed by the `kubectl` CLI — an
alternative to `SystemdSupervisor`/`DockerSupervisor` for projects deployed
onto a Kubernetes cluster. Same shell-out-to-CLI shape as `DockerSupervisor`
(no `kubernetes` Python client dependency), because the agent otherwise has
no way to assume kubeconfig/cluster access is even present.

Expects one Deployment per plugin, named `<deployment_prefix><plugin_id>`
(default prefix `xcore-plugin-`) in `namespace`, plus one
`project_deployment` for steps that don't name a specific plugin. Creating
those Deployments (image, env, resources, ...) is a deployment/ops concern
outside this class's scope — it only ever scales, restarts, and checks the
rollout status of Deployments that already exist.

Kubernetes has no direct "start/stop a container" verb the way `docker
start`/`docker stop` do; the equivalent for a Deployment is scaling replicas
to 1 or 0, and "restart" is `kubectl rollout restart`, whose completion is
observed via `kubectl rollout status` — which doubles as the healthcheck.
"""

import subprocess
import time
from dataclasses import dataclass

from .errors import HealthcheckError


class KubectlCommandError(Exception):
    """Raised when a `kubectl` invocation itself fails (unknown deployment,
    cluster unreachable, permission denied, ...) — distinct from a
    healthcheck simply reporting the rollout as not yet complete."""


@dataclass
class KubernetesSupervisor:
    namespace: str = "default"
    deployment_prefix: str = "xcore-plugin-"
    project_deployment: str = "xcore-project"
    kubeconfig: str | None = None
    context: str | None = None
    healthcheck_poll_interval_seconds: float = 1.0

    def _deployment(self, plugin_id: str | None) -> str:
        return f"{self.deployment_prefix}{plugin_id}" if plugin_id else self.project_deployment

    def _base_args(self) -> list[str]:
        args = ["--namespace", self.namespace]
        if self.kubeconfig:
            args += ["--kubeconfig", self.kubeconfig]
        if self.context:
            args += ["--context", self.context]
        return args

    def _run(self, *args: str, timeout: float | None = None) -> subprocess.CompletedProcess:
        cmd = ["kubectl", *self._base_args(), *args]
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise KubectlCommandError(f"{' '.join(cmd)} timed out after {timeout}s") from exc
        except FileNotFoundError as exc:
            raise KubectlCommandError("kubectl not found on this host") from exc

    def _run_checked(self, *args: str) -> None:
        result = self._run(*args)
        if result.returncode != 0:
            raise KubectlCommandError(
                f"kubectl {' '.join(args)} failed (exit {result.returncode}): "
                f"{result.stderr.strip() or result.stdout.strip()}"
            )

    def start(self, plugin_id: str | None) -> None:
        self._run_checked("scale", f"deployment/{self._deployment(plugin_id)}", "--replicas=1")

    def stop(self, plugin_id: str | None) -> None:
        self._run_checked("scale", f"deployment/{self._deployment(plugin_id)}", "--replicas=0")

    def restart(self, plugin_id: str | None) -> None:
        self._run_checked("rollout", "restart", f"deployment/{self._deployment(plugin_id)}")

    def is_running(self, plugin_id: str | None) -> bool:
        result = self._run(
            "get",
            f"deployment/{self._deployment(plugin_id)}",
            "-o",
            "jsonpath={.status.readyReplicas}",
        )
        if result.returncode != 0:
            return False
        ready = result.stdout.strip()
        return ready.isdigit() and int(ready) > 0

    def healthcheck(self, plugin_id: str | None, *, timeout_seconds: int, retries: int) -> None:
        deployment = self._deployment(plugin_id)
        last_error = ""
        for attempt in range(retries + 1):
            result = self._run(
                "rollout",
                "status",
                f"deployment/{deployment}",
                f"--timeout={timeout_seconds}s",
                timeout=timeout_seconds + 5,
            )
            if result.returncode == 0:
                return
            last_error = result.stderr.strip() or result.stdout.strip() or "unknown error"
            if attempt < retries:
                time.sleep(self.healthcheck_poll_interval_seconds)
        raise HealthcheckError(
            f"deployment {deployment!r} did not become ready after {retries + 1} "
            f"attempt(s) (last error: {last_error!r})"
        )
