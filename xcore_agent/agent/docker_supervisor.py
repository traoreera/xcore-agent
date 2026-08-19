"""A `Supervisor` (see install_driver.py) backed by the `docker` CLI — an
alternative to `SystemdSupervisor` for projects deployed as containers
instead of directly on the host.

Expects one container per plugin, named `<container_prefix><plugin_id>`
(default prefix `xcore-plugin-`), plus one `project_container` used for
steps that don't name a specific plugin. Creating/updating those containers
(image, env, volumes, `docker run` vs `docker compose`, ...) is a
deployment/ops concern outside this class's scope — it only ever calls
`start` / `stop` / `restart` / `inspect` on containers that already exist.
"""

import subprocess
import time
from dataclasses import dataclass

from .errors import HealthcheckError


class DockerCommandError(Exception):
    """Raised when a `docker` invocation itself fails (unknown container,
    daemon not running, permission denied, ...) — distinct from a
    healthcheck simply reporting the container as not running."""


@dataclass
class DockerSupervisor:
    container_prefix: str = "xcore-plugin-"
    project_container: str = "xcore-project"
    healthcheck_poll_interval_seconds: float = 1.0

    def _container(self, plugin_id: str | None) -> str:
        return f"{self.container_prefix}{plugin_id}" if plugin_id else self.project_container

    def _run(self, *args: str, timeout: float | None = None) -> subprocess.CompletedProcess:
        cmd = ["docker", *args]
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise DockerCommandError(f"{' '.join(cmd)} timed out after {timeout}s") from exc
        except FileNotFoundError as exc:
            raise DockerCommandError("docker not found on this host") from exc

    def _run_checked(self, *args: str) -> None:
        result = self._run(*args)
        if result.returncode != 0:
            raise DockerCommandError(
                f"docker {' '.join(args)} failed (exit {result.returncode}): "
                f"{result.stderr.strip() or result.stdout.strip()}"
            )

    def start(self, plugin_id: str | None) -> None:
        self._run_checked("start", self._container(plugin_id))

    def stop(self, plugin_id: str | None) -> None:
        self._run_checked("stop", self._container(plugin_id))

    def restart(self, plugin_id: str | None) -> None:
        self._run_checked("restart", self._container(plugin_id))

    def is_running(self, plugin_id: str | None) -> bool:
        result = self._run("inspect", "--format", "{{.State.Running}}", self._container(plugin_id))
        return result.returncode == 0 and result.stdout.strip() == "true"

    def healthcheck(self, plugin_id: str | None, *, timeout_seconds: int, retries: int) -> None:
        container = self._container(plugin_id)
        last_status = "unknown"
        for attempt in range(retries + 1):
            result = self._run(
                "inspect", "--format", "{{.State.Status}}", container, timeout=timeout_seconds
            )
            last_status = result.stdout.strip() or "unknown"
            if result.returncode == 0 and last_status == "running":
                return
            if attempt < retries:
                time.sleep(self.healthcheck_poll_interval_seconds)
        raise HealthcheckError(
            f"container {container!r} did not become running after {retries + 1} "
            f"attempt(s) (last status: {last_status!r})"
        )
