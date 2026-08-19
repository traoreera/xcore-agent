"""A `Supervisor` (see install_driver.py) backed by `systemctl` — the
concrete default for a project deployed directly on a VPS, as opposed to
inside Docker/k8s where the client's own orchestrator plays this role (see
README's "what's real vs. stubbed" table).

Expects one systemd unit per plugin, named `<unit_prefix><plugin_id>.service`
(default prefix `xcore-plugin-`), plus one `project_unit` used for steps that
don't name a specific plugin (a project-wide `start`/`stop`/`restart`).
Provisioning those units (writing the .service files, `daemon-reload`) is a
deployment/ops concern outside this class's scope — it only ever calls
`start` / `stop` / `restart` / `is-active` on units that already exist.
"""

import subprocess
import time
from dataclasses import dataclass

from .errors import HealthcheckError


class SystemdCommandError(Exception):
    """Raised when a `systemctl` invocation itself fails (bad unit, permission,
    systemd not running, ...) — distinct from a healthcheck simply reporting
    the unit as not active."""


@dataclass
class SystemdSupervisor:
    unit_prefix: str = "xcore-plugin-"
    project_unit: str = "xcore-project.service"
    user_scope: bool = True
    healthcheck_poll_interval_seconds: float = 1.0

    def _unit(self, plugin_id: str | None) -> str:
        return f"{self.unit_prefix}{plugin_id}.service" if plugin_id else self.project_unit

    def _run(self, *args: str, timeout: float | None = None) -> subprocess.CompletedProcess:
        cmd = ["systemctl", *(["--user"] if self.user_scope else []), *args]
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise SystemdCommandError(f"{' '.join(cmd)} timed out after {timeout}s") from exc
        except FileNotFoundError as exc:
            raise SystemdCommandError("systemctl not found on this host") from exc

    def _run_checked(self, *args: str) -> None:
        result = self._run(*args)
        if result.returncode != 0:
            raise SystemdCommandError(
                f"systemctl {' '.join(args)} failed (exit {result.returncode}): "
                f"{result.stderr.strip() or result.stdout.strip()}"
            )

    def start(self, plugin_id: str | None) -> None:
        self._run_checked("start", self._unit(plugin_id))

    def stop(self, plugin_id: str | None) -> None:
        self._run_checked("stop", self._unit(plugin_id))

    def restart(self, plugin_id: str | None) -> None:
        self._run_checked("restart", self._unit(plugin_id))

    def is_active(self, plugin_id: str | None) -> bool:
        result = self._run("is-active", self._unit(plugin_id))
        return result.stdout.strip() == "active"

    def healthcheck(self, plugin_id: str | None, *, timeout_seconds: int, retries: int) -> None:
        unit = self._unit(plugin_id)
        last_status = "unknown"
        for attempt in range(retries + 1):
            result = self._run("is-active", unit, timeout=timeout_seconds)
            last_status = result.stdout.strip() or "unknown"
            if last_status == "active":
                return
            if attempt < retries:
                time.sleep(self.healthcheck_poll_interval_seconds)
        raise HealthcheckError(
            f"{unit} did not become active after {retries + 1} attempt(s) "
            f"(last status: {last_status!r})"
        )
