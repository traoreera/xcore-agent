"""A concrete `Provisioner` (see install_driver.py) plus a loader that reads
a set of them from an operator-side config file.

xcore-agent deliberately never ships a Postgres/Redis/whatever client just
to support `provision` — that would bloat a lean deployment agent with
backend-specific dependencies most projects don't need. Instead,
`ShellCommandProvisioner` runs a command the *operator* configured on the
host. That's safe in a way a similar mechanism inside `install.yaml` would
not be: the command comes from the operator's own trusted, host-side
config — never from the (untrusted) `.xdeploy` artifact, which only ever
supplies a plugin id via `ProvisionStep`. The operator already has root on
their own VPS; this doesn't hand any new capability to the artifact.
"""

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from ..schema.install import ProvisionStep
from .errors import InstallError
from .install_driver import Provisioner


class ProvisionerConfigEntry(BaseModel):
    model_config = {"extra": "forbid"}

    command: list[str] = Field(..., min_length=1)
    env: dict[str, str] = Field(default_factory=dict)
    timeout: int = Field(default=300, gt=0, le=3600)


@dataclass
class ShellCommandProvisioner:
    """Runs `[*command, plugin_id]` to provision one plugin's backing
    service(s) — a database, a message queue, whatever the operator's script
    sets up. The plugin id is also exported as `PROVISION_PLUGIN_ID`."""

    command: list[str]
    env: dict[str, str] | None = None
    timeout_seconds: float = 300.0

    def __call__(self, step: ProvisionStep) -> None:
        full_env = {**os.environ, **(self.env or {}), "PROVISION_PLUGIN_ID": step.plugin}
        try:
            result = subprocess.run(
                [*self.command, step.plugin],
                env=full_env,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise InstallError(
                f"provisioner for plugin {step.plugin!r} timed out after "
                f"{self.timeout_seconds}s: {' '.join(self.command)}"
            ) from exc

        if result.returncode != 0:
            raise InstallError(
                f"provisioner for plugin {step.plugin!r} failed (exit {result.returncode}): "
                f"{result.stderr.strip() or result.stdout.strip()}"
            )


def load_provisioners_from_config(path: Path) -> dict[str, Provisioner]:
    """Parse a YAML file mapping plugin id -> {command, env, timeout} into a
    provisioner registry ready to pass to `DeploymentRunner`/`Watcher`.

    Example:
        demo:
          command: ["/usr/local/bin/provision-demo.sh"]
          env:
            PGHOST: localhost
          timeout: 120
    """
    raw = yaml.safe_load(path.read_text()) or {}
    if not isinstance(raw, dict):
        raise InstallError(f"{path}: expected a mapping of plugin id to provisioner config")

    provisioners: dict[str, Provisioner] = {}
    for plugin_id, entry_raw in raw.items():
        try:
            entry = ProvisionerConfigEntry.model_validate(entry_raw)
        except Exception as exc:
            raise InstallError(
                f"{path}: invalid provisioner config for {plugin_id!r}: {exc}"
            ) from exc
        provisioners[plugin_id] = ShellCommandProvisioner(
            command=entry.command, env=entry.env, timeout_seconds=entry.timeout
        )
    return provisioners
