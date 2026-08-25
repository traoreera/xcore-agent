"""A concrete `Notifier` (see install_driver.py) plus a loader that reads a
set of them from an operator-side config file — mirrors provisioners.py
almost exactly, same trust boundary and for the same reason (see that
module's docstring): the command comes from the operator's own trusted,
host-side config, never from the (untrusted) `.xdeploy` artifact, which
only ever supplies an opaque event label via `NotifyStep`.

Unlike `provision`, a missing or failing notifier never fails the
deployment — see `InstallDriver.notify`: notifying is a side channel, not
part of what makes an install succeed or fail (same reasoning as
`MarketplaceClient.report_deployment` being best-effort).
"""

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from ..schema.install import NotifyStep
from .errors import InstallError
from .install_driver import Notifier


class NotifierConfigEntry(BaseModel):
    model_config = {"extra": "forbid"}

    command: list[str] = Field(..., min_length=1)
    env: dict[str, str] = Field(default_factory=dict)
    timeout: int = Field(default=30, gt=0, le=600)


@dataclass
class ShellCommandNotifier:
    """Runs `[*command, event, message]` to notify on one event — the
    operator's own script decides what "notify" means (a Slack webhook via
    curl, sendmail, xdeployments' own report endpoint, ...). The event and
    message are also exported as NOTIFY_EVENT / NOTIFY_MESSAGE, same
    convention as ShellCommandProvisioner's PROVISION_PLUGIN_ID."""

    command: list[str]
    env: dict[str, str] | None = None
    timeout_seconds: float = 30.0

    def __call__(self, step: NotifyStep) -> None:
        message = step.message or ""
        full_env = {
            **os.environ,
            **(self.env or {}),
            "NOTIFY_EVENT": step.event,
            "NOTIFY_MESSAGE": message,
        }
        try:
            result = subprocess.run(
                [*self.command, step.event, message],
                env=full_env,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise InstallError(
                f"notifier for event {step.event!r} timed out after "
                f"{self.timeout_seconds}s: {' '.join(self.command)}"
            ) from exc

        if result.returncode != 0:
            raise InstallError(
                f"notifier for event {step.event!r} failed (exit {result.returncode}): "
                f"{result.stderr.strip() or result.stdout.strip()}"
            )


def load_notifiers_from_config(path: Path) -> dict[str, Notifier]:
    """Parse a YAML file mapping event -> {command, env, timeout} into a
    notifier registry ready to pass to `DeploymentRunner`/`Watcher`/
    `MarketplaceDeploymentRunner`.

    Example:
        deploy_success:
          command: ["/usr/local/bin/notify-slack.sh"]
          timeout: 15
        healthcheck_failed:
          command: ["/usr/local/bin/notify-slack.sh", "--urgent"]
    """
    raw = yaml.safe_load(path.read_text()) or {}
    if not isinstance(raw, dict):
        raise InstallError(f"{path}: expected a mapping of event to notifier config")

    notifiers: dict[str, Notifier] = {}
    for event, entry_raw in raw.items():
        try:
            entry = NotifierConfigEntry.model_validate(entry_raw)
        except Exception as exc:
            raise InstallError(f"{path}: invalid notifier config for {event!r}: {exc}") from exc
        notifiers[event] = ShellCommandNotifier(
            command=entry.command, env=entry.env, timeout_seconds=entry.timeout
        )
    return notifiers
