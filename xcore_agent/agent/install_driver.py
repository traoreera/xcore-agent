"""Executes individual `install.yaml` steps against a target host.

Filesystem operations (installing/configuring plugins, writing env files) are
implemented for real against a local directory layout. Process supervision
(start/stop/restart/healthcheck) is intentionally left as a `Supervisor`
protocol: which init system or orchestrator runs the actual processes
(systemd, Docker, Dockploy, k8s...) is the client's infrastructure choice,
not something xcore-agent should hardcode. `NullSupervisor` is provided for
tests and dry runs.
"""

import os
import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ..schema.install import (
    ConfigurePluginStep,
    HealthcheckStep,
    InstallExtensionStep,
    InstallPluginStep,
    ProvisionStep,
    RestartStep,
    StartStep,
    StopStep,
    WriteEnvStep,
)
from ..schema.manifest import ProjectManifest
from .errors import HealthcheckError, InstallError
from .plugin_signing import sign_installed_plugin

# A provisioner performs a `provision` step's work (e.g. creating a database,
# a message queue, ...) for one plugin. Registered by the caller — see
# InstallDriver's `provisioners` argument — because what "provisioning
# xcore.database" means is entirely infra-specific.
Provisioner = Callable[[ProvisionStep], None]


@dataclass
class Layout:
    """On-disk layout for one deployed project.

    Mirrors xcore's own convention of keeping secrets host-side, never inside
    the artifact: `<project_root>/plugins/<plugin>.env`.
    """

    project_root: Path
    extracted_root: Path
    # Which directory plugins live under, both inside the extracted artifact
    # and on the target host — "plugins" unless the source project's own
    # integration.yaml overrides it (e.g. "app" — see
    # packer.builder._read_plugins_dirname). Defaults to "plugins" so every
    # caller that never sets it (tests, `gc`, a manifest-less marketplace
    # deploy) is unaffected; DeploymentRunner sets it from
    # `manifest.plugins_dirname` once the manifest is parsed and verified —
    # see pipeline.py's `_verify_manifest`.
    plugins_dirname: str = "plugins"

    @property
    def plugins_dir(self) -> Path:
        return self.project_root / self.plugins_dirname

    @property
    def snapshots_dir(self) -> Path:
        return self.project_root / ".snapshots"

    def plugin_dir(self, plugin_id: str) -> Path:
        return self.plugins_dir / plugin_id

    def plugin_env_file(self, plugin_id: str) -> Path:
        return self.plugins_dir / f"{plugin_id}.env"

    @property
    def extensions_dir(self) -> Path:
        return self.project_root / "extensions"

    def extension_dir(self, extension_id: str) -> Path:
        return self.extensions_dir / extension_id


class Supervisor(Protocol):
    def start(self, plugin_id: str | None) -> None: ...
    def stop(self, plugin_id: str | None) -> None: ...
    def restart(self, plugin_id: str | None) -> None: ...
    def healthcheck(self, plugin_id: str | None, *, timeout_seconds: int, retries: int) -> None: ...


class NullSupervisor:
    """No-op supervisor for dry runs and tests."""

    def start(self, plugin_id: str | None) -> None:
        return None

    def stop(self, plugin_id: str | None) -> None:
        return None

    def restart(self, plugin_id: str | None) -> None:
        return None

    def healthcheck(self, plugin_id: str | None, *, timeout_seconds: int, retries: int) -> None:
        return None


@dataclass
class SnapshotRecord:
    step_id: str
    plugin_id: str
    # None means the plugin directory did not exist before this step ran —
    # i.e. this was a fresh install, so "rolling back" means deleting it,
    # not restoring a prior copy.
    saved_path: Path | None
    # "plugin" (default, matches every snapshot taken before extensions
    # existed) or "extension" — picks plugin_dir() vs extension_dir() when
    # rolling back, see rollback() below.
    kind: str = "plugin"


class InstallDriver:
    """Executes filesystem-touching install.yaml steps for real, with
    snapshot/rollback support for any step marked `snapshot: true`."""

    def __init__(
        self,
        layout: Layout,
        supervisor: Supervisor | None = None,
        *,
        provisioners: dict[str, Provisioner] | None = None,
        manifest: ProjectManifest | None = None,
        plugin_secret_key: bytes | None = None,
    ) -> None:
        self.layout = layout
        self._supervisor = supervisor or NullSupervisor()
        self._provisioners = provisioners or {}
        # Set by DeploymentRunner once manifest.json has been parsed and
        # verified — used to validate required environment variables in
        # write_env(). None in tests/callers that don't need that check.
        self.manifest = manifest
        # The target host's own `plugins.secret_key` (integration.yaml) —
        # host-local, never embedded in the artifact, passed in the same
        # spirit as `.env` values. None (default) skips plugin.sig signing
        # entirely: a caller with no strict_trusted host to satisfy pays
        # nothing for this. See plugin_signing.py for what this enables.
        self._plugin_secret_key = plugin_secret_key
        self._snapshots: list[SnapshotRecord] = []

    def snapshot_before(self, step_id: str, plugin_id: str, *, kind: str = "plugin") -> None:
        target = self.layout.plugin_dir(plugin_id) if kind == "plugin" else self.layout.extension_dir(plugin_id)
        if not target.exists():
            self._snapshots.append(
                SnapshotRecord(step_id=step_id, plugin_id=plugin_id, saved_path=None, kind=kind)
            )
            return
        self.layout.snapshots_dir.mkdir(parents=True, exist_ok=True)
        saved = self.layout.snapshots_dir / f"{step_id}-{plugin_id}-{int(time.time() * 1000)}"
        shutil.copytree(target, saved)
        self._snapshots.append(
            SnapshotRecord(step_id=step_id, plugin_id=plugin_id, saved_path=saved, kind=kind)
        )

    def rollback(self, *, to_step_id: str | None = None) -> None:
        """Restore snapshots in reverse order, optionally stopping once
        `to_step_id` is reached (exclusive) instead of rolling back everything.
        A step that had no prior state (fresh install) is undone by deleting
        what it created, not by restoring a copy that never existed."""
        for record in reversed(self._snapshots):
            if to_step_id is not None and record.step_id == to_step_id:
                break
            target = (
                self.layout.plugin_dir(record.plugin_id)
                if record.kind == "plugin"
                else self.layout.extension_dir(record.plugin_id)
            )
            if target.exists():
                shutil.rmtree(target)
            if record.saved_path is not None and record.saved_path.exists():
                shutil.copytree(record.saved_path, target)

    def provision(self, step: ProvisionStep) -> None:
        provisioner = self._provisioners.get(step.plugin)
        if provisioner is None:
            raise InstallError(
                f"no provisioner registered for plugin {step.plugin!r} — pass one via "
                f"InstallDriver(provisioners={{{step.plugin!r}: ...}}); provisioning a "
                "backing service is infra-specific, so there is no generic default"
            )
        provisioner(step)

    def install_plugin(self, step: InstallPluginStep) -> None:
        source = self.layout.extracted_root / self.layout.plugins_dirname / step.plugin
        if not source.is_dir():
            raise InstallError(f"plugin {step.plugin!r} not found in extracted artifact")
        target = self.layout.plugin_dir(step.plugin)
        if step.snapshot:
            self.snapshot_before(step.id, step.plugin)
        if target.exists():
            shutil.rmtree(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, target)

        # A no-op unless `target/plugin.yaml` declares `execution_mode:
        # trusted` AND a plugin_secret_key was configured — a project with
        # no trusted plugins, or a deployment onto a host that doesn't run
        # strict_trusted, pays nothing for this. See plugin_signing.py.
        if self._plugin_secret_key is not None:
            sign_installed_plugin(target, self._plugin_secret_key)

    def install_extension(self, step: InstallExtensionStep) -> None:
        source = self.layout.extracted_root / "extensions" / step.extension
        if not source.is_dir():
            raise InstallError(f"extension {step.extension!r} not found in extracted artifact")
        target = self.layout.extension_dir(step.extension)
        if step.snapshot:
            self.snapshot_before(step.id, step.extension, kind="extension")
        if target.exists():
            shutil.rmtree(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, target)

    def configure_plugin(self, step: ConfigurePluginStep) -> None:
        # Actual plugin configuration is applied by xcore's own runtime
        # (kernel.runtime.loader) once the host loads the plugin — this step
        # only needs to exist so install.yaml can express ordering/dependencies.
        return None

    def write_env(self, step: WriteEnvStep) -> None:
        target = self.layout.plugin_env_file(step.plugin)
        if not target.exists():
            # Never overwrite secrets already configured on the host — only
            # seed the file if it's missing. Seeding prefers a matching
            # value already exported in this process's own OS environment
            # (the operator's shell, a systemd unit's Environment=, ...)
            # over the template's own placeholder — still host-local, never
            # embedded in the artifact, just read from a place xcore-agent
            # already has access to instead of requiring a manual SSH edit
            # afterwards. A key absent from the OS environment falls back
            # to whatever the template already has (usually empty).
            template = self.layout.extracted_root / step.from_
            if not template.is_file():
                raise InstallError(f"env template {step.from_!r} not found in artifact")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(_seed_env_from_os_environ(template.read_text(), os.environ))
            target.chmod(0o600)

        self._check_required_env(step.plugin, target)

    def _check_required_env(self, plugin_id: str, env_file: Path) -> None:
        if self.manifest is None:
            return
        try:
            plugin = self.manifest.plugin(plugin_id)
        except KeyError:
            return
        if plugin.environment is None or not plugin.environment.required:
            return

        values = _parse_env_file(env_file)
        missing = [key for key in plugin.environment.required if not values.get(key)]
        if missing:
            raise InstallError(
                f"plugin {plugin_id!r} is missing required environment variable(s) "
                f"{', '.join(missing)} in {env_file} — set them on the host before deploying"
            )

    def start(self, step: StartStep) -> None:
        self._supervisor.start(step.plugin)

    def stop(self, step: StopStep) -> None:
        self._supervisor.stop(step.plugin)

    def restart(self, step: RestartStep) -> None:
        self._supervisor.restart(step.plugin)

    def healthcheck(self, step: HealthcheckStep) -> None:
        try:
            self._supervisor.healthcheck(
                step.plugin, timeout_seconds=step.timeout_seconds, retries=step.retries
            )
        except Exception as exc:
            raise HealthcheckError(str(exc)) from exc


def _parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values


def _seed_env_from_os_environ(template_text: str, os_env: "os._Environ[str]") -> str:
    """Return `template_text` with each `KEY=...` line's value replaced by
    `os_env[KEY]` when that key is present there — comments, blank lines,
    and keys absent from `os_env` (which keep the template's own
    placeholder, usually empty) pass through unchanged. Preserves the
    template's own formatting/ordering/comments rather than rewriting the
    file from a flat key set, so an operator's own `.env.template`
    annotations survive into the seeded file."""
    lines = []
    for line in template_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            lines.append(line)
            continue
        key, _, _value = line.partition("=")
        key = key.strip()
        if key in os_env:
            lines.append(f"{key}={os_env[key]}")
        else:
            lines.append(line)
    text = "\n".join(lines)
    if template_text.endswith("\n") and not text.endswith("\n"):
        text += "\n"
    return text
