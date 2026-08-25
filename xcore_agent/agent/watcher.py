"""Polls XCore Hub for the latest version/tag of a project and redeploys
automatically when it changes — the "CI/CD" loop: Hub publishes a new
release, the agent notices on its own and rolls it out without a human
running `xcore-agent deploy` by hand. Runs garbage collection after every
successful redeploy so snapshots and cached downloads don't grow unbounded.
"""

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

from ..plugin_resolver import PluginResolver
from ..schema.manifest import ProjectManifest
from .gc import GarbageCollector
from .hub_client import DeploymentReport, HubClient
from .install_driver import Layout, Notifier, Provisioner, Supervisor
from .pipeline import DeploymentCredentials, DeploymentRunner
from .state_store import StateStore


@dataclass(frozen=True)
class WatchResult:
    checked_version: str
    deployed: bool
    report: DeploymentReport | None = None


class Watcher:
    def __init__(
        self,
        *,
        hub: HubClient,
        credentials: DeploymentCredentials,
        workdir_root: Path,
        project_root: Path,
        trusted_signer_public_key: bytes,
        keep_snapshots: int = 3,
        supervisor: Supervisor | None = None,
        plugin_resolver: PluginResolver | None = None,
        provisioners: dict[str, Provisioner] | None = None,
        notifiers: dict[str, Notifier] | None = None,
    ) -> None:
        self._hub = hub
        self._credentials = credentials
        self._workdir_root = workdir_root
        self._project_root = project_root
        self._trusted_signer_public_key = trusted_signer_public_key
        self._keep_snapshots = keep_snapshots
        self._supervisor = supervisor
        self._plugin_resolver = plugin_resolver
        self._provisioners = provisioners
        self._notifiers = notifiers
        self._state = StateStore(project_root)

    async def check_once(self) -> WatchResult:
        session = await self._hub.authenticate(
            xdevkey=self._credentials.xdevkey, project_id=self._credentials.project_id
        )
        latest = await self._hub.get_latest_version(
            session, project_id=self._credentials.project_id
        )

        installed = self._state.read()
        if installed is not None and installed.version == latest:
            return WatchResult(checked_version=latest, deployed=False)

        runner = DeploymentRunner(
            hub=self._hub,
            credentials=self._credentials,
            version=latest,
            workdir=self._workdir_root / latest,
            project_root=self._project_root,
            trusted_signer_public_key=self._trusted_signer_public_key,
            plugin_resolver=self._plugin_resolver,
            provisioners=self._provisioners,
            notifiers=self._notifiers,
        )
        report = await runner.run()
        self._state.write(project_id=self._credentials.project_id, version=latest)
        self._collect_garbage(keep_versions=frozenset({latest}), manifest=runner.manifest)
        return WatchResult(checked_version=latest, deployed=True, report=report)

    def _collect_garbage(
        self, *, keep_versions: frozenset[str], manifest: ProjectManifest | None
    ) -> None:
        layout = Layout(
            project_root=self._project_root, extracted_root=self._workdir_root / "extracted"
        )
        gc = GarbageCollector(
            layout,
            keep_snapshots=self._keep_snapshots,
            cache_root=self._workdir_root,
            supervisor=self._supervisor,
        )
        restart_ids = [p.id for p in manifest.plugins] if manifest is not None else []
        gc.collect(keep_versions=keep_versions, restart_plugins=restart_ids)

    async def watch_forever(
        self,
        *,
        interval_seconds: float,
        on_result: Callable[[WatchResult], None] | None = None,
        on_error: Callable[[Exception], None] | None = None,
        stop_after: Callable[[], Awaitable[bool]] | None = None,
    ) -> None:
        """Loop `check_once()` every `interval_seconds`. A failed tick (Hub
        unreachable, a bad redeploy) must not kill the loop — that would
        defeat the point of an unattended CI/CD watcher — so errors go to
        `on_error` instead of propagating. `stop_after` is an injectable
        exit condition for tests; real callers just never pass it."""
        while True:
            try:
                result = await self.check_once()
            except Exception as exc:  # noqa: BLE001 — a bad tick must not stop the loop
                if on_error is not None:
                    on_error(exc)
            else:
                if on_result is not None:
                    on_result(result)

            if stop_after is not None and await stop_after():
                return
            await asyncio.sleep(interval_seconds)
