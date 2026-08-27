"""CI/CD watch loop for the *real* xcore-team/marketplace flow — the
counterpart to `agent.watcher.Watcher` for `MarketplaceClient` /
`MarketplaceDeploymentRunner` instead of the invented `HubClient` contract.

Polls `GET /{plugins|services}/{slug}` for `latest_version` and redeploys
through `MarketplaceDeploymentRunner` whenever it changes from what
`StateStore` says is currently installed — same version-change-detection
and GC-after-redeploy shape as `Watcher`, just against the Marketplace's
one-slug-per-deployment model instead of a multi-plugin project bundle (see
`marketplace_client.py`'s module docstring for why that's a separate client
and pipeline in the first place).
"""

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

from .gc import GarbageCollector
from .install_driver import Layout, Notifier, Provisioner, Supervisor
from .marketplace_client import Kind, MarketplaceClient
from .marketplace_pipeline import MarketplaceDeploymentReport, MarketplaceDeploymentRunner
from .state_store import StateStore


@dataclass(frozen=True)
class MarketplaceWatchResult:
    checked_version: str
    deployed: bool
    report: MarketplaceDeploymentReport | None = None


class MarketplaceWatcher:
    def __init__(
        self,
        *,
        client: MarketplaceClient,
        slug: str,
        trusted_signer_secret: bytes,
        install_plan_path: Path,
        workdir_root: Path,
        project_root: Path,
        kind: Kind = "plugin",
        host_id: str = "default",
        keep_snapshots: int = 3,
        supervisor: Supervisor | None = None,
        provisioners: dict[str, Provisioner] | None = None,
        notifiers: dict[str, Notifier] | None = None,
    ) -> None:
        self._client = client
        self._slug = slug
        self._trusted_signer_secret = trusted_signer_secret
        self._install_plan_path = install_plan_path
        self._workdir_root = workdir_root
        self._project_root = project_root
        self._kind = kind
        self._host_id = host_id
        self._keep_snapshots = keep_snapshots
        self._supervisor = supervisor
        self._provisioners = provisioners
        self._notifiers = notifiers
        # namespace=slug: see StateStore's own docstring — several
        # MarketplaceWatchers (one per slug) can share a project_root
        # without clobbering each other's recorded version.
        self._state = StateStore(project_root, namespace=slug)

    async def check_once(self) -> MarketplaceWatchResult:
        latest = await self._client.get_latest_version(slug=self._slug, kind=self._kind)

        installed = self._state.read()
        if installed is not None and installed.version == latest:
            return MarketplaceWatchResult(checked_version=latest, deployed=False)

        runner = MarketplaceDeploymentRunner(
            client=self._client,
            slug=self._slug,
            workdir=self._workdir_root / latest,
            project_root=self._project_root,
            trusted_signer_secret=self._trusted_signer_secret,
            install_plan_path=self._install_plan_path,
            version=latest,
            kind=self._kind,
            host_id=self._host_id,
            provisioners=self._provisioners,
            notifiers=self._notifiers,
        )
        report = await runner.run()
        self._state.write(project_id=self._slug, version=latest)
        self._collect_garbage(keep_versions=frozenset({latest}))
        return MarketplaceWatchResult(checked_version=latest, deployed=True, report=report)

    def _collect_garbage(self, *, keep_versions: frozenset[str]) -> None:
        layout = Layout(
            project_root=self._project_root, extracted_root=self._workdir_root / "extracted"
        )
        gc = GarbageCollector(
            layout,
            keep_snapshots=self._keep_snapshots,
            cache_root=self._workdir_root,
            supervisor=self._supervisor,
        )
        # One slug per deployment in this flow (unlike Watcher's multi-plugin
        # manifest) — restart just that plugin, and only for kind="plugin"
        # (services don't go through the Supervisor restart path).
        restart_ids = [self._slug] if self._kind == "plugin" else []
        gc.collect(keep_versions=keep_versions, restart_plugins=restart_ids)

    async def watch_forever(
        self,
        *,
        interval_seconds: float,
        on_result: Callable[[MarketplaceWatchResult], None] | None = None,
        on_error: Callable[[Exception], None] | None = None,
        stop_after: Callable[[], Awaitable[bool]] | None = None,
    ) -> None:
        """Loop `check_once()` every `interval_seconds`. A failed tick (Hub
        unreachable, a bad redeploy) must not kill the loop — errors go to
        `on_error` instead of propagating. `stop_after` is an injectable exit
        condition for tests; real callers just never pass it."""
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
