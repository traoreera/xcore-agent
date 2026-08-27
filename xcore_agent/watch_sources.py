"""Watches ALL marketplace `source:` entries in a project's own
`install.yaml` and re-resolves whichever ones have a newer published
version — the multi-source counterpart to `agent.marketplace_watcher.
MarketplaceWatcher`.

`MarketplaceWatcher` polls exactly ONE slug and, on a new version, replays
the *entire* install plan through `MarketplaceDeploymentRunner` (see that
module's docstring: "one deployment fetches one plugin or one service").
That's the right shape for a target project that IS one plugin — it breaks
for a composite project whose `install.yaml` declares many independent
marketplace sources for ONE shared deployment (e.g. xcore-team/marketplace
itself, which depends on ~14 marketplace-resolved plugins/extensions):
`_install()` would replay every step, including the 13 whose artifact was
never fetched this tick.

This module never touches `install.yaml`'s own steps (no InstallDriver, no
start/healthcheck) — it only keeps each source's resolved tree in sync with
the marketplace's latest published version, the same merge semantics as
`resolve_sources.resolve_all_sources` (`copytree` onto whatever's already
there — a plugin's own `.env.template`, absent from the resolved repo,
survives), just polling forever instead of once. What (if anything) should
happen to the running process after an update is applied is the caller's
decision (`exit_on_update` below) — this module only ever writes files.
"""

import asyncio
import json
import logging
import shutil
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

import yaml

from .packer.builder import _read_plugins_dirname
from .plugin_resolver import PluginResolver
from .schema.install import InstallExtensionStep, InstallPlan, InstallPluginStep

logger = logging.getLogger(__name__)

_INSTALL_PLAN_PATH = "deployment/install.yaml"
_STATE_PATH = ".xcore/watch-sources-state.json"


class WatchSourcesError(Exception):
    """A setup problem (install.yaml missing/invalid) — never raised for a
    single tick's transient failure, which `check_once` logs and skips."""


@dataclass(frozen=True)
class SourceUpdate:
    id: str  # install.yaml step id, e.g. "install_auth"
    kind: str  # "plugin" | "extension"
    slug: str  # marketplace slug, e.g. "xauth"
    from_version: str | None
    to_version: str


def _read_state(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _write_state(path: Path, state: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True))


async def check_once(
    project_root: Path,
    *,
    plugin_resolver: PluginResolver,
    install_plan_path: Path | None = None,
) -> list[SourceUpdate]:
    """Check every marketplace source in `install.yaml` once; resolve and
    apply any whose published version differs from what's recorded (in
    `<project_root>/.xcore/watch-sources-state.json`) as currently applied.
    On first check for a given source (nothing recorded yet on this host),
    seeded from install.yaml's own build-time pin rather than blindly
    treating it as "unset, therefore an update": resolve-sources already
    fetched exactly that pinned version into this directory at build time,
    so a fresh deploy whose pin already matches the marketplace's current
    latest correctly reports no change instead of "updating" to the exact
    version that's already there (which, combined with `watch_forever`'s
    `exit_on_update`, would otherwise self-restart the process once on
    every single fresh boot for no reason). Only a source pinned to
    "latest" (no fixed version to seed from) is left as a genuine
    first-tick update when unrecorded. Returns what was actually updated —
    an empty list is a normal, common outcome, not an error. A single
    source's failure (marketplace unreachable, bad signature) is logged
    and skipped, never aborts the others' checks."""
    plan_path = install_plan_path or project_root / _INSTALL_PLAN_PATH
    if not plan_path.is_file():
        raise WatchSourcesError(f"{plan_path} not found")
    try:
        plan = InstallPlan.model_validate(yaml.safe_load(plan_path.read_text()))
    except Exception as exc:
        raise WatchSourcesError(f"{plan_path}: invalid install plan: {exc}") from exc

    client = plugin_resolver.marketplace_client
    if client is None:
        raise WatchSourcesError("plugin_resolver has no marketplace_client configured")

    state_path = project_root / _STATE_PATH
    state = _read_state(state_path)
    plugins_dirname = _read_plugins_dirname(project_root)
    updates: list[SourceUpdate] = []
    state_dirty = False

    for step in plan.steps:
        if isinstance(step, InstallPluginStep) and step.source is not None:
            kind, target_id, resolver_id = "plugin", step.plugin, step.plugin
            target = project_root / plugins_dirname / target_id
        elif isinstance(step, InstallExtensionStep) and step.source is not None:
            kind, target_id = "extension", step.extension
            # Namespaced in the resolver's own cache, same reasoning as
            # resolve_sources.resolve_all_sources: a plugin and an
            # extension sharing an id must not collide there.
            resolver_id = f"ext-{target_id}"
            target = project_root / "extensions" / target_id
        else:
            continue
        source = step.source
        assert source is not None and source.marketplace_slug is not None

        slug = source.marketplace_slug
        try:
            latest = await client.get_latest_version(slug=slug, kind=source.marketplace_kind)
        except Exception as exc:  # noqa: BLE001 — one bad slug must not stop the others
            logger.warning("watch-sources: %s (%s) version check failed: %s", slug, step.id, exc)
            continue

        current = state.get(step.id)
        if current is None:
            # Never checked before on this host — seed from install.yaml's
            # OWN pin rather than treating this as "unset, therefore an
            # update": resolve-sources (build time) already fetched
            # exactly source.marketplace_version into this directory, so a
            # fresh deploy whose pin already matches the marketplace's
            # current latest has nothing to do. Without this, EVERY first
            # boot re-"discovers" all sources as new and (with
            # exit_on_update) immediately self-restarts once for no
            # reason — real "latest" isn't a valid pin to seed from, so
            # that case is left as a genuine first-tick update.
            current = source.marketplace_version if source.marketplace_version != "latest" else None
        if current == latest:
            if state.get(step.id) != latest:
                state[step.id] = latest
                state_dirty = True
            continue

        try:
            # Pinned to the exact version just discovered, not whatever
            # install.yaml's own marketplace_version says — that field is
            # the build-time pin, left untouched; this is the live one.
            pinned_source = source.model_copy(update={"marketplace_version": latest})
            source_tree = await plugin_resolver.resolve(resolver_id, pinned_source)
        except Exception as exc:  # noqa: BLE001 — ditto
            logger.warning(
                "watch-sources: %s (%s) fetch/verify of v%s failed: %s",
                slug,
                step.id,
                latest,
                exc,
            )
            continue

        target.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source_tree, target, dirs_exist_ok=True)
        updates.append(
            SourceUpdate(id=step.id, kind=kind, slug=slug, from_version=current, to_version=latest)
        )
        state[step.id] = latest
        state_dirty = True

    if state_dirty:
        _write_state(state_path, state)
    return updates


async def watch_forever(
    project_root: Path,
    *,
    plugin_resolver: PluginResolver,
    install_plan_path: Path | None = None,
    interval_seconds: float = 300,
    exit_on_update: bool = False,
    on_updates: Callable[[list[SourceUpdate]], None] | None = None,
    on_error: Callable[[Exception], None] | None = None,
    stop_after: Callable[[], Awaitable[bool]] | None = None,
) -> None:
    """Loop `check_once()` every `interval_seconds`. A failed tick (a bad
    install.yaml, e.g.) never stops the loop — logged via `on_error`
    instead; per-source failures are already handled inside `check_once`
    itself. `exit_on_update=True` returns right after a tick that applied
    at least one update instead of continuing to poll — for a caller whose
    only way to make a running process pick up newly-written files is a
    full restart (e.g. xcore-team/marketplace's docker-watch.sh, which
    relies on docker-start.sh's `wait -n` to restart the whole container
    when this process exits). `stop_after` is an injectable exit condition
    for tests; real callers never pass it."""
    while True:
        try:
            updates = await check_once(
                project_root,
                plugin_resolver=plugin_resolver,
                install_plan_path=install_plan_path,
            )
        except Exception as exc:  # noqa: BLE001 — a bad tick must not stop the loop
            if on_error is not None:
                on_error(exc)
            updates = []

        if updates:
            if on_updates is not None:
                on_updates(updates)
            if exit_on_update:
                return

        if stop_after is not None and await stop_after():
            return
        await asyncio.sleep(interval_seconds)
