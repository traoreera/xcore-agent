"""Garbage collection for xcore-agent's on-disk state.

Two things grow unbounded if nothing prunes them:

- `<project_root>/.snapshots/` — every `install_plugin` step with
  `snapshot: true` (see install_driver.py) leaves a copy of the previous
  plugin version behind, forever, unless something removes old ones.
- `<cache_root>/<version>/` — every version ever deployed leaves its
  downloaded/extracted workdir under the agent's cache root, forever.

`GarbageCollector` prunes both, and `force_restart` (used after a purge) is
how the agent makes sure a running plugin process actually drops any
in-memory state it was holding, rather than serving stale cached data
indefinitely after its on-disk snapshot was reclaimed.
"""

import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .install_driver import Layout, Supervisor


@dataclass(frozen=True)
class GCReport:
    snapshots_removed: list[Path] = field(default_factory=list)
    cache_dirs_removed: list[Path] = field(default_factory=list)
    plugins_restarted: list[str] = field(default_factory=list)
    bytes_freed: int = 0


class GarbageCollector:
    def __init__(
        self,
        layout: Layout,
        *,
        keep_snapshots: int = 3,
        cache_root: Path | None = None,
        supervisor: Supervisor | None = None,
    ) -> None:
        self.layout = layout
        self.keep_snapshots = keep_snapshots
        self.cache_root = cache_root
        self._supervisor = supervisor

    def collect_snapshots(self) -> list[Path]:
        """Keep only the `keep_snapshots` most recent snapshots per plugin.

        Snapshot directories are named `<step_id>-<plugin_id>-<epoch_ms>`
        (see `InstallDriver.snapshot_before`); grouping by the plugin_id
        segment and sorting by mtime finds each plugin's oldest snapshots.
        """
        removed: list[Path] = []
        if not self.layout.snapshots_dir.is_dir():
            return removed

        by_plugin: dict[str, list[Path]] = {}
        for entry in self.layout.snapshots_dir.iterdir():
            if not entry.is_dir():
                continue
            parts = entry.name.rsplit("-", 2)
            plugin_id = parts[1] if len(parts) == 3 else entry.name
            by_plugin.setdefault(plugin_id, []).append(entry)

        for snapshots in by_plugin.values():
            snapshots.sort(key=lambda p: p.stat().st_mtime)
            stale = snapshots[: max(0, len(snapshots) - self.keep_snapshots)]
            for path in stale:
                shutil.rmtree(path, ignore_errors=True)
                removed.append(path)
        return removed

    def collect_cache(self, *, keep_versions: frozenset[str]) -> list[Path]:
        """Remove cached download/extraction workdirs for any version not in
        `keep_versions` (normally: just the currently installed version)."""
        removed: list[Path] = []
        if self.cache_root is None or not self.cache_root.is_dir():
            return removed
        for version_dir in self.cache_root.iterdir():
            if version_dir.is_dir() and version_dir.name not in keep_versions:
                shutil.rmtree(version_dir, ignore_errors=True)
                removed.append(version_dir)
        return removed

    def force_restart(self, plugin_ids: list[str]) -> list[str]:
        """Restart each plugin so a running process drops any in-memory
        cache it was holding — a purged-on-disk snapshot alone doesn't do
        that for a process that's still up. Requires a `supervisor` to have
        been passed in; without one this is a no-op (nothing to restart)."""
        if self._supervisor is None:
            return []
        restarted = []
        for plugin_id in plugin_ids:
            self._supervisor.restart(plugin_id)
            restarted.append(plugin_id)
        return restarted

    def collect(
        self, *, keep_versions: frozenset[str], restart_plugins: list[str] | None = None
    ) -> GCReport:
        before = _dir_size(self.layout.project_root) + _dir_size(self.cache_root)
        snapshots_removed = self.collect_snapshots()
        cache_dirs_removed = self.collect_cache(keep_versions=keep_versions)
        after = _dir_size(self.layout.project_root) + _dir_size(self.cache_root)

        plugins_restarted = self.force_restart(restart_plugins or [])

        return GCReport(
            snapshots_removed=snapshots_removed,
            cache_dirs_removed=cache_dirs_removed,
            plugins_restarted=plugins_restarted,
            bytes_freed=before - after,
        )


def _dir_size(path: Path | None) -> int:
    if path is None or not path.is_dir():
        return 0
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
