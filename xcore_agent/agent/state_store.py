"""Tracks which project version is currently installed on this host.

Without this, the CI/CD watch loop (`agent.watcher.Watcher`) would have no
way to tell "Hub says v1.2.3 is latest" from "v1.2.3 is already what's
running here" and would redeploy on every single check.
"""

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class InstalledState:
    project_id: str
    version: str
    installed_at: str


class StateStore:
    """Persists install state as `<project_root>/.xcore/state.json` — or,
    with `namespace` set, `<project_root>/.xcore/state-<namespace>.json`.

    `namespace` matters as soon as more than one deployment shares a
    `project_root` (e.g. `MarketplaceWatcher` polling several independent
    slugs against the same host): without it, every watcher reads/writes
    the SAME file, so each poll clobbers the others' recorded version and
    every watcher but the last-written-one redeploys on every single check,
    mistaking a sibling's state for its own. Omit it (the default) for the
    single-project-per-root case (`agent.watcher.Watcher`), which never had
    this problem and keeps its existing `state.json` path unchanged."""

    def __init__(self, project_root: Path, *, namespace: str | None = None) -> None:
        filename = f"state-{namespace}.json" if namespace else "state.json"
        self._path = project_root / ".xcore" / filename

    def read(self) -> InstalledState | None:
        if not self._path.is_file():
            return None
        return InstalledState(**json.loads(self._path.read_text()))

    def write(self, *, project_id: str, version: str) -> InstalledState:
        state = InstalledState(
            project_id=project_id,
            version=version,
            installed_at=datetime.now(timezone.utc).isoformat(),
        )
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(asdict(state)))
        return state
