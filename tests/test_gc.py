import os
import time
from pathlib import Path

from xcore_agent.agent.gc import GarbageCollector
from xcore_agent.agent.install_driver import Layout


class RecordingSupervisor:
    def __init__(self) -> None:
        self.restarted: list[str | None] = []

    def start(self, plugin_id):
        pass

    def stop(self, plugin_id):
        pass

    def restart(self, plugin_id):
        self.restarted.append(plugin_id)

    def healthcheck(self, plugin_id, *, timeout_seconds, retries):
        pass


def _layout(tmp_path: Path) -> Layout:
    return Layout(project_root=tmp_path / "project", extracted_root=tmp_path / "extracted")


def _snapshot(
    snapshots_dir: Path, step_id: str, plugin_id: str, index: int, *, age_seconds: float
) -> Path:
    path = snapshots_dir / f"{step_id}-{plugin_id}-{index}"
    path.mkdir(parents=True)
    (path / "marker").write_text("x")
    mtime = time.time() - age_seconds
    os.utime(path, (mtime, mtime))
    return path


def test_collect_snapshots_keeps_only_most_recent_per_plugin(tmp_path):
    layout = _layout(tmp_path)
    layout.snapshots_dir.mkdir(parents=True)

    # 4 snapshots for "demo": index 0 is oldest (age 100s) .. index 3 is newest (age 97s)
    demo_snapshots = [
        _snapshot(layout.snapshots_dir, "install_demo", "demo", i, age_seconds=100 - i)
        for i in range(4)
    ]
    # a single snapshot for a different plugin must never be touched
    other_snapshot = _snapshot(layout.snapshots_dir, "install_other", "other", 0, age_seconds=10)

    gc = GarbageCollector(layout, keep_snapshots=2)
    removed = gc.collect_snapshots()

    assert set(removed) == {demo_snapshots[0], demo_snapshots[1]}
    assert demo_snapshots[2].exists()
    assert demo_snapshots[3].exists()
    assert other_snapshot.exists()


def test_collect_snapshots_is_noop_when_under_the_limit(tmp_path):
    layout = _layout(tmp_path)
    layout.snapshots_dir.mkdir(parents=True)
    kept = _snapshot(layout.snapshots_dir, "install_demo", "demo", 0, age_seconds=5)

    gc = GarbageCollector(layout, keep_snapshots=3)
    removed = gc.collect_snapshots()

    assert removed == []
    assert kept.exists()


def test_collect_snapshots_handles_missing_directory(tmp_path):
    gc = GarbageCollector(_layout(tmp_path))
    assert gc.collect_snapshots() == []


def test_collect_cache_removes_versions_not_kept(tmp_path):
    cache_root = tmp_path / "cache"
    for version in ["1.0.0", "1.1.0", "1.2.0"]:
        (cache_root / version).mkdir(parents=True)

    gc = GarbageCollector(_layout(tmp_path), cache_root=cache_root)
    removed = gc.collect_cache(keep_versions=frozenset({"1.2.0"}))

    assert {p.name for p in removed} == {"1.0.0", "1.1.0"}
    assert (cache_root / "1.2.0").is_dir()
    assert not (cache_root / "1.0.0").exists()
    assert not (cache_root / "1.1.0").exists()


def test_collect_cache_without_cache_root_is_noop(tmp_path):
    gc = GarbageCollector(_layout(tmp_path))
    assert gc.collect_cache(keep_versions=frozenset()) == []


def test_force_restart_calls_supervisor_for_each_plugin(tmp_path):
    supervisor = RecordingSupervisor()
    gc = GarbageCollector(_layout(tmp_path), supervisor=supervisor)

    restarted = gc.force_restart(["demo", "auth"])

    assert restarted == ["demo", "auth"]
    assert supervisor.restarted == ["demo", "auth"]


def test_force_restart_without_supervisor_is_a_noop(tmp_path):
    gc = GarbageCollector(_layout(tmp_path))
    assert gc.force_restart(["demo"]) == []


def test_collect_reports_bytes_freed_and_restarts(tmp_path):
    cache_root = tmp_path / "cache"
    stale = cache_root / "1.0.0"
    stale.mkdir(parents=True)
    (stale / "big.bin").write_bytes(b"x" * 1000)

    supervisor = RecordingSupervisor()
    gc = GarbageCollector(_layout(tmp_path), cache_root=cache_root, supervisor=supervisor)
    report = gc.collect(keep_versions=frozenset(), restart_plugins=["demo"])

    assert report.bytes_freed >= 1000
    assert {p.name for p in report.cache_dirs_removed} == {"1.0.0"}
    assert report.plugins_restarted == ["demo"]
    assert supervisor.restarted == ["demo"]
