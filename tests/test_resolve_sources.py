"""Tests for resolve_all_sources — resolving install.yaml's own `source:`
directly onto a project's plugins/extensions directories, in place (no
.xdeploy artifact, no manifest.json). See its module docstring for how
this differs from agent.pipeline.DeploymentRunner._resolve_plugins, which
this deliberately doesn't share code with.
"""

import subprocess
from pathlib import Path

import pytest
import yaml

from xcore_agent.plugin_resolver import PluginResolver
from xcore_agent.resolve_sources import ResolveSourcesError, resolve_all_sources

PROJECT_ID = "prj_test0000001"


def _git(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True)


@pytest.fixture
def source_repo(tmp_path) -> tuple[Path, str]:
    repo = tmp_path / "source-repo"
    repo.mkdir()
    _git("init", "--quiet", cwd=repo)
    _git("config", "user.email", "test@test.com", cwd=repo)
    _git("config", "user.name", "test", cwd=repo)
    (repo / "plugin.yaml").write_text("name: demo\nversion: 2.0.0\n")
    (repo / "main.py").write_text("# resolved from git\n")
    _git("add", "-A", cwd=repo)
    _git("commit", "--quiet", "-m", "initial", cwd=repo)
    sha = _git("rev-parse", "HEAD", cwd=repo).stdout.strip()
    return repo, sha


def _write_project(root: Path, *, extra_steps: list[dict]) -> None:
    (root / "plugins" / "demo").mkdir(parents=True)
    (root / "deployment").mkdir(parents=True)
    (root / "integration.yaml").write_text("services: {}\n")
    # Thin, build-time-only stub — same convention as a real project's
    # source-based plugin: no real code here, just enough to be a valid
    # plugin directory before resolution ever runs.
    (root / "plugins" / "demo" / "plugin.yaml").write_text(
        "name: demo\nversion: 1.0.0\n# thin stub — resolved by install.yaml's source:\n"
    )
    (root / "plugins" / "demo" / ".env.template").write_text("DEMO_API_KEY=\n")

    steps = [{"id": "prepare", "action": "prepare"}, *extra_steps]
    plan = {"format_version": "1", "project_id": PROJECT_ID, "version": "1.0.0", "steps": steps}
    (root / "deployment" / "install.yaml").write_text(yaml.safe_dump(plan))


async def test_resolves_plugin_source_in_place(tmp_path, source_repo):
    repo, sha = source_repo
    root = tmp_path / "project"
    _write_project(
        root,
        extra_steps=[
            {
                "id": "install_demo",
                "action": "install_plugin",
                "plugin": "demo",
                "source": {"url": f"file://{repo}", "ref": sha},
            }
        ],
    )
    resolver = PluginResolver(cache_root=tmp_path / "cache")

    resolved = await resolve_all_sources(root, plugin_resolver=resolver)

    assert len(resolved) == 1
    assert resolved[0].id == "demo"
    assert resolved[0].kind == "plugin"
    plugin_dir = root / "plugins" / "demo"
    assert (plugin_dir / "main.py").read_text() == "# resolved from git\n"
    # The resolved repo's own plugin.yaml wins over the thin build-time stub.
    assert "version: 2.0.0" in (plugin_dir / "plugin.yaml").read_text()
    # .env.template has no counterpart in the resolved repo — survives.
    assert (plugin_dir / ".env.template").is_file()


async def test_resolves_extension_source_in_place(tmp_path, source_repo):
    repo, sha = source_repo
    root = tmp_path / "project"
    _write_project(root, extra_steps=[])
    (root / "extensions" / "mail").mkdir(parents=True)
    plan_path = root / "deployment" / "install.yaml"
    plan = yaml.safe_load(plan_path.read_text())
    plan["steps"].append(
        {
            "id": "install_mail",
            "action": "install_extension",
            "extension": "mail",
            "source": {"url": f"file://{repo}", "ref": sha},
        }
    )
    plan_path.write_text(yaml.safe_dump(plan))
    resolver = PluginResolver(cache_root=tmp_path / "cache")

    resolved = await resolve_all_sources(root, plugin_resolver=resolver)

    assert len(resolved) == 1
    assert resolved[0].id == "mail"
    assert resolved[0].kind == "extension"
    assert (root / "extensions" / "mail" / "main.py").is_file()


async def test_no_source_steps_returns_empty_list(tmp_path):
    root = tmp_path / "project"
    _write_project(
        root,
        extra_steps=[{"id": "install_demo", "action": "install_plugin", "plugin": "demo"}],
    )
    resolver = PluginResolver(cache_root=tmp_path / "cache")

    resolved = await resolve_all_sources(root, plugin_resolver=resolver)

    assert resolved == []
    # Untouched — still the thin build-time stub, not overwritten.
    assert "thin stub" in (root / "plugins" / "demo" / "plugin.yaml").read_text()


async def test_missing_install_plan_raises(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    resolver = PluginResolver(cache_root=tmp_path / "cache")

    with pytest.raises(ResolveSourcesError, match="not found"):
        await resolve_all_sources(root, plugin_resolver=resolver)


async def test_respects_custom_plugins_directory(tmp_path, source_repo):
    repo, sha = source_repo
    root = tmp_path / "project"
    root.mkdir()
    (root / "app" / "demo").mkdir(parents=True)
    (root / "deployment").mkdir(parents=True)
    root.joinpath("integration.yaml").write_text("plugins:\n  directory: ./app\n")
    (root / "app" / "demo" / "plugin.yaml").write_text("name: demo\nversion: 1.0.0\n")
    plan = {
        "format_version": "1",
        "project_id": PROJECT_ID,
        "version": "1.0.0",
        "steps": [
            {"id": "prepare", "action": "prepare"},
            {
                "id": "install_demo",
                "action": "install_plugin",
                "plugin": "demo",
                "source": {"url": f"file://{repo}", "ref": sha},
            },
        ],
    }
    (root / "deployment" / "install.yaml").write_text(yaml.safe_dump(plan))
    resolver = PluginResolver(cache_root=tmp_path / "cache")

    resolved = await resolve_all_sources(root, plugin_resolver=resolver)

    assert resolved[0].target == root / "app" / "demo"
    assert (root / "app" / "demo" / "main.py").is_file()
    assert not (root / "plugins").exists()
