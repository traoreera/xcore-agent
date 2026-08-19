"""Tests for PluginResolver against real local git repositories (via
file:// URLs) — no mocking of `git` itself, since a real repo in tmp_path
costs nothing and proves the actual clone/fetch/checkout sequence works,
including resolving by commit SHA (not just branch/tag).
"""

import subprocess
from pathlib import Path

import pytest

from xcore_agent.plugin_resolver import PluginResolutionError, PluginResolver
from xcore_agent.schema.manifest import PluginSource


def _git(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True)


@pytest.fixture
def source_repo(tmp_path) -> tuple[Path, str]:
    """A local git repo with one commit, tagged v1.0.0, containing a
    `plugin-code/` subdirectory. Returns (repo_path, commit_sha)."""
    repo = tmp_path / "source-repo"
    repo.mkdir()
    _git("init", "--quiet", cwd=repo)
    _git("config", "user.email", "test@test.com", cwd=repo)
    _git("config", "user.name", "test", cwd=repo)
    (repo / "plugin-code").mkdir()
    (repo / "plugin-code" / "main.py").write_text("print('hello')\n")
    (repo / "README.md").write_text("not part of the plugin\n")
    _git("add", "-A", cwd=repo)
    _git("commit", "--quiet", "-m", "initial", cwd=repo)
    sha = _git("rev-parse", "HEAD", cwd=repo).stdout.strip()
    _git("tag", "v1.0.0", cwd=repo)
    return repo, sha


def test_resolve_by_commit_sha(tmp_path, source_repo):
    repo, sha = source_repo
    resolver = PluginResolver(cache_root=tmp_path / "cache")
    source = PluginSource(url=f"file://{repo}", ref=sha, subdirectory="plugin-code")

    result = resolver.resolve("demo", source)

    assert (result / "main.py").is_file()
    assert result.name == "plugin-code"


def test_resolve_by_tag(tmp_path, source_repo):
    repo, _sha = source_repo
    resolver = PluginResolver(cache_root=tmp_path / "cache")
    source = PluginSource(url=f"file://{repo}", ref="v1.0.0", subdirectory="plugin-code")

    result = resolver.resolve("demo", source)

    assert (result / "main.py").is_file()


def test_resolve_without_subdirectory_returns_repo_root(tmp_path, source_repo):
    repo, sha = source_repo
    resolver = PluginResolver(cache_root=tmp_path / "cache")
    source = PluginSource(url=f"file://{repo}", ref=sha)

    result = resolver.resolve("demo", source)

    assert (result / "plugin-code" / "main.py").is_file()
    assert (result / "README.md").is_file()


def test_resolve_strips_git_directory(tmp_path, source_repo):
    repo, sha = source_repo
    resolver = PluginResolver(cache_root=tmp_path / "cache")
    source = PluginSource(url=f"file://{repo}", ref=sha)

    result = resolver.resolve("demo", source)

    assert not (result / ".git").exists()


def test_resolve_is_cached_on_second_call(tmp_path, source_repo):
    repo, sha = source_repo
    resolver = PluginResolver(cache_root=tmp_path / "cache")
    source = PluginSource(url=f"file://{repo}", ref=sha, subdirectory="plugin-code")

    first = resolver.resolve("demo", source)
    marker = first.parent / ".xcore-resolved"
    marker_mtime_before = marker.stat().st_mtime

    second = resolver.resolve("demo", source)

    assert second == first
    assert marker.stat().st_mtime == marker_mtime_before  # not re-cloned


def test_resolve_unknown_ref_raises(tmp_path, source_repo):
    repo, _sha = source_repo
    resolver = PluginResolver(cache_root=tmp_path / "cache")
    source = PluginSource(url=f"file://{repo}", ref="does-not-exist")

    with pytest.raises(PluginResolutionError, match="fetch"):
        resolver.resolve("demo", source)


def test_resolve_missing_subdirectory_raises(tmp_path, source_repo):
    repo, sha = source_repo
    resolver = PluginResolver(cache_root=tmp_path / "cache")
    source = PluginSource(url=f"file://{repo}", ref=sha, subdirectory="does-not-exist")

    with pytest.raises(PluginResolutionError, match="not found"):
        resolver.resolve("demo", source)


def test_resolve_unknown_repo_raises(tmp_path):
    resolver = PluginResolver(cache_root=tmp_path / "cache")
    source = PluginSource(url=f"file://{tmp_path}/no-such-repo", ref="main")

    with pytest.raises(PluginResolutionError):
        resolver.resolve("demo", source)


def test_authenticated_url_injects_token_for_matching_host():
    resolver = PluginResolver(cache_root=Path("/unused"), git_credentials={"github.com": "tok_123"})

    url = resolver._authenticated_url("https://github.com/org/repo.git")

    assert url == "https://x-access-token:tok_123@github.com/org/repo.git"


def test_authenticated_url_leaves_url_unchanged_without_matching_credentials():
    resolver = PluginResolver(cache_root=Path("/unused"), git_credentials={"gitlab.com": "tok_x"})

    url = resolver._authenticated_url("https://github.com/org/repo.git")

    assert url == "https://github.com/org/repo.git"


def test_authenticated_url_leaves_ssh_urls_unchanged():
    resolver = PluginResolver(cache_root=Path("/unused"), git_credentials={"github.com": "tok_123"})

    url = resolver._authenticated_url("git@github.com:org/repo.git")

    assert url == "git@github.com:org/repo.git"
