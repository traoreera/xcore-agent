"""Tests for PluginResolver: against real local git repositories (via
file:// URLs — no mocking of `git` itself, since a real repo in tmp_path
costs nothing and proves the actual clone/fetch/checkout sequence works,
including resolving by commit SHA not just branch/tag), and against the
real xcore-team/marketplace HTTP contract (via `httpx.MockTransport`, same
pattern as test_marketplace_client.py) for the marketplace-primary path.
"""

import hashlib
import hmac
import io
import subprocess
import zipfile
from pathlib import Path

import httpx
import pytest

from xcore_agent.agent.marketplace_client import MarketplaceClient
from xcore_agent.plugin_resolver import PluginResolutionError, PluginResolver
from xcore_agent.schema.manifest import PluginSource

SECRET = b"the-developers-signing-secret"


def _sign(data: bytes) -> str:
    return "hmac_sha256:" + hmac.new(SECRET, data, hashlib.sha256).hexdigest()


def _zipball(*, root_dir_name: str = "acme-demo-abc1234") -> bytes:
    """A ZIP shaped like GitHub's zipball API (what the marketplace's
    `/install` endpoint proxies): one top-level directory wrapping the
    repo's actual files — see `flatten_single_root`."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(f"{root_dir_name}/plugin.yaml", "name: demo\nversion: 1.0.0\n")
        zf.writestr(f"{root_dir_name}/src/main.py", "# demo plugin\n")
    return buf.getvalue()


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


async def test_resolve_by_commit_sha(tmp_path, source_repo):
    repo, sha = source_repo
    resolver = PluginResolver(cache_root=tmp_path / "cache")
    source = PluginSource(url=f"file://{repo}", ref=sha, subdirectory="plugin-code")

    result = await resolver.resolve("demo", source)

    assert (result / "main.py").is_file()
    assert result.name == "plugin-code"


async def test_resolve_by_tag(tmp_path, source_repo):
    repo, _sha = source_repo
    resolver = PluginResolver(cache_root=tmp_path / "cache")
    source = PluginSource(url=f"file://{repo}", ref="v1.0.0", subdirectory="plugin-code")

    result = await resolver.resolve("demo", source)

    assert (result / "main.py").is_file()


async def test_resolve_without_subdirectory_returns_repo_root(tmp_path, source_repo):
    repo, sha = source_repo
    resolver = PluginResolver(cache_root=tmp_path / "cache")
    source = PluginSource(url=f"file://{repo}", ref=sha)

    result = await resolver.resolve("demo", source)

    assert (result / "plugin-code" / "main.py").is_file()
    assert (result / "README.md").is_file()


async def test_resolve_strips_git_directory(tmp_path, source_repo):
    repo, sha = source_repo
    resolver = PluginResolver(cache_root=tmp_path / "cache")
    source = PluginSource(url=f"file://{repo}", ref=sha)

    result = await resolver.resolve("demo", source)

    assert not (result / ".git").exists()


async def test_resolve_is_cached_on_second_call(tmp_path, source_repo):
    repo, sha = source_repo
    resolver = PluginResolver(cache_root=tmp_path / "cache")
    source = PluginSource(url=f"file://{repo}", ref=sha, subdirectory="plugin-code")

    first = await resolver.resolve("demo", source)
    marker = first.parent / ".xcore-resolved"
    marker_mtime_before = marker.stat().st_mtime

    second = await resolver.resolve("demo", source)

    assert second == first
    assert marker.stat().st_mtime == marker_mtime_before  # not re-cloned


async def test_resolve_unknown_ref_raises(tmp_path, source_repo):
    repo, _sha = source_repo
    resolver = PluginResolver(cache_root=tmp_path / "cache")
    source = PluginSource(url=f"file://{repo}", ref="does-not-exist")

    with pytest.raises(PluginResolutionError, match="fetch"):
        await resolver.resolve("demo", source)


async def test_resolve_missing_subdirectory_raises(tmp_path, source_repo):
    repo, sha = source_repo
    resolver = PluginResolver(cache_root=tmp_path / "cache")
    source = PluginSource(url=f"file://{repo}", ref=sha, subdirectory="does-not-exist")

    with pytest.raises(PluginResolutionError, match="not found"):
        await resolver.resolve("demo", source)


async def test_resolve_unknown_repo_raises(tmp_path):
    resolver = PluginResolver(cache_root=tmp_path / "cache")
    source = PluginSource(url=f"file://{tmp_path}/no-such-repo", ref="main")

    with pytest.raises(PluginResolutionError):
        await resolver.resolve("demo", source)


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


# ── Marketplace resolution (the primary path — see PluginSource's docstring) ──


async def test_resolve_marketplace_fetches_verifies_and_extracts(tmp_path):
    zip_bytes = _zipball()
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        assert request.url.path == "/app/marketplace/plugins/demo/install"
        assert request.url.params["version"] == "1.0.0"
        assert request.headers["x-api-key"] == "xdk_test"
        return httpx.Response(
            200,
            content=zip_bytes,
            headers={"X-Signature": _sign(zip_bytes), "X-Plugin": "demo@1.0.0"},
        )

    async with MarketplaceClient(
        "https://hub.example", api_key="xdk_test", transport=httpx.MockTransport(handler)
    ) as client:
        resolver = PluginResolver(
            cache_root=tmp_path / "cache",
            marketplace_client=client,
            trusted_signer_secret=SECRET,
        )
        source = PluginSource(marketplace_slug="demo", marketplace_version="1.0.0")

        result = await resolver.resolve("demo", source)

    assert (result / "plugin.yaml").is_file()
    assert (result / "src" / "main.py").is_file()
    assert len(calls) == 1


async def test_resolve_marketplace_respects_subdirectory(tmp_path):
    zip_bytes = _zipball()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=zip_bytes, headers={"X-Signature": _sign(zip_bytes)})

    async with MarketplaceClient(
        "https://hub.example", api_key="xdk_test", transport=httpx.MockTransport(handler)
    ) as client:
        resolver = PluginResolver(
            cache_root=tmp_path / "cache",
            marketplace_client=client,
            trusted_signer_secret=SECRET,
        )
        source = PluginSource(marketplace_slug="demo", subdirectory="src")

        result = await resolver.resolve("demo", source)

    assert result.name == "src"
    assert (result / "main.py").is_file()


async def test_resolve_marketplace_is_cached_on_second_call(tmp_path):
    zip_bytes = _zipball()
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        return httpx.Response(200, content=zip_bytes, headers={"X-Signature": _sign(zip_bytes)})

    async with MarketplaceClient(
        "https://hub.example", api_key="xdk_test", transport=httpx.MockTransport(handler)
    ) as client:
        resolver = PluginResolver(
            cache_root=tmp_path / "cache",
            marketplace_client=client,
            trusted_signer_secret=SECRET,
        )
        source = PluginSource(marketplace_slug="demo", marketplace_version="1.0.0")

        first = await resolver.resolve("demo", source)
        second = await resolver.resolve("demo", source)

    assert first == second
    assert call_count == 1  # not re-fetched


async def test_resolve_marketplace_signature_mismatch_raises(tmp_path):
    zip_bytes = _zipball()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=zip_bytes,
            headers={"X-Signature": _sign(b"not-the-real-payload")},
        )

    async with MarketplaceClient(
        "https://hub.example", api_key="xdk_test", transport=httpx.MockTransport(handler)
    ) as client:
        resolver = PluginResolver(
            cache_root=tmp_path / "cache",
            marketplace_client=client,
            trusted_signer_secret=SECRET,
        )
        source = PluginSource(marketplace_slug="demo")

        with pytest.raises(PluginResolutionError, match="signature"):
            await resolver.resolve("demo", source)


async def test_resolve_marketplace_without_client_configured_raises(tmp_path):
    resolver = PluginResolver(cache_root=tmp_path / "cache")  # no marketplace_client
    source = PluginSource(marketplace_slug="demo")

    with pytest.raises(PluginResolutionError, match="marketplace-api-key"):
        await resolver.resolve("demo", source)


async def test_resolve_marketplace_without_signing_secret_raises(tmp_path):
    async with MarketplaceClient(
        "https://hub.example",
        api_key="xdk_test",
        transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"x")),
    ) as client:
        resolver = PluginResolver(cache_root=tmp_path / "cache", marketplace_client=client)
        source = PluginSource(marketplace_slug="demo")

        with pytest.raises(PluginResolutionError, match="signing"):
            await resolver.resolve("demo", source)
