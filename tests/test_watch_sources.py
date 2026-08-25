"""Tests for watch_sources — the multi-source counterpart to
MarketplaceWatcher, see its module docstring for why the two can't share
code (MarketplaceWatcher replays install.yaml's whole plan through ONE
fetched artifact; a composite project's install.yaml declares MANY
independent marketplace sources for one shared deployment).
"""

import hashlib
import hmac
import io
import zipfile
from pathlib import Path

import pytest
import yaml

from xcore_agent.agent.marketplace_client import FetchedArtifact
from xcore_agent.plugin_resolver import PluginResolver
from xcore_agent.watch_sources import WatchSourcesError, check_once, watch_forever

SECRET = b"the-developers-signing-secret"


class FakeMarketplaceClient:
    """Structural stand-in for MarketplaceClient — no network access. Each
    slug has its own independently-configurable latest_version, matching
    real usage: many unrelated marketplace sources in one install.yaml."""

    def __init__(self) -> None:
        self.latest_versions: dict[str, str] = {}
        self.fail_latest: set[str] = set()
        self.get_latest_calls: list[str] = []
        self.fetch_calls: list[tuple[str, str, str]] = []

    async def get_latest_version(self, *, slug: str, kind: str = "plugin") -> str:
        self.get_latest_calls.append(slug)
        if slug in self.fail_latest:
            raise RuntimeError(f"marketplace unreachable for {slug}")
        return self.latest_versions[slug]

    async def fetch_artifact(self, *, slug: str, version: str = "latest", kind: str = "plugin"):
        self.fetch_calls.append((slug, version, kind))
        zip_bytes = _build_zipball(slug=slug, version=version)
        return FetchedArtifact(
            data=zip_bytes,
            signature_header=_sign(zip_bytes),
            plugin_header=f"{slug}@{version}",
            repo_header=f"acme/{slug}@{version}",
        )


def _build_zipball(*, slug: str, version: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        root = f"acme-{slug}-abc1234"
        zf.writestr(f"{root}/plugin.yaml", f"name: {slug}\nversion: {version}\n")
        zf.writestr(f"{root}/main.py", f"# {slug} v{version}\n")
    return buf.getvalue()


def _sign(data: bytes) -> str:
    return "hmac_sha256:" + hmac.new(SECRET, data, hashlib.sha256).hexdigest()


def _write_install_plan(root: Path, *, steps: list[dict]) -> Path:
    # Mirrors xcore-team/marketplace's own convention (plugins under
    # "app/", not the "plugins/" default) — the exact case this module
    # was written for, see _read_plugins_dirname.
    root.mkdir(parents=True, exist_ok=True)
    (root / "integration.yaml").write_text(yaml.safe_dump({"plugins": {"directory": "./app"}}))
    plan_path = root / "deployment" / "install.yaml"
    plan_path.parent.mkdir(parents=True, exist_ok=True)
    plan = {
        "format_version": "1",
        "project_id": "prj_test",
        "version": "1.0.0",
        "steps": [{"id": "prepare", "action": "prepare"}, *steps],
    }
    plan_path.write_text(yaml.safe_dump(plan))
    return plan_path


def _resolver(client: FakeMarketplaceClient, tmp_path: Path) -> PluginResolver:
    return PluginResolver(
        cache_root=tmp_path / "cache",
        marketplace_client=client,
        trusted_signer_secret=SECRET,
    )


async def test_applies_updates_for_multiple_independent_sources(tmp_path):
    client = FakeMarketplaceClient()
    client.latest_versions = {"xauth": "1.0.0", "xmailler": "0.1.1"}
    root = tmp_path / "project"
    root.mkdir()
    plan_path = _write_install_plan(
        root,
        steps=[
            {
                "id": "install_auth",
                "action": "install_plugin",
                "plugin": "auth",
                "source": {"marketplace_slug": "xauth", "marketplace_version": "0.9.0"},
            },
            {
                "id": "install_ext_xmailler",
                "action": "install_extension",
                "extension": "xmailler",
                "source": {
                    "marketplace_slug": "xmailler",
                    "marketplace_version": "0.1.0",
                    "marketplace_kind": "service",
                },
            },
        ],
    )
    resolver = _resolver(client, tmp_path)

    updates = await check_once(root, plugin_resolver=resolver, install_plan_path=plan_path)

    assert {(u.id, u.slug, u.to_version) for u in updates} == {
        ("install_auth", "xauth", "1.0.0"),
        ("install_ext_xmailler", "xmailler", "0.1.1"),
    }
    assert (root / "app" / "auth" / "main.py").read_text() == "# xauth v1.0.0\n"
    assert (root / "extensions" / "xmailler" / "main.py").read_text() == "# xmailler v0.1.1\n"

    state = yaml.safe_load((root / ".xcore" / "watch-sources-state.json").read_text())
    assert state == {"install_auth": "1.0.0", "install_ext_xmailler": "0.1.1"}


async def test_second_check_skips_unchanged_versions(tmp_path):
    client = FakeMarketplaceClient()
    client.latest_versions = {"xauth": "1.0.0"}
    root = tmp_path / "project"
    root.mkdir()
    plan_path = _write_install_plan(
        root,
        steps=[
            {
                "id": "install_auth",
                "action": "install_plugin",
                "plugin": "auth",
                "source": {"marketplace_slug": "xauth", "marketplace_version": "1.0.0"},
            }
        ],
    )
    resolver = _resolver(client, tmp_path)

    first = await check_once(root, plugin_resolver=resolver, install_plan_path=plan_path)
    assert len(first) == 1
    assert client.fetch_calls == [("xauth", "1.0.0", "plugin")]

    second = await check_once(root, plugin_resolver=resolver, install_plan_path=plan_path)
    assert second == []
    # No re-fetch — state already recorded 1.0.0 as applied.
    assert client.fetch_calls == [("xauth", "1.0.0", "plugin")]


async def test_one_sources_failure_does_not_block_the_others(tmp_path):
    client = FakeMarketplaceClient()
    client.latest_versions = {"xauth": "1.0.0", "xdevkeys": "1.0.0"}
    client.fail_latest = {"xauth"}
    root = tmp_path / "project"
    root.mkdir()
    plan_path = _write_install_plan(
        root,
        steps=[
            {
                "id": "install_auth",
                "action": "install_plugin",
                "plugin": "auth",
                "source": {"marketplace_slug": "xauth", "marketplace_version": "0.9.0"},
            },
            {
                "id": "install_xdevkeys",
                "action": "install_plugin",
                "plugin": "xdevkeys",
                "source": {"marketplace_slug": "xdevkeys", "marketplace_version": "0.9.0"},
            },
        ],
    )
    resolver = _resolver(client, tmp_path)

    updates = await check_once(root, plugin_resolver=resolver, install_plan_path=plan_path)

    assert [u.id for u in updates] == ["install_xdevkeys"]
    assert not (root / "app" / "auth").exists()
    assert (root / "app" / "xdevkeys" / "main.py").is_file()


async def test_steps_without_source_are_ignored(tmp_path):
    client = FakeMarketplaceClient()
    root = tmp_path / "project"
    root.mkdir()
    plan_path = _write_install_plan(
        root,
        steps=[{"id": "install_marketplace", "action": "install_plugin", "plugin": "marketplace"}],
    )
    resolver = _resolver(client, tmp_path)

    updates = await check_once(root, plugin_resolver=resolver, install_plan_path=plan_path)

    assert updates == []
    assert client.get_latest_calls == []


async def test_missing_install_plan_raises(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    client = FakeMarketplaceClient()
    resolver = _resolver(client, tmp_path)

    with pytest.raises(WatchSourcesError, match="not found"):
        await check_once(root, plugin_resolver=resolver)


async def test_watch_forever_exits_after_update_when_requested(tmp_path):
    client = FakeMarketplaceClient()
    client.latest_versions = {"xauth": "1.0.0"}
    root = tmp_path / "project"
    root.mkdir()
    plan_path = _write_install_plan(
        root,
        steps=[
            {
                "id": "install_auth",
                "action": "install_plugin",
                "plugin": "auth",
                "source": {"marketplace_slug": "xauth", "marketplace_version": "0.9.0"},
            }
        ],
    )
    resolver = _resolver(client, tmp_path)
    seen: list[list] = []

    await watch_forever(
        root,
        plugin_resolver=resolver,
        install_plan_path=plan_path,
        interval_seconds=0,
        exit_on_update=True,
        on_updates=seen.append,
    )

    assert len(seen) == 1
    assert seen[0][0].slug == "xauth"


async def test_watch_forever_reports_errors_and_keeps_looping(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    # No install.yaml at all — every tick raises WatchSourcesError.
    resolver = _resolver(FakeMarketplaceClient(), tmp_path)
    errors: list[Exception] = []
    ticks = 0

    async def stop_after_three() -> bool:
        nonlocal ticks
        ticks += 1
        return ticks >= 3

    await watch_forever(
        root,
        plugin_resolver=resolver,
        interval_seconds=0,
        on_error=errors.append,
        stop_after=stop_after_three,
    )

    assert len(errors) == 3
    assert all(isinstance(exc, WatchSourcesError) for exc in errors)
