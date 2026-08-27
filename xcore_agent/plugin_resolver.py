"""Resolves a plugin's source code from wherever `PluginSource` points, for
plugins a marketplace/registry references by link instead of embedding
inside the `.xdeploy` artifact (see `schema.manifest.PluginSource`).

Two origins, marketplace preferred:

- **Marketplace** (`source.marketplace_slug` set) — fetched via the real
  xcore-team/marketplace `GET /{slug}/install` endpoint
  (`agent.marketplace_client.MarketplaceClient`), whose response is
  HMAC-SHA256-signed and verified here against `trusted_signer_secret`
  before anything is extracted to disk. This is the primary path: it's what
  `xcli plugin install` records in `.xcore-registry.json` for anything
  actually installed from the marketplace (see `packer.builder._read_
  registry_source`), so most source-based plugins resolve this way without
  an operator ever writing a raw git URL.
- **Git** (`source.url` set) — a plain `git fetch`/`checkout`, for a plugin
  never published to the marketplace. This is the fallback: only used when
  a plugin's origin genuinely isn't the marketplace, not an alternative way
  to resolve one that is.

Shared between the packer (which may resolve a plugin at build time to pin
its hash — not yet implemented, see the packer's docstring) and the agent
(which resolves at deploy time, verifying against any pinned hash).

Public vs. private git repos are not distinguished by a flag: they're the
same `git` operation with different authentication, exactly like using
`git` directly from a shell —

- SSH URLs (`git@host:org/repo.git`) authenticate however the host's SSH
  agent/config already does; this module does nothing special for them.
- HTTPS URLs authenticate via a per-host token from `git_credentials`,
  spliced into the URL as `https://x-access-token:<token>@host/...` — the
  standard way to hand `git` a token non-interactively. No token configured
  for that host means the URL is used as-is (fine for a public repo, a
  clone failure otherwise).
"""

from __future__ import annotations

import shutil
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit, urlunsplit

from . import crypto
from .schema.manifest import PluginSource

if TYPE_CHECKING:
    # Deferred: importing agent.marketplace_client at module level here
    # would trigger xcore_agent.agent's own __init__.py (Python always
    # initializes a package before one of its submodules), which imports
    # .pipeline, which imports THIS module back — a real circular import
    # that only ever avoided firing because xcore_agent.cli always
    # happened to import xcore_agent.agent first. Nothing at runtime here
    # actually needs the class value: `marketplace_client` below is only
    # ever constructed by a caller (cli.py) and handed in; this module
    # only calls methods on it, never `MarketplaceClient(...)` itself.
    from .agent.marketplace_client import MarketplaceClient


class PluginResolutionError(Exception):
    """Raised when a plugin's source cannot be fetched or is unusable
    (git failure, marketplace signature mismatch, missing subdirectory, ...)."""


_RESOLVED_MARKER = ".xcore-resolved"


@dataclass
class PluginResolver:
    cache_root: Path
    git_credentials: dict[str, str] | None = None  # host -> token, HTTPS only
    # Both required to resolve a `marketplace_slug`-based source; absent by
    # default so a deployment with no marketplace-sourced plugin needs
    # neither (see cli.py's `deploy`/`watch` — these are optional options,
    # only enforced here, lazily, when actually needed).
    marketplace_client: MarketplaceClient | None = None
    trusted_signer_secret: bytes | None = None

    async def resolve(self, plugin_id: str, source: PluginSource) -> Path:
        """Return a local directory containing `plugin_id`'s code, fetching
        it from the marketplace or git (see module docstring) if not
        already cached.

        Caching is keyed on (plugin_id, version-or-ref): a commit SHA or a
        marketplace version is treated as immutable, so this is safe to
        reuse indefinitely within `cache_root` — acceptable since a caller
        pins to something immutable whenever integrity matters (see
        `PluginSource`'s docstring; a marketplace fetch also gets its own
        independent integrity guarantee from the HMAC signature check below,
        regardless of caching).
        """
        if source.marketplace_slug is not None:
            return await self._resolve_marketplace(plugin_id, source)
        return self._resolve_git(plugin_id, source)

    async def _resolve_marketplace(self, plugin_id: str, source: PluginSource) -> Path:
        assert source.marketplace_slug is not None
        if self.marketplace_client is None or self.trusted_signer_secret is None:
            raise PluginResolutionError(
                f"plugin {plugin_id!r} is resolved from the marketplace "
                f"(slug={source.marketplace_slug!r}) but no marketplace client/signing "
                "secret was configured for this deployment — pass --marketplace-api-key "
                "and --marketplace-signing-secret"
            )

        cache_key = _safe_ref_dirname(source.marketplace_version)
        dest = self.cache_root / plugin_id / f"mkt-{cache_key}"
        if not (dest / _RESOLVED_MARKER).is_file():
            if dest.exists():
                shutil.rmtree(dest)

            artifact = await self.marketplace_client.fetch_artifact(
                slug=source.marketplace_slug,
                version=source.marketplace_version,
                kind=source.marketplace_kind,
            )
            try:
                crypto.verify_hmac_sha256_hex(
                    secret=self.trusted_signer_secret,
                    signature_hex=artifact.signature_header,
                    payload=artifact.data,
                )
            except crypto.SignatureVerificationError as exc:
                raise PluginResolutionError(
                    f"plugin {plugin_id!r}: marketplace signature verification failed "
                    f"for {source.marketplace_slug}@{source.marketplace_version}: {exc}"
                ) from exc

            dest.mkdir(parents=True, exist_ok=True)
            zip_path = self.cache_root / plugin_id / f"{cache_key}.zip"
            zip_path.write_bytes(artifact.data)
            try:
                with zipfile.ZipFile(zip_path) as zf:
                    safe_extract_zip(zf, dest)
            except zipfile.BadZipFile as exc:
                shutil.rmtree(dest, ignore_errors=True)
                raise PluginResolutionError(
                    f"plugin {plugin_id!r}: marketplace artifact for "
                    f"{source.marketplace_slug}@{source.marketplace_version} is not a "
                    f"valid ZIP: {exc}"
                ) from exc
            except PluginResolutionError:
                shutil.rmtree(dest, ignore_errors=True)
                raise
            finally:
                zip_path.unlink(missing_ok=True)
            flatten_single_root(dest)
            (dest / _RESOLVED_MARKER).write_text(source.marketplace_version)

        result = dest / source.subdirectory if source.subdirectory else dest
        if not result.is_dir():
            raise PluginResolutionError(
                f"plugin {plugin_id!r}: subdirectory {source.subdirectory!r} not found "
                f"in marketplace artifact {source.marketplace_slug}@{source.marketplace_version}"
            )
        return result

    def _resolve_git(self, plugin_id: str, source: PluginSource) -> Path:
        assert source.url is not None and source.ref is not None
        clone_dir = self.cache_root / plugin_id / _safe_ref_dirname(source.ref)
        if not (clone_dir / _RESOLVED_MARKER).is_file():
            if clone_dir.exists():
                shutil.rmtree(clone_dir)
            self._clone(source, clone_dir)

        result = clone_dir / source.subdirectory if source.subdirectory else clone_dir
        if not result.is_dir():
            raise PluginResolutionError(
                f"plugin {plugin_id!r}: subdirectory {source.subdirectory!r} not found "
                f"in {source.url}@{source.ref}"
            )
        return result

    def _clone(self, source: PluginSource, dest: Path) -> None:
        assert source.url is not None and source.ref is not None
        dest.mkdir(parents=True, exist_ok=True)
        url = self._authenticated_url(source.url)
        try:
            self._git("init", "--quiet", str(dest))
            self._git("-C", str(dest), "remote", "add", "origin", url)
            # fetch by ref (branch, tag, or commit SHA) then check it out —
            # unlike `clone --branch`, this also works for an arbitrary
            # commit SHA, as long as the server allows fetching it directly
            # (true for GitHub/GitLab/Bitbucket and most self-hosted setups).
            self._git("-C", str(dest), "fetch", "--quiet", "--depth", "1", "origin", source.ref)
            self._git("-C", str(dest), "checkout", "--quiet", "FETCH_HEAD")
        except PluginResolutionError:
            shutil.rmtree(dest, ignore_errors=True)
            raise
        shutil.rmtree(dest / ".git", ignore_errors=True)
        (dest / _RESOLVED_MARKER).write_text(source.ref)

    def _authenticated_url(self, url: str) -> str:
        if not url.startswith("https://"):
            return url
        parts = urlsplit(url)
        token = (self.git_credentials or {}).get(parts.netloc)
        if token is None:
            return url
        netloc = f"x-access-token:{token}@{parts.netloc}"
        return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))

    def _git(self, *args: str) -> None:
        result = subprocess.run(["git", *args], capture_output=True, text=True)
        if result.returncode != 0:
            raise PluginResolutionError(
                f"git {' '.join(args)} failed: {result.stderr.strip() or result.stdout.strip()}"
            )


def _safe_ref_dirname(ref: str) -> str:
    return ref.replace("/", "_")


def safe_extract_zip(zf: zipfile.ZipFile, dest: Path) -> None:
    """Extract a ZIP archive, rejecting any member that would escape `dest`
    via `../` or an absolute path — same reasoning as `agent.pipeline`'s
    `_safe_extract` for tar archives. Shared with `agent.marketplace_
    pipeline` (the single-plugin `deploy-marketplace` flow), which fetches
    from the same signed marketplace endpoint this module resolves
    multi-plugin `source:` references from."""
    dest_resolved = dest.resolve()
    for name in zf.namelist():
        member_path = (dest_resolved / name).resolve()
        if not member_path.is_relative_to(dest_resolved):
            raise PluginResolutionError(f"artifact contains an unsafe path: {name!r}")
    zf.extractall(dest_resolved)  # noqa: S202 — membership already validated above


def flatten_single_root(target: Path) -> None:
    """GitHub's zipball API (what the marketplace's `/install` endpoint
    proxies) wraps every archive in a single top-level `owner-repo-<sha>/`
    directory. Strip it so `target` directly contains the plugin's own
    files (plugin.yaml, src/, ...), matching the layout `InstallDriver.
    install_plugin`/this module's own callers expect."""
    entries = list(target.iterdir())
    if len(entries) != 1 or not entries[0].is_dir():
        return
    root = entries[0]
    for child in root.iterdir():
        shutil.move(str(child), str(target / child.name))
    root.rmdir()
