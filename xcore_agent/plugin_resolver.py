"""Resolves a plugin's source code from a git repository, for plugins a
marketplace/registry references by link instead of embedding inside the
`.xdeploy` artifact (see `schema.manifest.PluginSource`).

Shared between the packer (which may resolve a plugin at build time to pin
its hash — not yet implemented, see the packer's docstring) and the agent
(which resolves at deploy time, verifying against any pinned hash).

Public vs. private repos are not distinguished by a flag: they're the same
`git` operation with different authentication, exactly like using `git`
directly from a shell —

- SSH URLs (`git@host:org/repo.git`) authenticate however the host's SSH
  agent/config already does; this module does nothing special for them.
- HTTPS URLs authenticate via a per-host token from `git_credentials`,
  spliced into the URL as `https://x-access-token:<token>@host/...` — the
  standard way to hand `git` a token non-interactively. No token configured
  for that host means the URL is used as-is (fine for a public repo, a
  clone failure otherwise).
"""

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from .schema.manifest import PluginSource


class PluginResolutionError(Exception):
    """Raised when a plugin's source cannot be fetched or is unusable
    (git failure, missing subdirectory, ...)."""


_RESOLVED_MARKER = ".xcore-resolved"


@dataclass
class PluginResolver:
    cache_root: Path
    git_credentials: dict[str, str] | None = None  # host -> token, HTTPS only

    def resolve(self, plugin_id: str, source: PluginSource) -> Path:
        """Return a local directory containing `plugin_id`'s code at
        `source.ref`, fetching it via `git` if not already cached.

        Caching is keyed on (plugin_id, ref): a commit SHA is immutable so
        this is safe to reuse indefinitely; a branch/tag ref will keep
        serving whatever commit it pointed to on first resolve within this
        cache_root — acceptable since callers pin to a commit SHA whenever
        integrity matters (see `PluginSource`'s docstring).
        """
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
