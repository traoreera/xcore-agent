"""Signs an installed plugin so the target XCore host's own runtime can
verify it — `xcore.kernel.security.signature.verify_plugin`, gated by
`strict_trusted: true` under `plugins:` in that host's `integration.yaml`
(secret: `plugins.secret_key`, e.g. `${PLUGIN_SECRET}`/`${SECRET_KEY}`
depending on the project's own env var naming).

This is a *separate, complementary* trust layer from everything else in
this package: `.xdeploy`'s Ed25519 artifact signature and the marketplace's
HMAC-signed ZIP both prove "this artifact is what the Hub/marketplace
actually built and served" — neither says anything about what happens
*after* extraction. A `source`-based plugin's own `plugin.yaml` (which wins
over the build-time stub — see pipeline.py's `_resolve_plugins`) decides
its `execution_mode`/`permissions` at deploy time, and `PluginRef.sha256`
pinning is optional. `strict_trusted` + `plugin.sig` is the target host's
own last line of defense: it refuses to *load* a `trusted`-mode plugin at
all unless a valid signature — computed with a secret only that host
knows — is sitting right next to its `plugin.yaml`. xcore-agent produces
that signature at install time (not embedded at build time) because the
secret is host-local, potentially different per deployment target, and
must never travel inside the artifact — same principle as `.env` handling
in `install_driver.py`'s `Layout` docstring.

The HMAC algorithm below MUST stay byte-for-byte identical to
`xcore/kernel/security/signature.py` (and its duplicate,
`Marketplace/sign_plugins.py`) — a signature computed here has to verify
under that exact code. Keep changes to `SECURITY_IGNORE`/`_compute_hmac` in
sync across all three if the upstream algorithm ever changes.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

import yaml

SIG_FILENAME = "plugin.sig"

SECURITY_IGNORE = {
    "__pycache__",
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    "*.md",
    "*.json",
    "plugin.sig",
    "plugin.yaml",
    "plugin.json",
}


def _should_ignore(path: Path, root: Path) -> bool:
    rel = path.relative_to(root)
    if any(part in SECURITY_IGNORE for part in rel.parts) or path.name in SECURITY_IGNORE:
        return True
    if path.suffix in {".pyc", ".pyo"}:
        return True
    if path.is_symlink():
        return True
    return False


def compute_plugin_hmac(plugin_dir: Path, entry_point: str, secret_key: bytes) -> str:
    """HMAC-SHA256 over the manifest (plugin.yaml/plugin.json) then every
    file under the entry point's source directory — identical algorithm to
    `xcore.kernel.security.signature._compute_hmac`, just reading
    `entry_point`/paths directly instead of through a PluginManifest."""
    root = plugin_dir.resolve()
    h = hmac.new(secret_key, digestmod=hashlib.sha256)

    for fname in ("plugin.yaml", "plugin.json"):
        p = root / fname
        if p.exists():
            h.update(p.read_bytes())
            break

    src_dir = (root / Path(entry_point).parent).resolve()
    if not src_dir.exists():
        raise FileNotFoundError(f"source directory {src_dir} not found under {root}")
    if not src_dir.is_relative_to(root):
        raise ValueError(f"source directory {src_dir} is outside the plugin directory")

    files = sorted(p for p in src_dir.rglob("*") if p.is_file() and not _should_ignore(p, root))
    for path in files:
        rel = path.relative_to(root).as_posix()
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        with open(path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        h.update(b"\0")

    return h.hexdigest()


def sign_installed_plugin(plugin_dir: Path, secret_key: bytes) -> Path | None:
    """Write `plugin_dir/plugin.sig` if `plugin.yaml` declares
    `execution_mode: trusted` — mirrors `sign_plugins.py`'s own check, since
    `strict_trusted` at load time only ever verifies trusted-mode plugins
    (see agent/pipeline.py's plugin_signing note in _dispatch). Returns the
    written path, or None if there's nothing to sign — no `plugin.yaml` at
    all (this InstallDriver is reused for `xservices`' `service.yaml`-based
    installs too, via marketplace_pipeline.py, which have no `execution_mode`
    concept) or `execution_mode` isn't `trusted`. Both are no-ops, not
    errors — most installs hit one of them."""
    plugin_yaml = plugin_dir / "plugin.yaml"
    if not plugin_yaml.is_file():
        return None
    data = yaml.safe_load(plugin_yaml.read_text()) or {}
    if data.get("execution_mode") != "trusted":
        return None

    name = data.get("name", plugin_dir.name)
    version = data.get("version", "0.0.0")
    entry_point = data.get("entry_point", "src/main.py")

    digest = compute_plugin_hmac(plugin_dir, entry_point, secret_key)

    sig_path = plugin_dir / SIG_FILENAME
    sig_path.write_text(
        json.dumps(
            {"plugin": name, "version": version, "digest": digest, "algo": "HMAC-SHA256"}, indent=2
        )
    )
    return sig_path
