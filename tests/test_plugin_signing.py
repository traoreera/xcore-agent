"""Tests for plugin_signing.py — the port of xcore.kernel.security.signature's
HMAC algorithm that lets xcore-agent produce a plugin.sig the target host's
own strict_trusted check can verify. Self-contained (no dependency on a real
`xcore` install, which isn't part of this project's own test env) — the
port's exact byte-for-byte compatibility with the real algorithm was
verified manually against a real `xcore` install (Marketplace's own venv)
and is not re-checked here; these tests lock in this module's own behavior
against regressions instead.
"""

import hashlib
import hmac
import json
from pathlib import Path

import pytest

from xcore_agent.agent.plugin_signing import (
    SIG_FILENAME,
    compute_plugin_hmac,
    sign_installed_plugin,
)


def _write_plugin(root: Path, *, execution_mode: str = "trusted") -> Path:
    plugin_dir = root / "demo"
    (plugin_dir / "src").mkdir(parents=True)
    plugin_dir.joinpath("plugin.yaml").write_text(
        f"name: demo\nversion: 1.0.0\nexecution_mode: {execution_mode}\nentry_point: src/main.py\n"
    )
    (plugin_dir / "src" / "main.py").write_text("# demo\n")
    return plugin_dir


def test_sign_writes_plugin_sig_for_trusted_plugin(tmp_path):
    plugin_dir = _write_plugin(tmp_path)

    sig_path = sign_installed_plugin(plugin_dir, b"secret")

    assert sig_path == plugin_dir / SIG_FILENAME
    data = json.loads(sig_path.read_text())
    assert data["plugin"] == "demo"
    assert data["version"] == "1.0.0"
    assert data["algo"] == "HMAC-SHA256"
    assert len(data["digest"]) == 64  # sha256 hex digest


def test_sign_is_noop_for_non_trusted_plugin(tmp_path):
    plugin_dir = _write_plugin(tmp_path, execution_mode="sandboxed")

    result = sign_installed_plugin(plugin_dir, b"secret")

    assert result is None
    assert not (plugin_dir / SIG_FILENAME).exists()


def test_sign_is_noop_when_plugin_yaml_missing(tmp_path):
    # InstallDriver.install_plugin is reused for xservices' service.yaml-based
    # installs too (via marketplace_pipeline.py) — no plugin.yaml at all there.
    plugin_dir = tmp_path / "some_service"
    (plugin_dir / "src").mkdir(parents=True)
    (plugin_dir / "src" / "main.py").write_text("# service\n")

    result = sign_installed_plugin(plugin_dir, b"secret")

    assert result is None
    assert not (plugin_dir / SIG_FILENAME).exists()


def test_digest_changes_if_source_changes(tmp_path):
    plugin_dir = _write_plugin(tmp_path)
    digest_before = compute_plugin_hmac(plugin_dir, "src/main.py", b"secret")

    (plugin_dir / "src" / "main.py").write_text("# demo, but tampered\n")
    digest_after = compute_plugin_hmac(plugin_dir, "src/main.py", b"secret")

    assert digest_before != digest_after


def test_digest_changes_if_secret_changes(tmp_path):
    plugin_dir = _write_plugin(tmp_path)

    digest_a = compute_plugin_hmac(plugin_dir, "src/main.py", b"secret-a")
    digest_b = compute_plugin_hmac(plugin_dir, "src/main.py", b"secret-b")

    assert digest_a != digest_b


def test_digest_ignores_pycache_and_git(tmp_path):
    plugin_dir = _write_plugin(tmp_path)
    digest_before = compute_plugin_hmac(plugin_dir, "src/main.py", b"secret")

    (plugin_dir / "src" / "__pycache__").mkdir()
    (plugin_dir / "src" / "__pycache__" / "main.cpython-312.pyc").write_bytes(b"junk")
    (plugin_dir / ".git").mkdir()
    (plugin_dir / ".git" / "HEAD").write_text("ref: refs/heads/main\n")

    digest_after = compute_plugin_hmac(plugin_dir, "src/main.py", b"secret")

    assert digest_before == digest_after


def test_signature_manually_reverifiable_with_hmac_compare_digest(tmp_path):
    # Sanity-check the wire format itself (not just this module's own
    # round trip) — a signature written here must be independently
    # reproducible from raw hashlib/hmac, matching what a verifier with no
    # dependency on this module at all (e.g. xcore's own signature.py)
    # would compute.
    plugin_dir = _write_plugin(tmp_path)
    secret = b"secret"
    sign_installed_plugin(plugin_dir, secret)
    stored = json.loads((plugin_dir / SIG_FILENAME).read_text())["digest"]

    h = hmac.new(secret, digestmod=hashlib.sha256)
    h.update((plugin_dir / "plugin.yaml").read_bytes())
    h.update(b"src/main.py")
    h.update(b"\0")
    h.update((plugin_dir / "src" / "main.py").read_bytes())
    h.update(b"\0")

    assert hmac.compare_digest(h.hexdigest(), stored)


def test_missing_entry_point_source_dir_raises(tmp_path):
    plugin_dir = tmp_path / "demo"
    plugin_dir.mkdir()
    plugin_dir.joinpath("plugin.yaml").write_text(
        "name: demo\nversion: 1.0.0\nexecution_mode: trusted\nentry_point: src/main.py\n"
    )
    # No src/ directory at all.

    with pytest.raises(FileNotFoundError):
        sign_installed_plugin(plugin_dir, b"secret")
