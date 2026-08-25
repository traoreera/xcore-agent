"""Cryptographic primitives used by the deployment pipeline.

Key custody model: xcore-agent never generates or stores long-lived secrets.
The artifact's per-version data-encryption key (DEK) is obtained at deploy
time from XCore Hub (see `agent.hub_client.HubClient.obtain_deployment_key`)
and kept only in memory for the duration of one deployment.
"""

import fnmatch
import hashlib
import hmac as _hmac
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SignatureVerificationError(Exception):
    """Raised when an artifact's Ed25519 signature does not match its content."""


def verify_hmac_sha256_hex(*, secret: bytes, signature_hex: str, payload: bytes) -> None:
    """Verify a `hmac_sha256:<hex>`-style signature (the real XCore Marketplace's
    install endpoint — see MarketplaceClient) over `payload`.

    This is a *symmetric* check: unlike `verify_signature` (Ed25519), whoever
    holds `secret` can also forge a signature. Authenticity therefore rests on
    the operator having obtained `secret` through a channel they trust (it's
    the plugin developer's own xdevkeys signing secret), not on public-key
    cryptography — see the "Key custody model" note in the README.
    """
    prefix = "hmac_sha256:"
    if not signature_hex.startswith(prefix):
        raise SignatureVerificationError(f"unrecognized signature format: {signature_hex[:20]!r}")
    expected = _hmac.new(secret, payload, hashlib.sha256).hexdigest()
    actual = signature_hex[len(prefix) :]
    if not _hmac.compare_digest(expected, actual):
        raise SignatureVerificationError("artifact HMAC signature verification failed")


class DecryptionError(Exception):
    """Raised when AES-GCM decryption/authentication fails."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_signature(*, public_key: bytes, signature: bytes, payload: bytes) -> None:
    """Verify an Ed25519 signature over `payload`.

    Raises SignatureVerificationError on any mismatch; never returns a falsy
    "invalid" value, so a caller cannot accidentally ignore the result.
    """
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
    except InvalidSignature as exc:
        raise SignatureVerificationError("artifact signature verification failed") from exc


def decrypt_aes_gcm(
    *, key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes | None = None
) -> bytes:
    """Decrypt+authenticate an AES-256-GCM ciphertext.

    `key` must be the artifact's per-version DEK (32 bytes), already unwrapped
    by the Hub — xcore-agent never derives or stores it itself.
    """
    if len(key) != 32:
        raise DecryptionError(f"expected a 32-byte AES-256 key, got {len(key)} bytes")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
    except Exception as exc:  # AESGCM raises InvalidTag on any auth/format failure
        raise DecryptionError(
            "artifact decryption failed (bad key or tampered ciphertext)"
        ) from exc


def compute_tree_digest(
    root: Path,
    *,
    exclude: frozenset[str] = frozenset(),
    skip_patterns: tuple[str, ...] = (),
) -> str:
    """Deterministic digest of every file under `root`, as sha256("relpath:sha256\\n"...).

    Used both to produce `manifest.json`'s `content_sha256` at build time and,
    here, to re-verify it after extraction. Hashing individual files instead
    of the whole tar means a single tampered file can be pinpointed, and it
    sidesteps the circular problem of a manifest hashing a tarball that
    contains that same manifest (and therefore its own hash) — `manifest.json`
    itself must always be passed in `exclude`.

    `exclude` matches a file's full relative path exactly (what `manifest.json`
    needs). `skip_patterns` matches by glob against every path *component*
    (same semantics as `shutil.ignore_patterns`) — for `packer.builder`
    passing its `_PACKAGING_EXCLUDE_PATTERNS`, so this digest is computed
    over the same tree `_prepare_packaging_view` actually seals (`.venv`,
    `.env`, ... never make it into the packaging view, so they must not
    silently count toward `content_sha256` either — otherwise the manifest
    would describe a tree that isn't the one inside the artifact).
    """
    entries = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel_path = path.relative_to(root)
        rel = rel_path.as_posix()
        if rel in exclude:
            continue
        if skip_patterns and any(
            fnmatch.fnmatch(part, pattern) for part in rel_path.parts for pattern in skip_patterns
        ):
            continue
        entries.append(f"{rel}:{sha256_hex(path.read_bytes())}")
    return hashlib.sha256("\n".join(entries).encode("utf-8")).hexdigest()
