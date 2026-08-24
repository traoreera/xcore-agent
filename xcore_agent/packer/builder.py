"""Builds `.xdeploy` artifacts.

This is the build-side counterpart to `agent.pipeline.DeploymentRunner`,
which consumes exactly the format produced here: tar the project, zstd
-compress it, AES-256-GCM encrypt it, and sign the ciphertext with Ed25519.
Both sides call the same `crypto.compute_tree_digest` to produce and to
re-verify `manifest.json`'s `content_sha256`, so there is no protocol drift
between "what the packer hashed" and "what the agent re-hashes".
"""

import io
import secrets
import shutil
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml
import zstandard
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .. import crypto
from ..schema.install import InstallPlan
from ..schema.manifest import (
    EnvironmentSpec,
    ExtensionRef,
    PluginRef,
    PluginSource,
    ProjectManifest,
)

MANIFEST_FILENAME = "manifest.json"
INSTALL_PLAN_PATH = "deployment/install.yaml"
EXTENSION_MANIFEST_FILENAME = "extension.yaml"


class BuildError(Exception):
    """Raised when a source tree cannot be turned into a valid .xdeploy artifact."""


@dataclass(frozen=True)
class BuildResult:
    output_path: Path
    manifest: ProjectManifest
    # Per-artifact DEK. The packer generates it but never stores it — the
    # caller (a future build-engine talking to XCore Hub) is responsible for
    # handing it to the Hub for KEK-wrapped storage.
    dek: bytes
    signature: bytes
    signer_public_key: bytes


def _read_plugins_dirname(source_root: Path) -> str:
    """Read `plugins.directory` from the project's own `integration.yaml`
    (e.g. `plugins:\n  directory: ./app`), so a project that doesn't use
    the `plugins/` convention — like this repo, which loads plugins from
    `app/` — still builds correctly instead of failing with "no plugins/
    directory". Falls back to "plugins" (the prior hardcoded behavior) if
    integration.yaml is missing, unreadable, or doesn't set it — every
    project built before this existed keeps working unchanged. The
    resolved name is recorded on the manifest as `plugins_dirname` so the
    deploy side (agent/pipeline.py, agent/install_driver.py) reads back the
    same convention instead of re-guessing "plugins"."""
    integration_yaml = source_root / "integration.yaml"
    if not integration_yaml.is_file():
        return "plugins"
    try:
        data = yaml.safe_load(integration_yaml.read_text()) or {}
    except yaml.YAMLError:
        return "plugins"
    raw = data.get("plugins") if isinstance(data, dict) else None
    directory = raw.get("directory") if isinstance(raw, dict) else None
    if not isinstance(directory, str) or not directory.strip():
        return "plugins"
    # Conventionally written relative to source_root, e.g. "./app" — strip
    # that down to a plain directory name/path so it composes the same way
    # as the "plugins" default everywhere it's used below.
    return directory.strip().removeprefix("./").strip("/") or "plugins"


def build_artifact(
    source_root: Path,
    *,
    project_id: str,
    project_name: str,
    version: str,
    output_path: Path,
    signing_key: Ed25519PrivateKey | None = None,
) -> BuildResult:
    """Build, encrypt, and sign a `.xdeploy` artifact from `source_root`.

    `source_root` must already contain a plugins directory (`plugins/` by
    default — see `_read_plugins_dirname` for how a project overrides that
    via `integration.yaml`'s `plugins.directory`), `integration.yaml`, and
    `deployment/install.yaml`. This writes `manifest.json` into it (and
    refuses to run if one is already there — see `write_manifest`). Pass
    `signing_key` to sign with a specific, persisted Hub key; a fresh
    throwaway one is generated and returned otherwise.

    A plugin/extension whose manifest declares `source:` gets pruned down
    to just its manifest file (`plugin.yaml`/`extension.yaml`) before
    sealing — even if the operator's local `source_root` happens to have
    the real code checked out at that path too (e.g. because they cloned it
    to poke around, or a prior embedded build left it there). It's
    resolved from git at deploy time (see `plugin_resolver.py` and
    `agent.pipeline`'s `_resolve_plugins`/`_resolve_extensions`), so
    embedding it here would only bloat the artifact with a copy nothing
    ever reads back out of it. `source_root` itself is never mutated —
    pruning happens on a temporary copy that gets sealed and discarded.
    """
    plugins_dirname = _read_plugins_dirname(source_root)
    _validate_source_tree(
        source_root, project_id=project_id, version=version, plugins_dirname=plugins_dirname
    )
    manifest = write_manifest(
        source_root,
        project_id=project_id,
        project_name=project_name,
        version=version,
        plugins_dirname=plugins_dirname,
    )
    with tempfile.TemporaryDirectory(prefix="xcore-agent-pack-") as tmp:
        packaging_root = Path(tmp) / "package"
        _prepare_packaging_view(source_root, packaging_root, manifest)
        ciphertext, dek, signature, signer_public_key = seal_directory(
            packaging_root, signing_key=signing_key
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(ciphertext)

    return BuildResult(
        output_path=output_path,
        manifest=manifest,
        dek=dek,
        signature=signature,
        signer_public_key=signer_public_key,
    )


def write_manifest(
    source_root: Path,
    *,
    project_id: str,
    project_name: str,
    version: str,
    plugins_dirname: str = "plugins",
) -> ProjectManifest:
    """Compute per-plugin and whole-tree content hashes and write
    `manifest.json` into `source_root`. Refuses to overwrite an existing one:
    the manifest is always generated fresh from the current tree, never
    hand-edited, so a leftover one is almost certainly stale."""
    manifest_path = source_root / MANIFEST_FILENAME
    if manifest_path.exists():
        raise BuildError(
            f"{MANIFEST_FILENAME} already exists in {source_root} — remove it, "
            "the packer always regenerates it from the current tree"
        )

    plugins_dir = source_root / plugins_dirname
    plugin_refs = []
    for plugin_dir in sorted(p for p in plugins_dir.iterdir() if p.is_dir()):
        plugin_yaml = plugin_dir / "plugin.yaml"
        if not plugin_yaml.is_file():
            raise BuildError(f"plugin {plugin_dir.name!r} is missing plugin.yaml")
        source = _read_plugin_source(plugin_yaml)
        plugin_refs.append(
            PluginRef(
                id=plugin_dir.name,
                version=_read_plugin_version(plugin_yaml),
                # A source-based plugin's code isn't necessarily embedded
                # here (it may be resolved from git at deploy time — see
                # plugin_resolver.py), so there's nothing to hash at build
                # time. An embedded plugin is always hashed: sha256 is what
                # the agent re-verifies post-extraction.
                sha256=None if source is not None else crypto.compute_tree_digest(plugin_dir),
                environment=_read_plugin_environment(plugin_yaml),
                source=source,
            )
        )
    if not plugin_refs:
        raise BuildError(f"no plugins found under {plugins_dirname}/")

    extension_refs = []
    extensions_dir = source_root / "extensions"
    if extensions_dir.is_dir():
        for extension_dir in sorted(p for p in extensions_dir.iterdir() if p.is_dir()):
            # extension.yaml is optional — absent means "embedded, hash the
            # whole directory" (the original, still-default behavior);
            # present with a `source:` block means "resolved from git at
            # deploy time, nothing to hash here" — see _read_extension_source.
            ext_source = _read_extension_source(extension_dir / EXTENSION_MANIFEST_FILENAME)
            extension_refs.append(
                ExtensionRef(
                    id=extension_dir.name,
                    sha256=(
                        None
                        if ext_source is not None
                        else crypto.compute_tree_digest(extension_dir)
                    ),
                    source=ext_source,
                )
            )

    content_sha256 = crypto.compute_tree_digest(source_root, exclude=frozenset({MANIFEST_FILENAME}))

    manifest = ProjectManifest(
        format_version="1",
        project_id=project_id,
        project_name=project_name,
        version=version,
        built_at=datetime.now(timezone.utc),
        plugins=plugin_refs,
        extensions=extension_refs,
        plugins_dirname=plugins_dirname,
        content_sha256=content_sha256,
    )
    manifest_path.write_text(manifest.model_dump_json())
    return manifest


def seal_directory(
    source_root: Path, *, signing_key: Ed25519PrivateKey | None = None
) -> tuple[bytes, bytes, bytes, bytes]:
    """Tar, zstd-compress, AES-256-GCM encrypt, and Ed25519-sign
    `source_root` as-is. Pure packaging — does not touch or require
    `manifest.json`, so it can also be used to build a deliberately
    tampered artifact for tests.

    Returns (ciphertext, dek, signature, signer_public_key). `ciphertext` is
    a 12-byte nonce prefix followed by the AES-256-GCM ciphertext, matching
    what `agent.pipeline.DeploymentRunner._decrypt` expects.
    """
    plaintext_tar = _tar_bytes(source_root)
    compressed = zstandard.ZstdCompressor(level=19).compress(plaintext_tar)

    dek = AESGCM.generate_key(bit_length=256)
    nonce = secrets.token_bytes(12)
    ciphertext = nonce + AESGCM(dek).encrypt(nonce, compressed, None)

    key = signing_key or Ed25519PrivateKey.generate()
    signature = key.sign(ciphertext)
    signer_public_key = key.public_key().public_bytes_raw()

    return ciphertext, dek, signature, signer_public_key


def _validate_source_tree(
    source_root: Path, *, project_id: str, version: str, plugins_dirname: str = "plugins"
) -> None:
    if not (source_root / "integration.yaml").is_file():
        raise BuildError("source tree is missing integration.yaml")

    plugins_dir = source_root / plugins_dirname
    if not plugins_dir.is_dir() or not any(plugins_dir.iterdir()):
        raise BuildError(f"source tree has no {plugins_dirname}/ directory (or it's empty)")

    install_path = source_root / INSTALL_PLAN_PATH
    if not install_path.is_file():
        raise BuildError(f"source tree is missing {INSTALL_PLAN_PATH}")

    plan = InstallPlan.model_validate(yaml.safe_load(install_path.read_text()))
    if plan.project_id != project_id:
        raise BuildError(
            f"install.yaml project_id {plan.project_id!r} does not match requested {project_id!r}"
        )
    if plan.version != version:
        raise BuildError(
            f"install.yaml version {plan.version!r} does not match requested {version!r}"
        )

    extensions_dir = source_root / "extensions"
    for step in plan.steps:
        plugin_id = getattr(step, "plugin", None)
        if plugin_id and not (plugins_dir / plugin_id).is_dir():
            raise BuildError(
                f"install.yaml step {step.id!r} references plugin {plugin_id!r} "
                f"but {plugins_dirname}/{plugin_id}/ is missing"
            )
        extension_id = getattr(step, "extension", None)
        if extension_id and not (extensions_dir / extension_id).is_dir():
            raise BuildError(
                f"install.yaml step {step.id!r} references extension {extension_id!r} "
                f"but extensions/{extension_id}/ is missing"
            )


def _read_plugin_version(plugin_yaml: Path) -> str:
    data = yaml.safe_load(plugin_yaml.read_text()) or {}
    version = data.get("version")
    if not isinstance(version, str):
        raise BuildError(f"{plugin_yaml} is missing a string 'version' field")
    return version


def _read_plugin_environment(plugin_yaml: Path) -> EnvironmentSpec | None:
    """Read the optional `environment: {required: [...], optional: [...]}`
    block from plugin.yaml, so `write_env` can validate it's satisfied on
    the target host before considering the plugin installed."""
    data = yaml.safe_load(plugin_yaml.read_text()) or {}
    raw = data.get("environment")
    if raw is None:
        return None
    try:
        return EnvironmentSpec.model_validate(raw)
    except Exception as exc:
        raise BuildError(f"{plugin_yaml} has an invalid 'environment' block: {exc}") from exc


def _read_plugin_source(plugin_yaml: Path) -> PluginSource | None:
    """Read the optional `source: {url, ref, subdirectory}` block from
    plugin.yaml. Its presence is what makes a plugin resolved from git at
    deploy time instead of embedded in the artifact."""
    data = yaml.safe_load(plugin_yaml.read_text()) or {}
    raw = data.get("source")
    if raw is None:
        return None
    try:
        return PluginSource.model_validate(raw)
    except Exception as exc:
        raise BuildError(f"{plugin_yaml} has an invalid 'source' block: {exc}") from exc


def _read_extension_source(extension_yaml: Path) -> PluginSource | None:
    """Same as `_read_plugin_source`, but `extension.yaml` itself is
    optional (an embedded extension needs no manifest file at all — unlike
    a plugin, which always needs plugin.yaml for version/execution_mode/...)."""
    if not extension_yaml.is_file():
        return None
    data = yaml.safe_load(extension_yaml.read_text()) or {}
    raw = data.get("source")
    if raw is None:
        return None
    try:
        return PluginSource.model_validate(raw)
    except Exception as exc:
        raise BuildError(f"{extension_yaml} has an invalid 'source' block: {exc}") from exc


def _prepare_packaging_view(
    source_root: Path, packaging_root: Path, manifest: ProjectManifest
) -> None:
    """Copy `source_root` into `packaging_root`, then prune every
    `source`-based plugin/extension down to just its manifest file — see
    `build_artifact`'s docstring for why. `source_root` itself is never
    touched."""
    shutil.copytree(source_root, packaging_root)

    for plugin in manifest.plugins:
        if plugin.source is not None:
            _prune_to_manifest_only(
                packaging_root / manifest.plugins_dirname / plugin.id, "plugin.yaml"
            )

    for extension in manifest.extensions:
        if extension.source is not None:
            _prune_to_manifest_only(
                packaging_root / "extensions" / extension.id, EXTENSION_MANIFEST_FILENAME
            )


def _prune_to_manifest_only(directory: Path, manifest_filename: str) -> None:
    for child in directory.iterdir():
        if child.name == manifest_filename:
            continue
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()


def _tar_bytes(root: Path) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        tf.add(root, arcname=".")
    return buf.getvalue()
