"""Builds `.xdeploy` artifacts.

This is the build-side counterpart to `agent.pipeline.DeploymentRunner`,
which consumes exactly the format produced here: tar the project, zstd
-compress it, AES-256-GCM encrypt it, and sign the ciphertext with Ed25519.
Both sides call the same `crypto.compute_tree_digest` to produce and to
re-verify `manifest.json`'s `content_sha256`, so there is no protocol drift
between "what the packer hashed" and "what the agent re-hashes".
"""

import io
import json
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
from ..schema.install import InstallExtensionStep, InstallPlan, InstallPluginStep
from ..schema.manifest import (
    EnvironmentSpec,
    ExtensionRef,
    PluginRef,
    PluginSource,
    ProjectManifest,
)

MANIFEST_FILENAME = "manifest.json"
INSTALL_PLAN_PATH = "deployment/install.yaml"
# "extension.yaml" was this packer's original, generic name for an
# extension's own manifest — nothing in this ecosystem ever actually
# writes a file by that name; every real extension (xmailler, xwebsocket,
# extpubsub, ...) uses "service.yaml". Checked in this order (service.yaml
# first) so a project's real manifest always wins.
EXTENSION_MANIFEST_FILENAMES = ("service.yaml", "extension.yaml")

# Never copied into the packaging view, regardless of what a project's
# .dockerignore/.gitignore does or doesn't say — matched by basename
# (`shutil.ignore_patterns` semantics: fnmatch against each directory
# entry's name, at every depth). Two different concerns share this one
# list because both come from the same failure mode: `source_root` is a
# developer's real working tree, and `_prepare_packaging_view`'s
# `copytree` used to take it verbatim —
#
#  - dependency/VCS/cache dirs (`.venv`, `.git`, `node_modules`, __pycache__,
#    ...): irrelevant to a deployable artifact, but large enough to make a
#    build take minutes instead of seconds copying/hashing them for nothing.
#  - secret-shaped files (`.env`, private keys, local DB files): a real
#    private key + populated `.env` + sqlite DB were once copied into a
#    sealed `.xdeploy` artifact this way. `.env.template` is deliberately
#    NOT excluded — see `_check_env_template_present`, it's meant to ship.
#
# This is a backstop, not a substitute for keeping secrets out of
# source_root in the first place — an operator who commits a real key
# under a name this list doesn't recognize is still exposed.
_PACKAGING_EXCLUDE_PATTERNS = (
    ".venv",
    "venv",
    ".git",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "*.pyc",
    ".env",
    "*.pem",
    "*.key",
    "*.p12",
    "id_rsa",
    "id_ed25519",
    "*.db",
    "*.sqlite",
    "*.sqlite3",
)


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
    plan = _load_install_plan(source_root, project_id=project_id, version=version)
    _validate_source_tree(source_root, plan=plan, plugins_dirname=plugins_dirname)
    manifest = write_manifest(
        source_root,
        project_id=project_id,
        project_name=project_name,
        version=version,
        plugins_dirname=plugins_dirname,
        plan=plan,
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
    plan: InstallPlan | None = None,
) -> ProjectManifest:
    """Compute per-plugin and whole-tree content hashes and write
    `manifest.json` into `source_root`. Refuses to overwrite an existing one:
    the manifest is always generated fresh from the current tree, never
    hand-edited, so a leftover one is almost certainly stale.

    `plan` is `deployment/install.yaml`, already parsed — pass it when
    caller already has one (`build_artifact` does, from `_load_install_
    plan`) to avoid re-parsing; re-read from `source_root` here otherwise
    (e.g. a test calling `write_manifest` directly) if the file exists,
    falling back to no install-plan sources if it doesn't. Its steps'
    `source:` (see `InstallPluginStep`/`InstallExtensionStep`) is checked
    before a plugin's own plugin.yaml `source:` and the xcli-written
    registry — see `_install_plan_plugin_sources`'s docstring for why."""
    manifest_path = source_root / MANIFEST_FILENAME
    if manifest_path.exists():
        raise BuildError(
            f"{MANIFEST_FILENAME} already exists in {source_root} — remove it, "
            "the packer always regenerates it from the current tree"
        )

    if plan is None:
        install_path = source_root / INSTALL_PLAN_PATH
        if install_path.is_file():
            plan = InstallPlan.model_validate(yaml.safe_load(install_path.read_text()))
    plugin_sources = _install_plan_plugin_sources(plan)
    extension_sources = _install_plan_extension_sources(plan)

    # Files that will be pruned away by `_prepare_packaging_view` (source-
    # based plugins/extensions get reduced to just their manifest file) —
    # `content_sha256` below must exclude these too, since it's computed on
    # `source_root` before that pruning happens. See `_non_manifest_
    # relpaths`'s docstring for why this matters.
    pruned_relpaths: set[str] = set()

    plugins_dir = source_root / plugins_dirname
    plugin_refs = []
    for plugin_dir in sorted(p for p in plugins_dir.iterdir() if p.is_dir()):
        plugin_yaml = plugin_dir / "plugin.yaml"
        if not plugin_yaml.is_file():
            raise BuildError(f"plugin {plugin_dir.name!r} is missing plugin.yaml")
        source = (
            plugin_sources.get(plugin_dir.name)
            or _read_plugin_source(plugin_yaml)
            or _read_registry_source(plugin_dir)
        )
        if source is None:
            _check_env_template_present(plugin_yaml, plugin_dir)
        else:
            pruned_relpaths.update(
                _non_manifest_relpaths(plugin_dir, "plugin.yaml", source_root=source_root)
            )
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
            # A manifest file is optional — absent means "embedded, hash
            # the whole directory" (the original, still-default behavior);
            # a source resolved (install.yaml, the manifest's own
            # `source:`, or the registry — same priority and same shared
            # .xcore-registry.json as plugins above, see _read_registry_
            # source's docstring for why registry_dir=plugins_dir is
            # required here) means "resolved at deploy time, nothing to
            # hash here".
            ext_manifest_path = _find_extension_manifest(extension_dir)
            ext_source = (
                extension_sources.get(extension_dir.name)
                or (_read_extension_source(ext_manifest_path) if ext_manifest_path else None)
                or _read_registry_source(extension_dir, registry_dir=plugins_dir)
            )
            manifest_filename = (
                ext_manifest_path.name if ext_manifest_path else EXTENSION_MANIFEST_FILENAMES[0]
            )
            if ext_source is not None:
                pruned_relpaths.update(
                    _non_manifest_relpaths(
                        extension_dir, manifest_filename, source_root=source_root
                    )
                )
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

    content_sha256 = crypto.compute_tree_digest(
        source_root,
        exclude=frozenset({MANIFEST_FILENAME}) | pruned_relpaths,
        skip_patterns=_PACKAGING_EXCLUDE_PATTERNS,
    )

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

    # cryptography's own Rust-backed AESGCM.generate_key accepts bit_length
    # at runtime (verified — every build in this test suite calls this),
    # but its bundled type stub doesn't declare the kwarg, so mypy flags it
    # regardless of the installed cryptography version.
    dek = AESGCM.generate_key(bit_length=256)  # type: ignore[call-arg]
    nonce = secrets.token_bytes(12)
    ciphertext = nonce + AESGCM(dek).encrypt(nonce, compressed, None)

    key = signing_key or Ed25519PrivateKey.generate()
    signature = key.sign(ciphertext)
    signer_public_key = key.public_key().public_bytes_raw()

    return ciphertext, dek, signature, signer_public_key


def _load_install_plan(source_root: Path, *, project_id: str, version: str) -> InstallPlan:
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
    return plan


def _validate_source_tree(
    source_root: Path, *, plan: InstallPlan, plugins_dirname: str = "plugins"
) -> None:
    if not (source_root / "integration.yaml").is_file():
        raise BuildError("source tree is missing integration.yaml")

    plugins_dir = source_root / plugins_dirname
    if not plugins_dir.is_dir() or not any(plugins_dir.iterdir()):
        raise BuildError(f"source tree has no {plugins_dirname}/ directory (or it's empty)")

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


def _install_plan_plugin_sources(plan: InstallPlan | None) -> dict:
    """`{plugin_id: PluginSource}` for every `install_plugin` step that
    declares its own `source:` — see `InstallPluginStep.source`'s
    docstring for why this outranks plugin.yaml's own `source:` and the
    xcli-written registry (checked next, in `write_manifest`)."""
    if plan is None:
        return {}
    return {
        step.plugin: step.source
        for step in plan.steps
        if isinstance(step, InstallPluginStep) and step.source is not None
    }


def _install_plan_extension_sources(plan: InstallPlan | None) -> dict:
    """Mirrors `_install_plan_plugin_sources`, for `install_extension` steps."""
    if plan is None:
        return {}
    return {
        step.extension: step.source
        for step in plan.steps
        if isinstance(step, InstallExtensionStep) and step.source is not None
    }


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


def _check_env_template_present(plugin_yaml: Path, plugin_dir: Path) -> None:
    """If plugin.yaml declares `envconfiguration: {inject: true, env_file:
    <name>}`, the plugin's own docker-entrypoint (by convention across this
    ecosystem — see e.g. xauth/xdeploy/xdevkeys's plugin.yaml/.env.template)
    reconstructs `<name>` from a physically-present `<name>.template` at
    container startup. A plugin that declares `inject: true` but ships no
    template fails at deploy time with a ManifestError the operator can't
    see until a real host tries to start it — catch it here instead, at
    build time, where the operator is still looking at this exact repo.

    Only checked for embedded plugins: a `source:`-based plugin is resolved
    from git at deploy time (see `_read_plugin_source`), so there's nothing
    on disk here to check — the same reasoning `_read_plugin_source`'s
    caller already applies to sha256."""
    data = yaml.safe_load(plugin_yaml.read_text()) or {}
    envconfig = data.get("envconfiguration")
    if not isinstance(envconfig, dict) or not envconfig.get("inject"):
        return
    env_file = envconfig.get("env_file") or ".env"
    template_path = plugin_dir / f"{env_file}.template"
    if not template_path.is_file():
        raise BuildError(
            f"{plugin_yaml} declares envconfiguration.inject: true (env_file: "
            f"{env_file!r}) but {template_path.name} is missing from "
            f"{plugin_dir} — without it, the plugin fails to start on any "
            "host with a ManifestError. Add one (placeholders only, "
            "${VAR} per secret — see any other plugin in this ecosystem "
            "for the convention) or set envconfiguration.inject: false."
        )


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


def _read_registry_source(item_dir: Path, *, registry_dir: Path | None = None) -> PluginSource | None:
    """Fallback for a plugin/extension with no explicit `source:` in its own
    manifest: check `.xcore-registry.json`, written by `xcli plugin install
    --source marketplace|git` (and the equivalent `xcli service install`)
    — see xcoreCli's install_commands.py. Lets something installed that
    way get resolved from its real origin at deploy time automatically,
    without an operator hand-writing `source:` into its manifest (what this
    whole mechanism used to require — see the xauth/xmailler/etc. manifest
    edits that motivated this).

    `registry_dir` defaults to `item_dir.parent` — correct for a plugin,
    since the registry sits next to the plugins directory. An extension
    must pass `registry_dir=plugins_dir` explicitly: xcli's own
    `registry_path()` always writes ONE shared `.xcore-registry.json` next
    to the PLUGINS directory, regardless of whether the entry describes a
    plugin or an extension — `extension_dir.parent` (`extensions/`) would
    look in the wrong place and silently find nothing.

    Marketplace-primary, git-fallback — same rule as `PluginSource` itself:
    a 'marketplace' entry resolves via `slug`/`kind`/`version` (the
    marketplace stays the authoritative origin even though the registry
    also records the `X-Repo` GitHub coordinates as a courtesy), a 'git'
    entry resolves via `repository`/`ref` because that IS its only origin
    (never installed from the marketplace, i.e. `--source git`). Anything
    else (a local zip install, a partial/failed registry write, an entry
    missing what its own source kind requires) falls through to the safe
    default: embed the actual files instead of guessing at a source."""
    registry_path = (registry_dir or item_dir.parent) / ".xcore-registry.json"
    if not registry_path.is_file():
        return None
    try:
        registry = json.loads(registry_path.read_text())
    except (OSError, ValueError):
        return None
    entry = registry.get(item_dir.name)
    if not isinstance(entry, dict):
        return None

    if entry.get("source") == "marketplace":
        slug = entry.get("slug")
        if not slug:
            return None
        # xcli's registry vocabulary isn't the same as PluginSource's:
        # `xcli service install` records "kind": "extension" (matching its
        # own `plugin`/`extension` split), but PluginSource.marketplace_kind
        # is Literal["plugin", "service"] — "extension" isn't a valid value
        # there. Without this translation, every marketplace-sourced
        # extension's PluginSource(...) construction below raised (caught
        # by the blanket except, so silently) and fell through to "embed
        # the actual files", exactly the bug this whole fallback exists to
        # avoid.
        kind = entry.get("kind") or "plugin"
        if kind == "extension":
            kind = "service"
        try:
            return PluginSource(
                marketplace_slug=slug,
                marketplace_version=entry.get("version") or "latest",
                marketplace_kind=kind,
            )
        except Exception:
            return None

    if entry.get("source") == "git":
        repository, ref = entry.get("repository"), entry.get("ref")
        if not repository or not ref:
            return None
        try:
            return PluginSource(url=repository, ref=ref)
        except Exception:
            return None

    return None


def _find_extension_manifest(extension_dir: Path) -> Path | None:
    """Locate an extension's own manifest file, trying each name in
    EXTENSION_MANIFEST_FILENAMES in order (service.yaml first — the only
    one anything in this ecosystem actually writes). None means "embedded,
    no manifest at all", same as a missing extension.yaml used to mean
    before service.yaml support existed."""
    for name in EXTENSION_MANIFEST_FILENAMES:
        candidate = extension_dir / name
        if candidate.is_file():
            return candidate
    return None


def _read_extension_source(extension_yaml: Path) -> PluginSource | None:
    """Same as `_read_plugin_source`, but the manifest itself is optional
    (an embedded extension needs no manifest file at all — unlike a
    plugin, which always needs plugin.yaml for version/execution_mode/...).
    Caller resolves which manifest filename to look at via
    _find_extension_manifest; this just reads whatever path it's given."""
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
    """Copy `source_root` into `packaging_root` (skipping anything in
    `_PACKAGING_EXCLUDE_PATTERNS`), then prune every `source`-based
    plugin/extension down to just its manifest file — see `build_artifact`'s
    docstring for why. `source_root` itself is never touched."""
    shutil.copytree(
        source_root, packaging_root, ignore=shutil.ignore_patterns(*_PACKAGING_EXCLUDE_PATTERNS)
    )

    for plugin in manifest.plugins:
        if plugin.source is not None:
            _prune_to_manifest_only(
                packaging_root / manifest.plugins_dirname / plugin.id, "plugin.yaml"
            )

    for extension in manifest.extensions:
        if extension.source is not None:
            ext_dir = packaging_root / "extensions" / extension.id
            # Re-detect which manifest filename this extension actually
            # uses (service.yaml in practice) — packaging_root is a fresh,
            # unpruned copy of source_root at this point, so the file is
            # still there to find. Pruning to the WRONG hardcoded name
            # would delete the real manifest and keep nothing.
            ext_manifest_path = _find_extension_manifest(ext_dir)
            _prune_to_manifest_only(
                ext_dir,
                ext_manifest_path.name if ext_manifest_path else EXTENSION_MANIFEST_FILENAMES[0],
            )


def _survives_pruning(name: str, manifest_filename: str) -> bool:
    """Whether a top-level file in a source-based plugin/extension
    directory survives `_prune_to_manifest_only` — its own manifest file,
    or a `*.template` (e.g. `.env.template`): a build-time-only file with
    no counterpart in the resolved repo, meant to ship as-is so `write_env`
    (and the operator, before the real code is even fetched) has something
    to seed/inspect — see `agent.pipeline._resolve_plugins`'s docstring on
    why a resolved repo's own files must not clobber it, and `_check_env_
    template_present` for the embedded-plugin equivalent of this same
    convention. Shared by `_prune_to_manifest_only` (deletes) and
    `_non_manifest_relpaths` (lists, for content_sha256's exclude set) so
    the two can never disagree about what actually gets sealed."""
    return name == manifest_filename or name.endswith(".template")


def _prune_to_manifest_only(directory: Path, manifest_filename: str) -> None:
    # Top-level children only (not the recursive file listing `_non_
    # manifest_relpaths` computes for content_sha256's exclude set) — an
    # rmtree on a top-level directory already removes everything nested
    # under it in one call.
    for child in directory.iterdir():
        if _survives_pruning(child.name, manifest_filename):
            continue
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()


def _non_manifest_relpaths(
    directory: Path, manifest_filename: str, *, source_root: Path
) -> set[str]:
    """Every FILE under a source-based plugin/extension `directory` that
    `_prune_to_manifest_only` would delete (i.e. not `_survives_pruning`),
    as paths relative to `source_root`. `content_sha256` (write_manifest,
    computed on `source_root` BEFORE that pruning happens) must exclude
    these too, or it describes a tree containing files that will never
    actually be inside the sealed artifact — e.g. an extension whose
    `source_root` directory still has its original embedded code sitting
    next to (now unused) since a `source:` was added for it: real, hit in
    production the first time an extension had leftover code where
    `source:` said to resolve it elsewhere instead — see write_manifest's
    call site. Only top-level `*.template` files survive pruning (matching
    `_survives_pruning`), so a nested one (unlikely, but possible) is still
    excluded here like any other non-manifest file."""
    return {
        p.relative_to(source_root).as_posix()
        for p in directory.rglob("*")
        if p.is_file()
        and not (p.parent == directory and _survives_pruning(p.name, manifest_filename))
    }


def _tar_bytes(root: Path) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        tf.add(root, arcname=".")
    return buf.getvalue()
