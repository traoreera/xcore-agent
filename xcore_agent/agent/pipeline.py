"""The end-to-end deployment pipeline:

authenticate -> request_artifact -> download -> verify_signature ->
obtain_key -> decrypt -> extract -> verify_manifest -> validate_project ->
resolve_sequence -> install -> healthcheck -> notify

Each stage is a small method on DeploymentRunner so tests can drive/inspect
the pipeline stage by stage. State transitions are enforced against
`state.TRANSITIONS` so a caller cannot skip a security-relevant stage (e.g.
installing before the artifact's signature has been verified) by accident.
"""

import shutil
import tarfile
from dataclasses import dataclass, field
from pathlib import Path

import yaml
import zstandard

from .. import crypto
from ..plugin_resolver import PluginResolver
from ..schema.install import (
    ConfigurePluginStep,
    HealthcheckStep,
    InstallExtensionStep,
    InstallPlan,
    InstallPluginStep,
    PrepareStep,
    ProvisionStep,
    RestartStep,
    StartStep,
    Step,
    StopStep,
    WriteEnvStep,
)
from ..schema.manifest import ProjectManifest
from .errors import ArtifactError, DeploymentError
from .hub_client import ArtifactLocation, DeploymentReport, HubClient, Session
from .install_driver import InstallDriver, Layout, Provisioner
from .state import TERMINAL_STATES, TRANSITIONS, DeploymentState

_MANIFEST_FILENAME = "manifest.json"
_INSTALL_PLAN_PATH = "deployment/install.yaml"


@dataclass(frozen=True)
class DeploymentCredentials:
    xdevkey: str
    project_id: str
    deployment_credential: str


@dataclass
class DeploymentRunner:
    hub: HubClient
    credentials: DeploymentCredentials
    version: str
    workdir: Path
    project_root: Path
    trusted_signer_public_key: bytes
    driver: InstallDriver | None = None
    plugin_resolver: PluginResolver | None = None
    provisioners: dict[str, Provisioner] | None = None
    # The target host's own `plugins.secret_key` (integration.yaml) — signs
    # any `execution_mode: trusted` plugin at install time so this host's
    # strict_trusted verification (xcore.kernel.security.signature) can
    # actually load it. None (default): no signing, matches today's
    # behavior. See install_driver.py/plugin_signing.py.
    plugin_secret_key: bytes | None = None

    state: DeploymentState = field(default=DeploymentState.PENDING, init=False)
    session: Session | None = field(default=None, init=False)
    manifest: ProjectManifest | None = field(default=None, init=False)
    install_plan: InstallPlan | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        if self.driver is None:
            self.driver = InstallDriver(
                Layout(
                    project_root=self.project_root,
                    extracted_root=self.workdir / "extracted",
                ),
                provisioners=self.provisioners,
                plugin_secret_key=self.plugin_secret_key,
            )

    def _transition(self, new_state: DeploymentState) -> None:
        allowed = TRANSITIONS[self.state]
        if new_state not in allowed:
            raise DeploymentError(
                f"illegal transition {self.state} -> {new_state} (allowed: {allowed})"
            )
        self.state = new_state

    async def run(self) -> DeploymentReport:
        try:
            await self._authenticate()
            location = await self._request_artifact()
            encrypted = await self._download(location)
            self._verify_signature(encrypted, location)
            dek = await self._obtain_key(location)
            compressed_tar = self._decrypt(encrypted, dek)
            self._extract(compressed_tar)
            self._verify_manifest()
            self._validate_project()
            self._resolve_plugins()
            order = self._resolve_sequence()
            self._install(order)
            self._healthcheck()
            report = await self._notify(status="success")
            self._transition(DeploymentState.SUCCEEDED)
            return report
        except DeploymentError:
            if self.state not in TERMINAL_STATES:
                self._transition(DeploymentState.FAILED)
            raise

    async def _authenticate(self) -> None:
        self._transition(DeploymentState.AUTHENTICATING)
        self.session = await self.hub.authenticate(
            xdevkey=self.credentials.xdevkey, project_id=self.credentials.project_id
        )

    async def _request_artifact(self) -> ArtifactLocation:
        self._transition(DeploymentState.REQUESTING_ARTIFACT)
        assert self.session is not None
        return await self.hub.request_artifact(self.session, version=self.version)

    async def _download(self, location: ArtifactLocation) -> bytes:
        self._transition(DeploymentState.DOWNLOADING)
        return await self.hub.download(location)

    def _verify_signature(self, encrypted: bytes, location: ArtifactLocation) -> None:
        self._transition(DeploymentState.VERIFYING_SIGNATURE)
        if location.signer_public_key != self.trusted_signer_public_key:
            raise ArtifactError("artifact signed by an untrusted key")
        try:
            crypto.verify_signature(
                public_key=location.signer_public_key,
                signature=location.signature,
                payload=encrypted,
            )
        except crypto.SignatureVerificationError as exc:
            raise ArtifactError(str(exc)) from exc

    async def _obtain_key(self, location: ArtifactLocation) -> bytes:
        self._transition(DeploymentState.OBTAINING_KEY)
        assert self.session is not None
        return await self.hub.obtain_deployment_key(
            self.session,
            deployment_credential=self.credentials.deployment_credential,
            artifact_signature=location.signature,
        )

    def _decrypt(self, encrypted: bytes, dek: bytes) -> bytes:
        self._transition(DeploymentState.DECRYPTING)
        # Wire format: 12-byte nonce prefix + AES-256-GCM ciphertext, whose
        # plaintext is a zstd-compressed tar (see packer.builder.seal_directory).
        nonce, ciphertext = encrypted[:12], encrypted[12:]
        try:
            return crypto.decrypt_aes_gcm(key=dek, nonce=nonce, ciphertext=ciphertext)
        except crypto.DecryptionError as exc:
            raise ArtifactError(str(exc)) from exc

    def _extract(self, compressed_tar: bytes) -> None:
        self._transition(DeploymentState.EXTRACTING)
        try:
            plaintext_tar = zstandard.ZstdDecompressor().decompress(compressed_tar)
        except zstandard.ZstdError as exc:
            raise ArtifactError(f"failed to decompress artifact: {exc}") from exc

        extracted_root = self.workdir / "extracted"
        extracted_root.mkdir(parents=True, exist_ok=True)
        archive_path = self.workdir / "artifact.tar"
        archive_path.write_bytes(plaintext_tar)
        with tarfile.open(archive_path, "r:") as tf:
            _safe_extract(tf, extracted_root)

    def _verify_manifest(self) -> None:
        self._transition(DeploymentState.VERIFYING_MANIFEST)
        extracted_root = self.workdir / "extracted"
        manifest_path = extracted_root / _MANIFEST_FILENAME
        if not manifest_path.is_file():
            raise ArtifactError(f"extracted artifact is missing {_MANIFEST_FILENAME}")
        self.manifest = ProjectManifest.model_validate_json(manifest_path.read_text())
        assert self.driver is not None
        self.driver.manifest = self.manifest

        actual = crypto.compute_tree_digest(extracted_root, exclude=frozenset({_MANIFEST_FILENAME}))
        if actual != self.manifest.content_sha256:
            raise ArtifactError(
                f"content hash mismatch: manifest declares {self.manifest.content_sha256}, "
                f"computed {actual} — artifact may have been tampered with"
            )

        install_path = extracted_root / _INSTALL_PLAN_PATH
        if not install_path.is_file():
            raise ArtifactError(f"extracted artifact is missing {_INSTALL_PLAN_PATH}")
        self.install_plan = InstallPlan.model_validate(yaml.safe_load(install_path.read_text()))

    def _validate_project(self) -> None:
        self._transition(DeploymentState.VALIDATING_PROJECT)
        assert self.manifest is not None and self.install_plan is not None
        if self.manifest.project_id != self.credentials.project_id:
            raise ArtifactError(
                f"artifact project_id {self.manifest.project_id!r} does not match "
                f"requested project {self.credentials.project_id!r}"
            )
        if self.install_plan.project_id != self.credentials.project_id:
            raise ArtifactError("install.yaml project_id does not match artifact manifest")
        if self.manifest.version != self.version:
            raise ArtifactError(
                f"artifact version {self.manifest.version!r} does not match "
                f"requested version {self.version!r}"
            )

    def _resolve_plugins(self) -> None:
        """Fetch any plugin OR extension the manifest references by `source`
        (a git repo, typically handed out by a marketplace/registry) rather
        than embeds, materializing it into `extracted_root/plugins/<id>/`
        (or `extracted_root/extensions/<id>/`) so `InstallDriver.
        install_plugin`/`install_extension` can treat every one the same
        way regardless of where its code actually came from. Both kinds
        share the RESOLVING_PLUGINS state — resolving an extension isn't
        security-relevant enough on its own to warrant a distinct state in
        the transition graph, and it's the same operation either way."""
        self._transition(DeploymentState.RESOLVING_PLUGINS)
        assert self.manifest is not None
        extracted_root = self.workdir / "extracted"

        for plugin in self.manifest.plugins:
            if plugin.source is None:
                continue
            if self.plugin_resolver is None:
                raise ArtifactError(
                    f"plugin {plugin.id!r} is resolved from {plugin.source.url!r} but no "
                    "plugin_resolver was configured for this deployment"
                )

            resolved = self.plugin_resolver.resolve(plugin.id, plugin.source)
            if plugin.sha256 is not None:
                actual = crypto.compute_tree_digest(resolved)
                if actual != plugin.sha256:
                    raise ArtifactError(
                        f"plugin {plugin.id!r}: resolved content hash mismatch "
                        f"(manifest declares {plugin.sha256}, computed {actual}) — "
                        f"{plugin.source.url}@{plugin.source.ref} does not match what was built"
                    )

            # Merge onto whatever's already extracted there — NOT a
            # replace-the-directory wipe, so build-time-only files with no
            # counterpart in the resolved repo (e.g. .env.template, absent
            # from a real plugin's own git history) survive untouched.
            #
            # But `shutil.copytree(..., dirs_exist_ok=True)` overwrites any
            # file the resolved repo DOES also ship — and a real plugin repo
            # always ships its own plugin.yaml (see e.g. auth/plugin.yaml:
            # execution_mode, permissions, resources — the actual runtime
            # privilege grant, not just name/version). So the resolved
            # repo's plugin.yaml deliberately wins over the thin build-time
            # stub in plugins/<id>/plugin.yaml (whose only required job is
            # declaring `source:` — see packer.builder._read_plugin_source).
            #
            # This is exactly why `sha256` pinning matters here: it's what
            # stops a mutable ref (a branch/tag, as opposed to a pinned
            # commit SHA) from silently changing what permissions/
            # execution_mode land on this host between builds — see
            # PluginSource's docstring, and note plugin.sha256 is OPTIONAL
            # for a source-based plugin, so an operator who never pins it
            # gets no protection against exactly that.
            target = extracted_root / "plugins" / plugin.id
            target.mkdir(parents=True, exist_ok=True)
            shutil.copytree(resolved, target, dirs_exist_ok=True)

        for extension in self.manifest.extensions:
            if extension.source is None:
                continue
            if self.plugin_resolver is None:
                raise ArtifactError(
                    f"extension {extension.id!r} is resolved from {extension.source.url!r} but "
                    "no plugin_resolver was configured for this deployment"
                )

            # Namespaced ("ext-<id>") so a plugin and an extension sharing
            # the same id (they install to different target directories —
            # see Layout.plugin_dir vs extension_dir) don't collide in
            # PluginResolver's cache, which is keyed on the id string alone.
            resolved = self.plugin_resolver.resolve(f"ext-{extension.id}", extension.source)
            if extension.sha256 is not None:
                actual = crypto.compute_tree_digest(resolved)
                if actual != extension.sha256:
                    raise ArtifactError(
                        f"extension {extension.id!r}: resolved content hash mismatch "
                        f"(manifest declares {extension.sha256}, computed {actual}) — "
                        f"{extension.source.url}@{extension.source.ref} does not match "
                        "what was built"
                    )

            target = extracted_root / "extensions" / extension.id
            target.mkdir(parents=True, exist_ok=True)
            shutil.copytree(resolved, target, dirs_exist_ok=True)

    def _resolve_sequence(self) -> list[str]:
        self._transition(DeploymentState.RESOLVING_SEQUENCE)
        assert self.install_plan is not None
        return self.install_plan.execution_order()

    def _install(self, order: list[str]) -> None:
        self._transition(DeploymentState.INSTALLING)
        assert self.install_plan is not None and self.driver is not None
        executed: list[str] = []
        try:
            for step_id in order:
                step = self.install_plan.step(step_id)
                self._dispatch(step)
                executed.append(step_id)
        except Exception as exc:
            self.driver.rollback()
            self._transition(DeploymentState.ROLLED_BACK)
            last = executed[-1] if executed else "<none>"
            raise DeploymentError(f"install failed at step {last!r}: {exc}") from exc

    def _dispatch(self, step: Step) -> None:
        assert self.driver is not None
        if isinstance(step, PrepareStep):
            self.project_root.mkdir(parents=True, exist_ok=True)
        elif isinstance(step, ProvisionStep):
            self.driver.provision(step)
        elif isinstance(step, InstallPluginStep):
            self.driver.install_plugin(step)
        elif isinstance(step, InstallExtensionStep):
            self.driver.install_extension(step)
        elif isinstance(step, ConfigurePluginStep):
            self.driver.configure_plugin(step)
        elif isinstance(step, WriteEnvStep):
            self.driver.write_env(step)
        elif isinstance(step, StartStep):
            self.driver.start(step)
        elif isinstance(step, StopStep):
            self.driver.stop(step)
        elif isinstance(step, RestartStep):
            self.driver.restart(step)
        elif isinstance(step, HealthcheckStep):
            self.driver.healthcheck(step)
        # DownloadStep / ExtractStep / RollbackStep: no-ops here. Download and
        # extract already happened as pipeline stages before install.yaml's
        # own steps run; rollback is driven by the runner on failure, never by
        # a step appearing mid-plan.

    def _healthcheck(self) -> None:
        self._transition(DeploymentState.HEALTHCHECKING)
        # Explicit `healthcheck` steps already ran inside _install(). This
        # stage exists in the state machine so a future project-wide check
        # (e.g. an aggregate /health across all installed plugins) has a
        # defined slot without reshaping the pipeline.

    async def _notify(self, *, status: str) -> DeploymentReport:
        self._transition(DeploymentState.NOTIFYING)
        assert self.session is not None and self.manifest is not None
        report = DeploymentReport(
            project_id=self.credentials.project_id,
            deployment_id="",  # assigned by the Hub once notify() has a real response shape
            status=status,
            version=self.version,
            started_at="",
            completed_at="",
            plugins=[p.model_dump() for p in self.manifest.plugins],
        )
        await self.hub.notify(self.session, report)
        return report


def _safe_extract(tf: tarfile.TarFile, dest: Path) -> None:
    """Extract a tar archive, rejecting any member that would escape `dest`
    via `../` or an absolute path. A decrypted, signature-verified artifact
    is still untrusted input as far as path handling is concerned."""
    dest_resolved = dest.resolve()
    for member in tf.getmembers():
        member_path = (dest_resolved / member.name).resolve()
        if not member_path.is_relative_to(dest_resolved):
            raise ArtifactError(f"artifact contains an unsafe path: {member.name!r}")
    tf.extractall(dest_resolved)  # noqa: S202 — membership already validated above
