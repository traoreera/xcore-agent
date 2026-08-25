"""Deployment pipeline for the *real* xcore-team/marketplace contract.

Structurally different from `pipeline.DeploymentRunner` (see
`marketplace_client`'s module docstring for why this isn't just a new
`HubClient` implementation):

  - No auth exchange: the API key is sent on every request.
  - No DEK/decrypt step: the fetched ZIP is plaintext (Marketplace-side
    the ZIP is HMAC-signed, not encrypted).
  - No manifest.json / install.yaml *inside* the artifact — a plain GitHub
    zipball has neither. The install plan is supplied by the operator from
    their own trusted host, the same way `provisioners` already are (see
    `install_driver`'s docstring on provisioning) — the Marketplace only
    ever hands back one plugin's source code, never deployment orchestration.
  - Deployment status is both written locally (JSON, always) and reported
    to the Hub (`POST /deployments/report`, best-effort — see
    `MarketplaceClient.report_deployment`'s docstring for why a reporting
    failure never fails the deployment itself).
"""

import json
import logging
import shutil
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .. import crypto
from ..packer.builder import _read_plugins_dirname
from ..plugin_resolver import PluginResolutionError, flatten_single_root, safe_extract_zip
from ..schema.install import (
    ConfigurePluginStep,
    HealthcheckStep,
    InstallExtensionStep,
    InstallPlan,
    InstallPluginStep,
    NotifyStep,
    PrepareStep,
    ProvisionStep,
    RestartStep,
    StartStep,
    Step,
    StopStep,
    WriteEnvStep,
)
from .errors import ArtifactError, DeploymentError
from .install_driver import InstallDriver, Layout, Notifier, Provisioner
from .marketplace_client import FetchedArtifact, Kind, MarketplaceClient
from .marketplace_state import (
    MARKETPLACE_TERMINAL_STATES,
    MARKETPLACE_TRANSITIONS,
    MarketplaceDeploymentState,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MarketplaceDeploymentReport:
    slug: str
    kind: Kind
    status: str  # "success" | "failed" | "rolled_back"
    requested_version: str
    resolved_version: str
    repo: str
    started_at: str
    completed_at: str
    error_message: str = ""


@dataclass
class MarketplaceDeploymentRunner:
    client: MarketplaceClient
    slug: str
    workdir: Path
    project_root: Path
    trusted_signer_secret: bytes
    install_plan_path: Path
    version: str = "latest"
    kind: Kind = "plugin"
    host_id: str = "default"
    driver: InstallDriver | None = None
    provisioners: dict[str, Provisioner] | None = None
    notifiers: dict[str, Notifier] | None = None
    # See pipeline.DeploymentRunner.plugin_secret_key — same mechanism, only
    # meaningful for kind="plugin" (a "service" install has no plugin.yaml/
    # execution_mode to sign; sign_installed_plugin no-ops on that).
    plugin_secret_key: bytes | None = None

    state: MarketplaceDeploymentState = field(
        default=MarketplaceDeploymentState.PENDING, init=False
    )
    install_plan: InstallPlan | None = field(default=None, init=False)
    resolved_version: str = field(default="", init=False)

    def __post_init__(self) -> None:
        if self.driver is None:
            self.driver = InstallDriver(
                Layout(
                    project_root=self.project_root,
                    extracted_root=self.workdir / "extracted",
                    # This flow never has a manifest.json (see _load_plan)
                    # to read plugins_dirname back from, so — unlike
                    # agent.pipeline.DeploymentRunner — it would otherwise
                    # silently fall back to Layout's "plugins" default even
                    # for a target project whose own integration.yaml
                    # declares a different convention (e.g. "app/", see
                    # xcore-team/marketplace), installing into a directory
                    # the running app never reads from.
                    plugins_dirname=_read_plugins_dirname(self.project_root),
                ),
                provisioners=self.provisioners,
                notifiers=self.notifiers,
                plugin_secret_key=self.plugin_secret_key,
            )

    def _transition(self, new_state: MarketplaceDeploymentState) -> None:
        allowed = MARKETPLACE_TRANSITIONS[self.state]
        if new_state not in allowed:
            raise DeploymentError(
                f"illegal transition {self.state} -> {new_state} (allowed: {allowed})"
            )
        self.state = new_state

    async def run(self) -> MarketplaceDeploymentReport:
        started_at = _now()
        try:
            artifact = await self._fetch()
            self._verify_signature(artifact)
            self._extract(artifact)
            self._load_plan(artifact)
            order = self._resolve_sequence()
            self._install(order)
            self._healthcheck()
            self._transition(MarketplaceDeploymentState.SUCCEEDED)
            report = self._build_report(
                status="success", started_at=started_at, repo=artifact.repo_header
            )
        except DeploymentError as exc:
            if self.state not in MARKETPLACE_TERMINAL_STATES:
                self._transition(MarketplaceDeploymentState.FAILED)
            status = (
                "rolled_back" if self.state == MarketplaceDeploymentState.ROLLED_BACK else "failed"
            )
            report = self._build_report(
                status=status, started_at=started_at, repo="", error_message=str(exc)
            )
            self._write_report(report)
            await self._report_to_hub(report)
            raise
        self._write_report(report)
        await self._report_to_hub(report)
        return report

    async def _fetch(self) -> FetchedArtifact:
        self._transition(MarketplaceDeploymentState.FETCHING)
        return await self.client.fetch_artifact(
            slug=self.slug, version=self.version, kind=self.kind
        )

    def _verify_signature(self, artifact: FetchedArtifact) -> None:
        self._transition(MarketplaceDeploymentState.VERIFYING_SIGNATURE)
        try:
            crypto.verify_hmac_sha256_hex(
                secret=self.trusted_signer_secret,
                signature_hex=artifact.signature_header,
                payload=artifact.data,
            )
        except crypto.SignatureVerificationError as exc:
            raise ArtifactError(str(exc)) from exc
        # "name@version" — e.g. "my-plugin@1.2.3"
        self.resolved_version = artifact.plugin_header.rsplit("@", 1)[-1] or self.version

    def _extract(self, artifact: FetchedArtifact) -> None:
        self._transition(MarketplaceDeploymentState.EXTRACTING)
        extracted_root = self.workdir / "extracted"
        assert self.driver is not None
        # kind="service" extracts into extensions/<slug>, matching what
        # InstallDriver.install_extension actually looks for — a
        # kind=service deployment previously always extracted into
        # plugins/<slug> regardless, which install_extension never reads
        # from, silently installing nothing (see _dispatch's matching fix).
        # kind="plugin" must match install_plugin's OWN lookup, which reads
        # layout.plugins_dirname (now resolved from the target project's
        # integration.yaml, see __post_init__) rather than a hardcoded
        # "plugins" — staging anywhere else would leave install_plugin
        # unable to find what was just extracted.
        subdir = self.driver.layout.plugins_dirname if self.kind == "plugin" else "extensions"
        target = extracted_root / subdir / self.slug
        if target.exists():
            shutil.rmtree(target)
        target.mkdir(parents=True, exist_ok=True)

        zip_path = self.workdir / "artifact.zip"
        zip_path.write_bytes(artifact.data)
        try:
            with zipfile.ZipFile(zip_path) as zf:
                safe_extract_zip(zf, target)
        except zipfile.BadZipFile as exc:
            raise ArtifactError(f"fetched artifact is not a valid ZIP: {exc}") from exc
        except PluginResolutionError as exc:
            raise ArtifactError(str(exc)) from exc
        flatten_single_root(target)

    def _load_plan(self, artifact: FetchedArtifact) -> None:
        self._transition(MarketplaceDeploymentState.LOADING_PLAN)
        if not self.install_plan_path.is_file():
            raise ArtifactError(
                f"install plan {self.install_plan_path} not found — the Marketplace flow "
                "does not ship an install.yaml inside the artifact, it must be supplied "
                "locally by the operator (same trust boundary as `provisioners`)"
            )
        self.install_plan = InstallPlan.model_validate(
            yaml.safe_load(self.install_plan_path.read_text())
        )
        if self.install_plan.project_id != self.slug:
            raise ArtifactError(
                f"install plan project_id {self.install_plan.project_id!r} does not match "
                f"the plugin being deployed {self.slug!r}"
            )
        assert self.driver is not None
        self.driver.manifest = None  # no manifest.json in this flow — see class docstring

    def _resolve_sequence(self) -> list[str]:
        self._transition(MarketplaceDeploymentState.RESOLVING_SEQUENCE)
        assert self.install_plan is not None
        return self.install_plan.execution_order()

    def _install(self, order: list[str]) -> None:
        self._transition(MarketplaceDeploymentState.INSTALLING)
        assert self.install_plan is not None and self.driver is not None
        executed: list[str] = []
        try:
            for step_id in order:
                step = self.install_plan.step(step_id)
                self._dispatch(step)
                executed.append(step_id)
        except Exception as exc:
            self.driver.rollback()
            self._transition(MarketplaceDeploymentState.ROLLED_BACK)
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
        elif isinstance(step, NotifyStep):
            self.driver.notify(step)
        elif isinstance(step, StartStep):
            self.driver.start(step)
        elif isinstance(step, StopStep):
            self.driver.stop(step)
        elif isinstance(step, RestartStep):
            self.driver.restart(step)
        elif isinstance(step, HealthcheckStep):
            self.driver.healthcheck(step)
        # DownloadStep / ExtractStep / RollbackStep: no-ops — see pipeline.py's
        # equivalent comment, same reasoning applies here.

    def _healthcheck(self) -> None:
        self._transition(MarketplaceDeploymentState.HEALTHCHECKING)

    def _build_report(
        self, *, status: str, started_at: str, repo: str, error_message: str = ""
    ) -> MarketplaceDeploymentReport:
        return MarketplaceDeploymentReport(
            slug=self.slug,
            kind=self.kind,
            status=status,
            requested_version=self.version,
            resolved_version=self.resolved_version or self.version,
            repo=repo,
            started_at=started_at,
            completed_at=_now(),
            error_message=error_message,
        )

    def _write_report(self, report: MarketplaceDeploymentReport) -> None:
        reports_dir = self.workdir / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        path = reports_dir / f"{report.started_at.replace(':', '-')}.json"
        path.write_text(json.dumps(report.__dict__, indent=2))

    async def _report_to_hub(self, report: MarketplaceDeploymentReport) -> None:
        """Best-effort: a Hub-reporting failure must never mask the actual
        deployment outcome (which has already been decided and written locally)."""
        try:
            await self.client.report_deployment(
                kind=report.kind,
                slug=report.slug,
                version=report.resolved_version,
                status=report.status,  # type: ignore[arg-type]
                started_at=report.started_at,
                completed_at=report.completed_at,
                host_id=self.host_id,
                repo=report.repo,
                error_message=report.error_message or None,
            )
        except Exception as exc:
            logger.warning("failed to report deployment status to the Hub: %s", exc)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
