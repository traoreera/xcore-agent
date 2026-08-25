"""Command-line entry point for xcore-agent."""

import asyncio
import contextlib
import socket
from enum import Enum
from pathlib import Path

import typer
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from rich.console import Console

from .agent.docker_supervisor import DockerSupervisor
from .agent.errors import DeploymentError
from .agent.gc import GarbageCollector
from .agent.hub_client import DeploymentReport, HttpHubClient
from .agent.install_driver import Layout, Supervisor
from .agent.kubernetes_supervisor import KubernetesSupervisor
from .agent.marketplace_client import MarketplaceClient
from .agent.marketplace_pipeline import MarketplaceDeploymentReport, MarketplaceDeploymentRunner
from .agent.marketplace_watcher import MarketplaceWatcher, MarketplaceWatchResult
from .agent.pipeline import DeploymentCredentials, DeploymentRunner
from .agent.notifiers import load_notifiers_from_config
from .agent.provisioners import load_provisioners_from_config
from .agent.systemd_supervisor import SystemdSupervisor
from .agent.watcher import Watcher, WatchResult
from .packer.builder import build_artifact
from .plugin_resolver import PluginResolver
from .scaffold import (
    ExtensionSpec,
    PluginSpec,
    ScaffoldOptions,
    render_install_plan_yaml,
    scaffold_install_plan,
)
from .schema.install import InstallPlan
from .schema.manifest import ProjectManifest

app = typer.Typer(add_completion=False, help="xcore-agent — deploys .xdeploy artifacts.")
console = Console()


class SupervisorKind(str, Enum):
    none = "none"
    systemd = "systemd"
    docker = "docker"
    kubernetes = "kubernetes"


class MarketplaceKind(str, Enum):
    plugin = "plugin"
    service = "service"


def _build_supervisor(
    kind: SupervisorKind,
    *,
    user_scope: bool,
    k8s_namespace: str = "default",
    k8s_kubeconfig: str | None = None,
    k8s_context: str | None = None,
) -> Supervisor | None:
    if kind is SupervisorKind.systemd:
        return SystemdSupervisor(user_scope=user_scope)
    if kind is SupervisorKind.docker:
        return DockerSupervisor()
    if kind is SupervisorKind.kubernetes:
        return KubernetesSupervisor(
            namespace=k8s_namespace, kubeconfig=k8s_kubeconfig, context=k8s_context
        )
    return None


def _parse_git_tokens(entries: list[str]) -> dict[str, str]:
    """Parse repeated `--git-token host=token` options into a
    {host: token} map for PluginResolver's HTTPS authentication."""
    tokens: dict[str, str] = {}
    for entry in entries:
        host, sep, token = entry.partition("=")
        if not sep:
            raise typer.BadParameter(f"--git-token must be HOST=TOKEN, got {entry!r}")
        tokens[host] = token
    return tokens


def _parse_env_templates(entries: list[str]) -> dict[str, str]:
    """Parse repeated `--env-template plugin=path` options into a
    {plugin_id: relative_path} map for init-plan's write_env steps."""
    templates: dict[str, str] = {}
    for entry in entries:
        plugin_id, sep, path = entry.partition("=")
        if not sep:
            raise typer.BadParameter(f"--env-template must be PLUGIN=PATH, got {entry!r}")
        templates[plugin_id] = path
    return templates


@app.command()
def validate(
    install_yaml: Path = typer.Argument(..., help="Path to install.yaml"),
    manifest_json: Path = typer.Option(
        None, help="Optional path to manifest.json to validate alongside it"
    ),
) -> None:
    """Validate an install.yaml (and optionally manifest.json) — local only, no network."""
    plan = InstallPlan.model_validate(yaml.safe_load(install_yaml.read_text()))
    console.print(f"[green]OK[/green] {install_yaml}: {len(plan.steps)} step(s)")
    console.print("Execution order:")
    for step_id in plan.execution_order():
        console.print(f"  - {step_id}")

    if manifest_json is not None:
        manifest = ProjectManifest.model_validate_json(manifest_json.read_text())
        console.print(
            f"[green]OK[/green] {manifest_json}: project {manifest.project_name!r} "
            f"v{manifest.version} ({len(manifest.plugins)} plugin(s))"
        )


@app.command("init-plan")
def init_plan(
    project_id: str = typer.Argument(
        ...,
        help="project_id to stamp in the plan — must equal the plugin's marketplace slug "
        "for `deploy-marketplace`/`watch-marketplace`",
    ),
    plugin: list[str] = typer.Option(
        ...,
        help="Plugin id to install (repeatable) — one install_plugin step per id, "
        "in the order given",
    ),
    extension: list[str] = typer.Option(
        [],
        help="Extension id to install (repeatable) — one install_extension step per id, "
        "for a shared non-plugin service under extensions/<id> (see manifest.ExtensionRef). "
        "Separate id namespace from --plugin: a plugin and an extension may share an id.",
    ),
    version: str = typer.Option("0.1.0", help="Version to stamp in the plan"),
    output: Path = typer.Option(
        Path("deployment/install.yaml"), help="Where to write the generated install.yaml"
    ),
    env_template: list[str] = typer.Option(
        [],
        help="PLUGIN=RELATIVE_PATH adding a write_env step for that plugin (repeatable), "
        "e.g. demo=plugins/demo/.env.template",
    ),
    snapshot: bool = typer.Option(
        True, help="Take a rollback snapshot before each install_plugin/install_extension step"
    ),
    healthcheck: bool = typer.Option(True, help="Append a healthcheck step after start"),
    healthcheck_timeout: str = typer.Option("30s", help="Healthcheck timeout, e.g. '30s' or '2m'"),
    healthcheck_retries: int = typer.Option(3, help="Healthcheck retry count"),
    force: bool = typer.Option(False, help="Overwrite --output if it already exists"),
) -> None:
    """Generate a starter install.yaml for a project: one install_plugin step
    per --plugin (in order given), one install_extension step per --extension,
    an optional write_env step per --env-template, a start step depending on
    all of them, and an optional trailing healthcheck. The result is
    validated through InstallPlan before being written, so it is guaranteed
    loadable by `validate`/`deploy`/`deploy-marketplace` as-is — a starting
    point to hand-edit from, not a substitute for reviewing what actually
    gets deployed."""
    if output.exists() and not force:
        console.print(f"[red]{output} already exists[/red] — pass --force to overwrite")
        raise typer.Exit(code=1)

    templates = _parse_env_templates(env_template)
    unknown = set(templates) - set(plugin)
    if unknown:
        raise typer.BadParameter(
            f"--env-template references unknown plugin(s): {', '.join(sorted(unknown))}"
        )

    options = ScaffoldOptions(
        project_id=project_id,
        plugins=[
            PluginSpec(id=p, snapshot=snapshot, env_template=templates.get(p)) for p in plugin
        ],
        extensions=[ExtensionSpec(id=e, snapshot=snapshot) for e in extension],
        version=version,
        with_healthcheck=healthcheck,
        healthcheck_timeout=healthcheck_timeout,
        healthcheck_retries=healthcheck_retries,
    )

    try:
        plan_dict = scaffold_install_plan(options)
    except ValueError as exc:
        console.print(f"[red]Could not scaffold install.yaml:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_install_plan_yaml(plan_dict))
    console.print(f"[green]Wrote[/green] {output} ({len(plan_dict['steps'])} step(s))")


@app.command()
def build(
    source_root: Path = typer.Argument(
        ..., help="Project source tree: plugins/, integration.yaml, deployment/install.yaml"
    ),
    project_id: str = typer.Option(...),
    project_name: str = typer.Option(...),
    version: str = typer.Option(..., help="Version to stamp on this artifact, e.g. 1.0.0"),
    output: Path = typer.Option(..., help="Output path for the encrypted .xdeploy artifact"),
    signing_key_file: Path = typer.Option(
        None,
        help="Path to a raw 32-byte Ed25519 private key. A throwaway key is "
        "generated (and NOT saved) if omitted — fine for local testing, "
        "not for anything an agent needs to trust across builds.",
    ),
) -> None:
    """Build, encrypt, and sign a .xdeploy artifact from a project source tree."""
    signing_key = (
        Ed25519PrivateKey.from_private_bytes(signing_key_file.read_bytes())
        if signing_key_file is not None
        else None
    )

    result = build_artifact(
        source_root,
        project_id=project_id,
        project_name=project_name,
        version=version,
        output_path=output,
        signing_key=signing_key,
    )

    console.print(f"[green]Built[/green] {result.output_path}")
    console.print(f"  project:        {project_name} v{version}")
    console.print(f"  plugins:        {', '.join(p.id for p in result.manifest.plugins)}")
    console.print(f"  content_sha256: {result.manifest.content_sha256}")
    console.print()
    console.print(
        "[yellow]DEK (hex) — hand this to XCore Hub for storage; not saved here:[/yellow]"
    )
    console.print(f"  {result.dek.hex()}")
    console.print(
        "[yellow]Signer public key (hex) — distribute to agents as the trusted key:[/yellow]"
    )
    console.print(f"  {result.signer_public_key.hex()}")
    if signing_key_file is None:
        console.print(
            "[red]No --signing-key-file given: this used a throwaway key that was "
            "NOT saved. Re-running build will sign with a different key.[/red]"
        )


@app.command()
def publish(
    source_root: Path = typer.Argument(
        ..., help="Project source tree: plugins/, integration.yaml, deployment/install.yaml"
    ),
    project_id: str = typer.Option(..., envvar="XCORE_PROJECT_ID"),
    project_name: str = typer.Option(...),
    version: str = typer.Option(..., help="Version to stamp on this artifact, e.g. 1.0.0"),
    xdevkey: str = typer.Option(..., envvar="XCORE_XDEVKEY"),
    hub_url: str = typer.Option("https://hub.xcorehub.dev", envvar="XCORE_HUB_URL"),
    output: Path = typer.Option(
        None,
        help="Also write the sealed .xdeploy artifact here (optional — it stays "
        "on Hub either way, this is just a local copy for your own records)",
    ),
    signing_key_file: Path = typer.Option(
        None,
        help="Path to a raw 32-byte Ed25519 private key. A throwaway key is "
        "generated (and NOT saved) if omitted — fine for a one-off publish, "
        "but a `watch`er needs the SAME trusted key across every version of "
        "a project it's told to follow, so reuse one across builds if you "
        "intend to keep publishing updates to this project_id.",
    ),
) -> None:
    """Build, encrypt, sign, and upload a .xdeploy artifact to XCore Hub in
    one step. `build` alone only produces a local file and prints the DEK to
    your terminal with instructions to "hand this to the Hub" — nothing in
    xcore-agent actually did that upload before this command existed. The
    DEK never touches disk here: it stays in memory between build and
    publish, exactly like `deploy`/`watch` never persist one either."""
    import tempfile

    signing_key = (
        Ed25519PrivateKey.from_private_bytes(signing_key_file.read_bytes())
        if signing_key_file is not None
        else None
    )

    with tempfile.TemporaryDirectory(prefix="xcore-agent-publish-") as tmp:
        artifact_path = output if output is not None else Path(tmp) / "artifact.xdeploy"
        result = build_artifact(
            source_root,
            project_id=project_id,
            project_name=project_name,
            version=version,
            output_path=artifact_path,
            signing_key=signing_key,
        )
        console.print(f"[green]Built[/green] {artifact_path}")
        console.print(f"  content_sha256: {result.manifest.content_sha256}")

        async def _publish():
            async with HttpHubClient(hub_url) as hub:
                return await hub.publish(
                    xdevkey=xdevkey,
                    project_id=project_id,
                    project_name=project_name,
                    version=version,
                    ciphertext=artifact_path.read_bytes(),
                    content_sha256=result.manifest.content_sha256,
                    dek=result.dek,
                    signature=result.signature,
                    signer_public_key=result.signer_public_key,
                )

        try:
            published = asyncio.run(_publish())
        except DeploymentError as exc:
            console.print(f"[red]Publish failed:[/red] {exc}")
            raise typer.Exit(code=1) from exc

    console.print(f"[green]Published[/green] {project_id} v{published.version} to {hub_url}")
    console.print(f"  artifact_id: {published.artifact_id}")
    console.print(f"  size_bytes:  {published.size_bytes}")
    if output is None:
        console.print(
            "[dim]No --output given: the local .xdeploy file was discarded — "
            "it lives on the Hub now, re-download it if you need a local copy.[/dim]"
        )
    if signing_key_file is None:
        console.print(
            "[yellow]No --signing-key-file given: this used a throwaway key. "
            "A `watch`er following this project must be told THIS run's "
            "signer public key, and won't trust a future publish signed by a "
            "different one.[/yellow]"
        )
        console.print(f"  signer public key (hex): {result.signer_public_key.hex()}")


@app.command()
def deploy(
    project_id: str = typer.Option(..., envvar="XCORE_PROJECT_ID"),
    version: str = typer.Option(..., help="Version to deploy, e.g. 1.0.0"),
    xdevkey: str = typer.Option(..., envvar="XCORE_XDEVKEY"),
    deployment_credential: str = typer.Option(..., envvar="XCORE_DEPLOYMENT_KEY"),
    hub_url: str = typer.Option("https://hub.xcorehub.dev", envvar="XCORE_HUB_URL"),
    project_root: Path = typer.Option(
        ..., help="Target install directory, e.g. /etc/xcore/projects/my-erp"
    ),
    signer_public_key: Path = typer.Option(
        ..., help="Path to the Hub's Ed25519 public key (raw 32 bytes)"
    ),
    git_token: list[str] = typer.Option(
        [],
        help="HOST=TOKEN for a private git host a source-based plugin may need "
        "to authenticate against (repeatable) — only used for a plugin/extension "
        "whose 'source:' is a git fallback (see PluginSource), not a marketplace "
        "slug. Public repos and SSH URLs need none of this.",
    ),
    marketplace_url: str = typer.Option(
        "https://marketplace.xcorehub.dev",
        envvar="XCORE_MARKETPLACE_URL",
        help="Marketplace root (no /app/... segment), used to resolve any plugin/"
        "extension whose 'source:' is a marketplace slug — see `deploy-marketplace "
        "--help` for the shape of this URL. Irrelevant if every plugin in this "
        "project is either embedded or git-sourced.",
    ),
    marketplace_api_key: str = typer.Option(
        None,
        envvar="XCORE_MARKETPLACE_API_KEY",
        help="xdevkeys API key (xdk_...), required only if some plugin/extension "
        "in this project has a marketplace-slug 'source:' (the default xcli "
        "records for anything installed via `xcli plugin install`).",
    ),
    marketplace_signing_secret: str = typer.Option(
        None,
        envvar="XCORE_MARKETPLACE_SIGNING_SECRET",
        help="HMAC signing secret verifying marketplace-sourced plugins/extensions "
        "(see `deploy-marketplace --help`) — required alongside --marketplace-api-key "
        "whenever this project has one.",
    ),
    provisioners_config: Path = typer.Option(
        None,
        help="YAML file mapping plugin id -> {command, env, timeout} for the "
        "'provision' action — see agent/provisioners.py. Omit if no plugin "
        "in this project uses 'provision'.",
    ),
    notifiers_config: Path = typer.Option(
        None,
        help="YAML file mapping event -> {command, env, timeout} for the "
        "'notify' action — see agent/notifiers.py. Omit if no step in this "
        "project's install.yaml uses 'notify'.",
    ),
    plugin_secret_key: str = typer.Option(
        None,
        envvar="XCORE_PLUGIN_SECRET",
        help="This host's own `plugins.secret_key` (root integration.yaml, e.g. "
        "${PLUGIN_SECRET}/${SECRET_KEY} depending on the project's env naming) — "
        "signs every installed `execution_mode: trusted` plugin with plugin.sig "
        "so this host's strict_trusted check (xcore.kernel.security.signature) "
        "can load it. Host-local, never embedded in the artifact — same as "
        "--signing-secret is NOT this. Omit if this host doesn't run "
        "strict_trusted: true, or has no trusted-mode plugins.",
    ),
) -> None:
    """Deploy a project version fetched from XCore Hub.

    Requires a live Hub API — not available yet (see agent.hub_client.HttpHubClient) —
    so this command currently fails at the authenticate step by design.
    """
    workdir = Path.home() / ".cache" / "xcore-agent" / project_id / version
    workdir.mkdir(parents=True, exist_ok=True)
    provisioners = (
        load_provisioners_from_config(provisioners_config)
        if provisioners_config is not None
        else None
    )
    notifiers = (
        load_notifiers_from_config(notifiers_config) if notifiers_config is not None else None
    )
    runner_holder: dict[str, DeploymentRunner] = {}

    async def _run() -> DeploymentReport:
        async with contextlib.AsyncExitStack() as stack:
            hub = await stack.enter_async_context(HttpHubClient(hub_url))
            marketplace_client = None
            if marketplace_api_key:
                marketplace_client = await stack.enter_async_context(
                    MarketplaceClient(marketplace_url, api_key=marketplace_api_key)
                )
            plugin_resolver = PluginResolver(
                cache_root=Path.home() / ".cache" / "xcore-agent" / "plugins",
                git_credentials=_parse_git_tokens(git_token),
                marketplace_client=marketplace_client,
                trusted_signer_secret=(
                    marketplace_signing_secret.encode() if marketplace_signing_secret else None
                ),
            )
            runner = DeploymentRunner(
                hub=hub,
                credentials=DeploymentCredentials(
                    xdevkey=xdevkey,
                    project_id=project_id,
                    deployment_credential=deployment_credential,
                ),
                version=version,
                workdir=workdir,
                project_root=project_root,
                trusted_signer_public_key=signer_public_key.read_bytes(),
                plugin_resolver=plugin_resolver,
                provisioners=provisioners,
                notifiers=notifiers,
                plugin_secret_key=plugin_secret_key.encode() if plugin_secret_key else None,
            )
            runner_holder["runner"] = runner
            return await runner.run()

    try:
        report = asyncio.run(_run())
    except NotImplementedError as exc:
        console.print(f"[red]Not yet supported:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except Exception as exc:
        state = runner_holder["runner"].state.value if "runner" in runner_holder else "unknown"
        console.print(f"[red]Deployment failed[/red] (state={state}): {exc}")
        raise typer.Exit(code=1) from exc

    console.print(f"[green]Deployment {report.status}[/green] for {project_id} v{version}")


@app.command("deploy-marketplace")
def deploy_marketplace(
    slug: str = typer.Argument(..., help="Plugin or extension slug on the marketplace"),
    version: str = typer.Option("latest", help="Version to deploy, or 'latest'"),
    kind: MarketplaceKind = typer.Option(MarketplaceKind.plugin),
    api_key: str = typer.Option(..., envvar="XCORE_API_KEY", help="xdevkeys API key (xdk_...)"),
    signing_secret: str = typer.Option(
        ...,
        envvar="XCORE_SIGNING_SECRET",
        help="The publisher's HMAC signing secret (from xdevkeys) — obtained out-of-band, "
        "e.g. from the plugin's developer. Unlike Ed25519, this is a *shared* secret: "
        "whoever holds it can also forge a signature, so treat its source as part of "
        "your trust decision, not the signature check alone.",
    ),
    hub_url: str = typer.Option(
        "https://marketplace.xcorehub.dev",
        envvar="XCORE_HUB_URL",
        help="Hub root, WITHOUT a plugin segment — MarketplaceClient appends the "
        "right /app/<plugin> mount itself (marketplace, xservices, or "
        "xdeployments depending on the request; see marketplace_client.py's "
        "module docstring). e.g. https://marketplace.xcorehub.dev, or "
        "http://localhost:8000 for a local Hub.",
    ),
    project_root: Path = typer.Option(
        ..., help="Target install directory, e.g. /etc/xcore/projects/my-erp"
    ),
    host_id: str = typer.Option(
        None,
        envvar="XCORE_HOST_ID",
        help="Identifier for this target reported alongside deployment status "
        "(GET /deployments/{kind}/{slug}/hosts on the marketplace) — defaults to "
        "this machine's hostname.",
    ),
    install_plan: Path = typer.Option(
        ...,
        help="Local install.yaml — the real Marketplace ships plain plugin source, not a "
        "deployment plan, so this is supplied by the operator (same trust boundary as "
        "--provisioners-config), never fetched from the Hub.",
    ),
    provisioners_config: Path = typer.Option(
        None,
        help="YAML file mapping plugin id -> {command, env, timeout} for the "
        "'provision' action — see agent/provisioners.py.",
    ),
    notifiers_config: Path = typer.Option(
        None,
        help="YAML file mapping event -> {command, env, timeout} for the "
        "'notify' action — see agent/notifiers.py.",
    ),
    plugin_secret_key: str = typer.Option(
        None,
        envvar="XCORE_PLUGIN_SECRET",
        help="This host's own `plugins.secret_key` (root integration.yaml) — signs "
        "the installed plugin with plugin.sig if it declares `execution_mode: "
        "trusted`, so this host's strict_trusted check can load it. No effect for "
        "kind=service (no plugin.yaml/execution_mode there). See `deploy --help` "
        "for the same option's full explanation.",
    ),
) -> None:
    """Deploy a single plugin or extension fetched from the real xcore-team/marketplace
    (X-API-Key auth, HMAC-SHA256-signed plain ZIP) — see agent/marketplace_client.py
    for how this differs from `deploy`'s .xdeploy/DEK/Ed25519 contract."""
    resolved_host_id = host_id or socket.gethostname()
    workdir = Path.home() / ".cache" / "xcore-agent" / "marketplace" / slug / version
    workdir.mkdir(parents=True, exist_ok=True)
    provisioners = (
        load_provisioners_from_config(provisioners_config)
        if provisioners_config is not None
        else None
    )
    notifiers = (
        load_notifiers_from_config(notifiers_config) if notifiers_config is not None else None
    )
    runner_holder: dict[str, MarketplaceDeploymentRunner] = {}

    async def _run() -> MarketplaceDeploymentReport:
        async with MarketplaceClient(hub_url, api_key=api_key) as client:
            runner = MarketplaceDeploymentRunner(
                client=client,
                slug=slug,
                workdir=workdir,
                project_root=project_root,
                trusted_signer_secret=signing_secret.encode(),
                install_plan_path=install_plan,
                version=version,
                kind=kind.value,
                host_id=resolved_host_id,
                provisioners=provisioners,
                notifiers=notifiers,
                plugin_secret_key=plugin_secret_key.encode() if plugin_secret_key else None,
            )
            runner_holder["runner"] = runner
            return await runner.run()

    try:
        report = asyncio.run(_run())
    except Exception as exc:
        state = runner_holder["runner"].state.value if "runner" in runner_holder else "unknown"
        console.print(f"[red]Deployment failed[/red] (state={state}): {exc}")
        raise typer.Exit(code=1) from exc

    console.print(
        f"[green]Deployment {report.status}[/green] for {slug} v{report.resolved_version} "
        f"(host={resolved_host_id})"
    )


@app.command("watch-marketplace")
def watch_marketplace(
    slug: str = typer.Argument(..., help="Plugin or extension slug on the marketplace"),
    kind: MarketplaceKind = typer.Option(MarketplaceKind.plugin),
    api_key: str = typer.Option(..., envvar="XCORE_API_KEY", help="xdevkeys API key (xdk_...)"),
    signing_secret: str = typer.Option(
        ...,
        envvar="XCORE_SIGNING_SECRET",
        help="The publisher's HMAC signing secret (from xdevkeys) — see `deploy-marketplace` "
        "--signing-secret for the trust-model caveat.",
    ),
    hub_url: str = typer.Option(
        "https://marketplace.xcorehub.dev",
        envvar="XCORE_HUB_URL",
        help="Hub root, WITHOUT a plugin segment — MarketplaceClient appends the "
        "right /app/<plugin> mount itself (marketplace, xservices, or "
        "xdeployments depending on the request; see marketplace_client.py's "
        "module docstring). e.g. https://marketplace.xcorehub.dev, or "
        "http://localhost:8000 for a local Hub.",
    ),
    project_root: Path = typer.Option(
        ..., help="Target install directory, e.g. /etc/xcore/projects/my-erp"
    ),
    host_id: str = typer.Option(
        None,
        envvar="XCORE_HOST_ID",
        help="Identifier for this target reported alongside deployment status — "
        "defaults to this machine's hostname.",
    ),
    install_plan: Path = typer.Option(
        ...,
        help="Local install.yaml — supplied by the operator, never fetched from the Hub "
        "(same as `deploy-marketplace` --install-plan).",
    ),
    interval: int = typer.Option(60, help="Seconds between Marketplace checks"),
    once: bool = typer.Option(False, help="Check once and exit instead of looping forever"),
    keep_snapshots: int = typer.Option(3, help="Rollback snapshots to keep for this plugin"),
    supervisor: SupervisorKind = typer.Option(
        SupervisorKind.none, help="How to restart the plugin after a redeploy and GC pass"
    ),
    systemd_user_scope: bool = typer.Option(True, help="Use `systemctl --user` vs system-wide"),
    k8s_namespace: str = typer.Option("default", help="Namespace for --supervisor kubernetes"),
    k8s_kubeconfig: str = typer.Option(
        None,
        help="Path to a kubeconfig file for --supervisor kubernetes (defaults to kubectl's own)",
    ),
    k8s_context: str = typer.Option(
        None, help="kubeconfig context for --supervisor kubernetes (defaults to kubectl's current)"
    ),
    provisioners_config: Path = typer.Option(
        None,
        help="YAML file mapping plugin id -> {command, env, timeout} for the "
        "'provision' action — see agent/provisioners.py.",
    ),
    notifiers_config: Path = typer.Option(
        None,
        help="YAML file mapping event -> {command, env, timeout} for the "
        "'notify' action — see agent/notifiers.py.",
    ),
) -> None:
    """Poll the real xcore-team/marketplace for a new version of one plugin
    or extension and redeploy automatically when it appears — the CI/CD loop
    for the Marketplace flow (X-API-Key auth, HMAC-signed plain ZIP; see
    agent/marketplace_client.py). Runs garbage collection after every
    successful redeploy, same as `watch`."""
    resolved_host_id = host_id or socket.gethostname()
    workdir_root = Path.home() / ".cache" / "xcore-agent" / "marketplace" / slug
    provisioners = (
        load_provisioners_from_config(provisioners_config)
        if provisioners_config is not None
        else None
    )
    notifiers = (
        load_notifiers_from_config(notifiers_config) if notifiers_config is not None else None
    )

    def _report(result: MarketplaceWatchResult) -> None:
        if result.deployed:
            console.print(f"[green]Deployed[/green] {slug} v{result.checked_version}")
        else:
            console.print(f"[dim]No change (still v{result.checked_version})[/dim]")

    def _report_error(exc: Exception) -> None:
        console.print(f"[red]Check failed:[/red] {exc}")

    async def _watch() -> MarketplaceWatchResult | None:
        async with MarketplaceClient(hub_url, api_key=api_key) as client:
            watcher = MarketplaceWatcher(
                client=client,
                slug=slug,
                trusted_signer_secret=signing_secret.encode(),
                install_plan_path=install_plan,
                workdir_root=workdir_root,
                project_root=project_root,
                kind=kind.value,
                host_id=resolved_host_id,
                keep_snapshots=keep_snapshots,
                supervisor=_build_supervisor(
                    supervisor,
                    user_scope=systemd_user_scope,
                    k8s_namespace=k8s_namespace,
                    k8s_kubeconfig=k8s_kubeconfig,
                    k8s_context=k8s_context,
                ),
                provisioners=provisioners,
                notifiers=notifiers,
            )
            if once:
                return await watcher.check_once()
            await watcher.watch_forever(
                interval_seconds=interval, on_result=_report, on_error=_report_error
            )
            return None

    if once:
        try:
            result = asyncio.run(_watch())
        except Exception as exc:
            _report_error(exc)
            raise typer.Exit(code=1) from exc
        assert result is not None
        _report(result)
        return

    asyncio.run(_watch())


@app.command()
def watch(
    project_id: str = typer.Option(..., envvar="XCORE_PROJECT_ID"),
    xdevkey: str = typer.Option(..., envvar="XCORE_XDEVKEY"),
    deployment_credential: str = typer.Option(..., envvar="XCORE_DEPLOYMENT_KEY"),
    hub_url: str = typer.Option("https://hub.xcorehub.dev", envvar="XCORE_HUB_URL"),
    project_root: Path = typer.Option(...),
    signer_public_key: Path = typer.Option(
        ..., help="Path to the Hub's Ed25519 public key (raw 32 bytes)"
    ),
    interval: int = typer.Option(60, help="Seconds between Hub checks"),
    once: bool = typer.Option(False, help="Check once and exit instead of looping forever"),
    keep_snapshots: int = typer.Option(3, help="Rollback snapshots to keep per plugin"),
    supervisor: SupervisorKind = typer.Option(
        SupervisorKind.none, help="How to restart plugins after a redeploy and GC pass"
    ),
    systemd_user_scope: bool = typer.Option(True, help="Use `systemctl --user` vs system-wide"),
    k8s_namespace: str = typer.Option("default", help="Namespace for --supervisor kubernetes"),
    k8s_kubeconfig: str = typer.Option(
        None,
        help="Path to a kubeconfig file for --supervisor kubernetes (defaults to kubectl's own)",
    ),
    k8s_context: str = typer.Option(
        None, help="kubeconfig context for --supervisor kubernetes (defaults to kubectl's current)"
    ),
    git_token: list[str] = typer.Option(
        [],
        help="HOST=TOKEN for a private git host a source-based plugin may need "
        "to authenticate against (repeatable) — only used for a plugin/extension "
        "whose 'source:' is a git fallback (see PluginSource), not a marketplace "
        "slug. Public repos and SSH URLs need none of this.",
    ),
    marketplace_url: str = typer.Option(
        "https://marketplace.xcorehub.dev",
        envvar="XCORE_MARKETPLACE_URL",
        help="Marketplace root (no /app/... segment), used to resolve any plugin/"
        "extension whose 'source:' is a marketplace slug. Irrelevant if every "
        "plugin in this project is either embedded or git-sourced.",
    ),
    marketplace_api_key: str = typer.Option(
        None,
        envvar="XCORE_MARKETPLACE_API_KEY",
        help="xdevkeys API key (xdk_...), required only if some plugin/extension "
        "in this project has a marketplace-slug 'source:' (the default xcli "
        "records for anything installed via `xcli plugin install`).",
    ),
    marketplace_signing_secret: str = typer.Option(
        None,
        envvar="XCORE_MARKETPLACE_SIGNING_SECRET",
        help="HMAC signing secret verifying marketplace-sourced plugins/extensions — "
        "required alongside --marketplace-api-key whenever this project has one.",
    ),
    provisioners_config: Path = typer.Option(
        None,
        help="YAML file mapping plugin id -> {command, env, timeout} for the "
        "'provision' action — see agent/provisioners.py.",
    ),
    notifiers_config: Path = typer.Option(
        None,
        help="YAML file mapping event -> {command, env, timeout} for the "
        "'notify' action — see agent/notifiers.py.",
    ),
) -> None:
    """Poll XCore Hub for a new version/tag and redeploy automatically when
    one appears — the CI/CD loop. Runs garbage collection (stale rollback
    snapshots + cached downloads) after every successful redeploy. Requires
    a live Hub API — not available yet (see agent.hub_client.HttpHubClient)."""
    workdir_root = Path.home() / ".cache" / "xcore-agent" / project_id
    provisioners = (
        load_provisioners_from_config(provisioners_config)
        if provisioners_config is not None
        else None
    )
    notifiers = (
        load_notifiers_from_config(notifiers_config) if notifiers_config is not None else None
    )

    def _report(result: WatchResult) -> None:
        if result.deployed:
            console.print(f"[green]Deployed[/green] {project_id} v{result.checked_version}")
        else:
            console.print(f"[dim]No change (still v{result.checked_version})[/dim]")

    def _report_error(exc: Exception) -> None:
        console.print(f"[red]Check failed:[/red] {exc}")

    async def _watch() -> WatchResult | None:
        async with contextlib.AsyncExitStack() as stack:
            hub = await stack.enter_async_context(HttpHubClient(hub_url))
            marketplace_client = None
            if marketplace_api_key:
                marketplace_client = await stack.enter_async_context(
                    MarketplaceClient(marketplace_url, api_key=marketplace_api_key)
                )
            plugin_resolver = PluginResolver(
                cache_root=Path.home() / ".cache" / "xcore-agent" / "plugins",
                git_credentials=_parse_git_tokens(git_token),
                marketplace_client=marketplace_client,
                trusted_signer_secret=(
                    marketplace_signing_secret.encode() if marketplace_signing_secret else None
                ),
            )
            watcher = Watcher(
                hub=hub,
                credentials=DeploymentCredentials(
                    xdevkey=xdevkey,
                    project_id=project_id,
                    deployment_credential=deployment_credential,
                ),
                workdir_root=workdir_root,
                project_root=project_root,
                trusted_signer_public_key=signer_public_key.read_bytes(),
                keep_snapshots=keep_snapshots,
                supervisor=_build_supervisor(
                    supervisor,
                    user_scope=systemd_user_scope,
                    k8s_namespace=k8s_namespace,
                    k8s_kubeconfig=k8s_kubeconfig,
                    k8s_context=k8s_context,
                ),
                plugin_resolver=plugin_resolver,
                provisioners=provisioners,
                notifiers=notifiers,
            )
            if once:
                return await watcher.check_once()
            await watcher.watch_forever(
                interval_seconds=interval, on_result=_report, on_error=_report_error
            )
            return None

    if once:
        try:
            result = asyncio.run(_watch())
        except Exception as exc:
            _report_error(exc)
            raise typer.Exit(code=1) from exc
        assert result is not None
        _report(result)
        return

    asyncio.run(_watch())


@app.command()
def gc(
    project_root: Path = typer.Option(...),
    cache_root: Path = typer.Option(
        None, help="Cache root to prune (e.g. ~/.cache/xcore-agent/<project-id>)"
    ),
    keep_version: list[str] = typer.Option(
        [], help="Version(s) to keep in the cache — repeat for multiple"
    ),
    keep_snapshots: int = typer.Option(3, help="Rollback snapshots to keep per plugin"),
    force_restart: bool = typer.Option(False, help="Restart every installed plugin after cleanup"),
    supervisor: SupervisorKind = typer.Option(
        SupervisorKind.systemd, help="Which supervisor to use when --force-restart is set"
    ),
    systemd_user_scope: bool = typer.Option(True, help="Use `systemctl --user` vs system-wide"),
    k8s_namespace: str = typer.Option("default", help="Namespace for --supervisor kubernetes"),
    k8s_kubeconfig: str = typer.Option(
        None,
        help="Path to a kubeconfig file for --supervisor kubernetes (defaults to kubectl's own)",
    ),
    k8s_context: str = typer.Option(
        None, help="kubeconfig context for --supervisor kubernetes (defaults to kubectl's current)"
    ),
) -> None:
    """Purge stale rollback snapshots and cached artifact downloads, and
    optionally force every plugin to restart afterward so no running
    process keeps serving state that was just reclaimed on disk."""
    layout = Layout(project_root=project_root, extracted_root=project_root / ".gc-unused")
    supervisor_instance = (
        _build_supervisor(
            supervisor,
            user_scope=systemd_user_scope,
            k8s_namespace=k8s_namespace,
            k8s_kubeconfig=k8s_kubeconfig,
            k8s_context=k8s_context,
        )
        if force_restart
        else None
    )
    collector = GarbageCollector(
        layout, keep_snapshots=keep_snapshots, cache_root=cache_root, supervisor=supervisor_instance
    )

    restart_ids = []
    if force_restart and layout.plugins_dir.is_dir():
        restart_ids = [p.name for p in layout.plugins_dir.iterdir() if p.is_dir()]

    report = collector.collect(keep_versions=frozenset(keep_version), restart_plugins=restart_ids)

    console.print(
        f"[green]GC done[/green]: {len(report.snapshots_removed)} snapshot(s) and "
        f"{len(report.cache_dirs_removed)} cache dir(s) removed, {report.bytes_freed} bytes freed"
    )
    if report.plugins_restarted:
        console.print(f"[green]Restarted[/green]: {', '.join(report.plugins_restarted)}")


if __name__ == "__main__":
    app()
