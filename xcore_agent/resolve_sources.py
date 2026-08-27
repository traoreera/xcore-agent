"""Resolves `source:` directly from a project's own `install.yaml` onto its
own plugins/extensions directories — no `.xdeploy` artifact, no
`manifest.json`, no sha256 pin check: this is for a project resolving ITS
OWN declared sources against ITSELF (e.g. a container image reconstructing
its marketplace-sourced plugins at boot — see `docker-entrypoint.sh` in
xcore-team/marketplace), not for verifying a *downloaded* artifact matches
what was built elsewhere.

Same merge semantics as `agent.pipeline.DeploymentRunner._resolve_plugins`
(resolved content is `copytree`'d ONTO whatever's already there, so a
plugin's own `.env.template` — absent from the resolved repo — survives),
deliberately NOT sharing code with that method: it verifies a manifest's
sha256 pin against a downloaded artifact's own resolve, a check with no
equivalent here — there is no manifest, no artifact, `install.yaml` is
already inside this project's own trusted tree.
"""

import shutil
from dataclasses import dataclass
from pathlib import Path

import yaml

from .packer.builder import _read_plugins_dirname
from .plugin_resolver import PluginResolver
from .schema.install import InstallExtensionStep, InstallPlan, InstallPluginStep

_INSTALL_PLAN_PATH = "deployment/install.yaml"


class ResolveSourcesError(Exception):
    """Raised when `install.yaml` can't be found or doesn't parse."""


@dataclass(frozen=True)
class ResolvedSource:
    id: str
    kind: str  # "plugin" | "extension"
    target: Path


async def resolve_all_sources(
    project_root: Path,
    *,
    plugin_resolver: PluginResolver,
    install_plan_path: Path | None = None,
) -> list[ResolvedSource]:
    """Resolve every step's `source:` in `project_root`'s own install.yaml
    and merge each resolved tree onto `project_root`'s own plugins_dirname/
    extensions directory. Returns what was actually resolved — an empty
    list is a normal outcome for a project with nothing source-based to
    resolve at this host, not an error."""
    plan_path = install_plan_path or project_root / _INSTALL_PLAN_PATH
    if not plan_path.is_file():
        raise ResolveSourcesError(f"{plan_path} not found")
    try:
        plan = InstallPlan.model_validate(yaml.safe_load(plan_path.read_text()))
    except Exception as exc:
        raise ResolveSourcesError(f"{plan_path}: invalid install plan: {exc}") from exc

    plugins_dirname = _read_plugins_dirname(project_root)
    resolved: list[ResolvedSource] = []

    for step in plan.steps:
        if isinstance(step, InstallPluginStep) and step.source is not None:
            source_tree = await plugin_resolver.resolve(step.plugin, step.source)
            target = project_root / plugins_dirname / step.plugin
            target.mkdir(parents=True, exist_ok=True)
            shutil.copytree(source_tree, target, dirs_exist_ok=True)
            resolved.append(ResolvedSource(id=step.plugin, kind="plugin", target=target))
        elif isinstance(step, InstallExtensionStep) and step.source is not None:
            # Namespaced ("ext-<id>") in the resolver's own cache for the
            # same reason as DeploymentRunner._resolve_plugins: a plugin
            # and an extension sharing an id must not collide there.
            source_tree = await plugin_resolver.resolve(f"ext-{step.extension}", step.source)
            target = project_root / "extensions" / step.extension
            target.mkdir(parents=True, exist_ok=True)
            shutil.copytree(source_tree, target, dirs_exist_ok=True)
            resolved.append(ResolvedSource(id=step.extension, kind="extension", target=target))

    return resolved
