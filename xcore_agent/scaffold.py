"""Generates a starter `install.yaml` for a new project.

Hand-writing an `install.yaml` means re-deriving the same shape every time
(`prepare` -> one `install_plugin` per plugin -> optional `write_env` ->
`start` -> optional `healthcheck`) while also getting every step id,
`depends_on` edge, and the closed `action` enum right by hand. This module
builds that shape as a plain dict — the same shape a human would hand-write
— and validates it through `InstallPlan.model_validate` before it's ever
written to disk, so a scaffolded plan is guaranteed loadable by
`validate`/`deploy`/`deploy-marketplace` as-is.
"""

from dataclasses import dataclass, field
from typing import Any

import yaml

from .schema.install import InstallPlan


@dataclass(frozen=True)
class PluginSpec:
    id: str
    snapshot: bool = True
    env_template: str | None = None  # relative "from" path for a write_env step, if any


@dataclass(frozen=True)
class ExtensionSpec:
    id: str
    snapshot: bool = True


@dataclass(frozen=True)
class ScaffoldOptions:
    project_id: str
    plugins: list[PluginSpec] = field(default_factory=list)
    extensions: list[ExtensionSpec] = field(default_factory=list)
    version: str = "0.1.0"
    with_healthcheck: bool = True
    healthcheck_timeout: str = "30s"
    healthcheck_retries: int = 3


def scaffold_install_plan(options: ScaffoldOptions) -> dict[str, Any]:
    """Build an install.yaml-shaped dict and validate it via `InstallPlan`
    (raising on any inconsistency) before returning it. The returned dict —
    not a round-tripped pydantic dump — is what gets rendered to YAML, so
    the output matches what a human would hand-write."""
    if not options.plugins:
        raise ValueError("at least one plugin is required to scaffold an install.yaml")

    steps: list[dict[str, Any]] = [{"id": "prepare", "action": "prepare"}]
    start_deps: list[str] = []

    for plugin in options.plugins:
        install_id = f"install_{plugin.id}"
        step: dict[str, Any] = {"id": install_id, "action": "install_plugin", "plugin": plugin.id}
        if plugin.snapshot:
            step["snapshot"] = True
        steps.append(step)
        last_step_id = install_id

        if plugin.env_template:
            env_id = f"write_env_{plugin.id}"
            steps.append(
                {
                    "id": env_id,
                    "action": "write_env",
                    "plugin": plugin.id,
                    "from": plugin.env_template,
                    "depends_on": [install_id],
                }
            )
            last_step_id = env_id

        start_deps.append(last_step_id)

    # "install_ext_<id>" rather than "install_<id>": a plugin and an
    # extension can legitimately share an id (they install to different
    # target directories — see Layout.plugin_dir vs extension_dir), and step
    # ids must stay unique across the whole plan (InstallPlan._validate_graph).
    for extension in options.extensions:
        install_id = f"install_ext_{extension.id}"
        step = {"id": install_id, "action": "install_extension", "extension": extension.id}
        if extension.snapshot:
            step["snapshot"] = True
        steps.append(step)
        start_deps.append(install_id)

    steps.append({"id": "start", "action": "start", "depends_on": start_deps})

    if options.with_healthcheck:
        steps.append(
            {
                "id": "healthcheck",
                "action": "healthcheck",
                "depends_on": ["start"],
                "timeout": options.healthcheck_timeout,
                "retries": options.healthcheck_retries,
            }
        )

    plan_dict = {
        "format_version": "1",
        "project_id": options.project_id,
        "version": options.version,
        "steps": steps,
    }
    InstallPlan.model_validate(plan_dict)  # raises ValidationError if scaffolding is inconsistent
    return plan_dict


def render_install_plan_yaml(plan_dict: dict[str, Any]) -> str:
    return yaml.safe_dump(plan_dict, sort_keys=False)
