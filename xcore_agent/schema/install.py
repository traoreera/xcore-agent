"""Schema and validation for `install.yaml` — the deployment plan shipped inside
a `.xdeploy` artifact.

Every step's `action` is restricted to a fixed, closed enum of verbs the agent
knows how to execute safely. There is intentionally no generic "run a shell
command" action: a malicious or tampered artifact must not be able to turn
xcore-agent into an arbitrary remote-execution primitive.
"""

import re
from typing import Annotated, Literal, Union

from pydantic import BaseModel, Field, field_validator, model_validator

from .manifest import PluginSource

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_PLUGIN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
_DURATION_RE = re.compile(r"^(\d+)(s|m)$")


def _parse_duration_string(value: str) -> int:
    match = _DURATION_RE.match(value.strip())
    if not match:
        raise ValueError(f"invalid duration {value!r}: expected e.g. '30s' or '5m'")
    amount, unit = match.groups()
    return int(amount) * (60 if unit == "m" else 1)


class _StepBase(BaseModel):
    model_config = {"extra": "forbid"}

    id: str
    depends_on: list[str] = Field(default_factory=list)
    snapshot: bool = False

    @field_validator("id")
    @classmethod
    def _valid_id(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError(f"invalid step id {v!r}: must match {_ID_RE.pattern}")
        return v


class _PluginStepBase(_StepBase):
    plugin: str

    @field_validator("plugin")
    @classmethod
    def _valid_plugin(cls, v: str) -> str:
        if not _PLUGIN_ID_RE.match(v):
            raise ValueError(f"invalid plugin id {v!r}: must match {_PLUGIN_ID_RE.pattern}")
        return v


class _ExtensionStepBase(_StepBase):
    """Mirrors `_PluginStepBase` for `extensions/<id>` — a shared, non-plugin
    service bundled into the artifact (see manifest.ExtensionRef). Separate
    field/id namespace from `plugin` on purpose: a project can legitimately
    have a plugin and an extension that share the same id (they install to
    different target directories — see Layout.plugin_dir vs
    Layout.extension_dir), so step ids must not collide either — see
    scaffold.py's `install_ext_<id>` vs `install_<id>` prefixing."""

    extension: str

    @field_validator("extension")
    @classmethod
    def _valid_extension(cls, v: str) -> str:
        if not _PLUGIN_ID_RE.match(v):
            raise ValueError(f"invalid extension id {v!r}: must match {_PLUGIN_ID_RE.pattern}")
        return v


class PrepareStep(_StepBase):
    action: Literal["prepare"] = "prepare"


class DownloadStep(_StepBase):
    action: Literal["download"] = "download"


class ExtractStep(_StepBase):
    action: Literal["extract"] = "extract"


class ProvisionStep(_PluginStepBase):
    action: Literal["provision"] = "provision"


class InstallPluginStep(_PluginStepBase):
    action: Literal["install_plugin"] = "install_plugin"
    # Where to fetch this plugin's code from — marketplace slug (preferred)
    # or git (fallback), same `PluginSource` the packer would otherwise read
    # off the plugin's own plugin.yaml (see packer.builder._read_plugin_
    # source) or `.xcore-registry.json` (_read_registry_source). Declaring
    # it here instead keeps plugin.yaml itself untouched — a project that
    # wants its deployment-time origins centralized in one reviewable file
    # (this one) rather than scattered across every plugin's own manifest.
    # Checked first when the packer resolves a plugin's source at build
    # time (see write_manifest); plugin.yaml's own `source:` and the
    # registry are still consulted, in that order, if this step has none.
    source: PluginSource | None = None


class InstallExtensionStep(_ExtensionStepBase):
    action: Literal["install_extension"] = "install_extension"
    # Mirrors InstallPluginStep.source, for extensions — see its docstring.
    source: PluginSource | None = None


class NotifyStep(_StepBase):
    """Tells the agent's `notify()` a named event happened at this point in
    the plan — never a URL/webhook/recipient itself (same reasoning as
    `ProvisionStep.plugin`: the artifact only supplies an opaque label, the
    real destination is host-side operator config, see `agent.notifiers`).
    A missing or failing notifier never fails the deployment — notifying is
    a side channel, not part of what makes an install succeed or fail."""

    action: Literal["notify"] = "notify"
    event: str
    # Optional human-readable text for the notifier to use as-is, e.g.
    # "auth deployed successfully" — not a template, no placeholder
    # substitution happens on it.
    message: str | None = None

    @field_validator("event")
    @classmethod
    def _valid_event(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError(f"invalid notify event {v!r}: must match {_ID_RE.pattern}")
        return v


class ConfigurePluginStep(_PluginStepBase):
    action: Literal["configure_plugin"] = "configure_plugin"


class WriteEnvStep(_PluginStepBase):
    action: Literal["write_env"] = "write_env"
    from_: str = Field(..., alias="from")

    @field_validator("from_")
    @classmethod
    def _relative_path_only(cls, v: str) -> str:
        if v.startswith("/") or v.startswith("~") or ".." in v.split("/"):
            raise ValueError(f"'from' must be a relative path inside the artifact, got {v!r}")
        return v


class StartStep(_StepBase):
    action: Literal["start"] = "start"
    plugin: str | None = None


class StopStep(_StepBase):
    action: Literal["stop"] = "stop"
    plugin: str | None = None


class RestartStep(_StepBase):
    action: Literal["restart"] = "restart"
    plugin: str | None = None


class HealthcheckStep(_StepBase):
    action: Literal["healthcheck"] = "healthcheck"
    plugin: str | None = None
    timeout_seconds: int = Field(default=30, gt=0, le=600, alias="timeout")
    retries: int = Field(default=3, ge=0, le=20)

    @field_validator("timeout_seconds", mode="before")
    @classmethod
    def _parse_duration(cls, v: object) -> object:
        if isinstance(v, str):
            return _parse_duration_string(v)
        return v


class RollbackStep(_StepBase):
    action: Literal["rollback"] = "rollback"
    to: str | None = None


Step = Annotated[
    Union[
        PrepareStep,
        DownloadStep,
        ExtractStep,
        ProvisionStep,
        InstallPluginStep,
        InstallExtensionStep,
        ConfigurePluginStep,
        WriteEnvStep,
        NotifyStep,
        StartStep,
        StopStep,
        RestartStep,
        HealthcheckStep,
        RollbackStep,
    ],
    Field(discriminator="action"),
]


def _topological_order(ids: list[str], deps: dict[str, list[str]]) -> list[str]:
    state: dict[str, int] = {}  # 0 = unvisited, 1 = in progress, 2 = done
    order: list[str] = []

    def visit(node: str, path: list[str]) -> None:
        mark = state.get(node, 0)
        if mark == 2:
            return
        if mark == 1:
            cycle = " -> ".join([*path, node])
            raise ValueError(f"dependency cycle detected: {cycle}")
        state[node] = 1
        for dep in deps.get(node, []):
            visit(dep, [*path, node])
        state[node] = 2
        order.append(node)

    for node_id in ids:
        visit(node_id, [])
    return order


class InstallPlan(BaseModel):
    """Parsed, validated `install.yaml`."""

    model_config = {"extra": "forbid"}

    format_version: Literal["1"]
    project_id: str
    version: str
    steps: list[Step] = Field(..., min_length=1)

    @model_validator(mode="after")
    def _validate_graph(self) -> "InstallPlan":
        seen: set[str] = set()
        for step in self.steps:
            if step.id in seen:
                raise ValueError(f"duplicate step id: {step.id!r}")
            seen.add(step.id)

        for step in self.steps:
            for dep in step.depends_on:
                if dep not in seen:
                    raise ValueError(f"step {step.id!r} depends_on unknown step {dep!r}")
                if dep == step.id:
                    raise ValueError(f"step {step.id!r} cannot depend on itself")

        # Raises on cycles; result is reused by execution_order() at call time
        # rather than cached here, since it's cheap and keeps the model simple.
        _topological_order([s.id for s in self.steps], {s.id: s.depends_on for s in self.steps})
        return self

    def execution_order(self) -> list[str]:
        """Return step ids in an order that respects every `depends_on` edge."""
        return _topological_order(
            [s.id for s in self.steps], {s.id: s.depends_on for s in self.steps}
        )

    def step(self, step_id: str) -> "Step":
        for s in self.steps:
            if s.id == step_id:
                return s
        raise KeyError(step_id)
