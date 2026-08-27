"""Schema for `manifest.json` — the plaintext description of a `.xdeploy` artifact's
contents, hashed and referenced by the outer signature so the agent can verify
what it received matches what was built, independently of the encryption layer.
"""

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PROJECT_ID_RE = re.compile(r"^prj_[A-Za-z0-9]{10,40}$")
_PLUGIN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
# A relative path, one or more `/`-separated segments, none of them `.`/`..`
# — deliberately stricter than an arbitrary path: this is a single directory
# name inside a trusted `.xdeploy` artifact, not user-supplied filesystem
# input, so there's no reason to allow anything an attacker could use to
# climb out of the extracted tree.
_PLUGINS_DIRNAME_RE = re.compile(r"^[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*$")


def _validate_sha256(v: str) -> str:
    if not _SHA256_RE.match(v):
        raise ValueError(f"invalid sha256 digest {v!r}")
    return v


class EnvironmentSpec(BaseModel):
    """A plugin's declared `.env` contract — which variables the host
    operator must fill in before the plugin can start. `write_env`
    (agent/install_driver.py) checks `required` against the actual env
    file after seeding it from the template."""

    model_config = {"extra": "forbid"}

    required: list[str] = Field(default_factory=list)
    optional: list[str] = Field(default_factory=list)


class PluginSource(BaseModel):
    """Where to fetch a plugin's code from instead of (or in addition to)
    what's embedded in the `.xdeploy` artifact — typically handed out by a
    marketplace/registry as a resolvable link.

    Exactly one origin, not both:

    - **Marketplace (preferred)** — `marketplace_slug` (+ optional
      `marketplace_version`/`marketplace_kind`). Resolved at deploy time via
      the real xcore-team/marketplace `GET /{slug}/install` endpoint
      (`agent.marketplace_client.MarketplaceClient`), whose response is
      HMAC-SHA256-signed — see `plugin_resolver.PluginResolver._resolve_
      marketplace`. This is `xcli`'s default when it writes `.xcore-
      registry.json` for a plugin installed *from* the marketplace (see
      `xcli`'s `shared.record_install`): the marketplace is the
      authoritative origin for anything published there, not an
      alternative to git.
    - **Git (fallback)** — `url` + `ref`, for a plugin never published to
      the marketplace (an operator's own private fork, something still
      under development). `ref` should be a commit SHA whenever integrity
      matters: it's the only form that's content-addressed, so pinning to
      one lets `PluginRef.sha256` (computed over the resolved tree) actually
      mean something. A branch or tag is mutable — the code behind it can
      change without `sha256` in the manifest ever being updated, silently
      defeating the tamper check.

    A marketplace-sourced plugin gets an equivalent integrity guarantee for
    free from the HMAC signature itself (verified against the publisher's
    `signing_secret` on every fetch), independently of whether `PluginRef.
    sha256` is also pinned.
    """

    model_config = {"extra": "forbid"}

    marketplace_slug: str | None = None
    marketplace_version: str = "latest"
    marketplace_kind: Literal["plugin", "service"] = "plugin"

    url: str | None = None
    ref: str | None = None
    subdirectory: str | None = None

    @model_validator(mode="after")
    def _exactly_one_origin(self) -> "PluginSource":
        has_marketplace = self.marketplace_slug is not None
        has_git = self.url is not None
        if has_marketplace == has_git:  # both set, or neither
            raise ValueError(
                "PluginSource needs exactly one origin: either 'marketplace_slug' "
                "(preferred — resolved from the marketplace) or 'url' (+'ref', git "
                "fallback for a plugin not published there), not both or neither"
            )
        if has_git and self.ref is None:
            raise ValueError("git source ('url') requires 'ref'")
        return self


class PluginRef(BaseModel):
    model_config = {"extra": "forbid"}

    id: str
    version: str
    # Required for an embedded plugin (hash of its files inside the
    # artifact). Optional for a `source`-based plugin: the packer doesn't
    # fetch external repositories at build time, so it has nothing to hash
    # unless the caller pins one out of band. When present, the agent still
    # verifies it against the resolved tree after fetching — see
    # agent/pipeline.py's plugin resolution stage.
    sha256: str | None = None
    environment: EnvironmentSpec | None = None
    source: PluginSource | None = None

    @field_validator("id")
    @classmethod
    def _valid_id(cls, v: str) -> str:
        if not _PLUGIN_ID_RE.match(v):
            raise ValueError(f"invalid plugin id {v!r}")
        return v

    @field_validator("version")
    @classmethod
    def _valid_version(cls, v: str) -> str:
        if not _SEMVER_RE.match(v):
            raise ValueError(f"invalid semantic version {v!r}")
        return v

    @field_validator("sha256")
    @classmethod
    def _valid_sha256(cls, v: str | None) -> str | None:
        return v if v is None else _validate_sha256(v)

    @model_validator(mode="after")
    def _require_hash_for_embedded_plugins(self) -> "PluginRef":
        if self.source is None and self.sha256 is None:
            raise ValueError(
                f"plugin {self.id!r} has no 'source' — it's embedded in the artifact, "
                "so 'sha256' is required"
            )
        return self


class ExtensionRef(BaseModel):
    """A shared, non-plugin service bundled into the artifact (e.g.
    `extensions/xmailler`) — embedded by default, OR resolved from git at
    deploy time via `source` (see `extensions/<id>/extension.yaml` —
    `PluginSource` reused verbatim; the field name stays `source` for
    symmetry with `PluginRef.source`, there's nothing plugin-specific about
    it). Same rule as `PluginRef`: `sha256` is required unless `source` is
    set — nothing to hash for a repo the packer never fetches at build time."""

    model_config = {"extra": "forbid"}

    id: str
    sha256: str | None = None
    source: PluginSource | None = None

    @field_validator("id")
    @classmethod
    def _valid_id(cls, v: str) -> str:
        if not _PLUGIN_ID_RE.match(v):
            raise ValueError(f"invalid extension id {v!r}")
        return v

    @field_validator("sha256")
    @classmethod
    def _valid_sha256(cls, v: str | None) -> str | None:
        return v if v is None else _validate_sha256(v)

    @model_validator(mode="after")
    def _require_hash_for_embedded_extensions(self) -> "ExtensionRef":
        if self.source is None and self.sha256 is None:
            raise ValueError(
                f"extension {self.id!r} has no 'source' — it's embedded in the artifact, "
                "so 'sha256' is required"
            )
        return self


class ProjectManifest(BaseModel):
    """Describes one built version of a project's `.xdeploy` artifact."""

    model_config = {"extra": "forbid"}

    format_version: str = Field(..., pattern=r"^\d+$")
    project_id: str
    project_name: str
    version: str
    built_at: datetime
    plugins: list[PluginRef] = Field(..., min_length=1)
    # Optional and separate from `plugins`: a project with no extensions/
    # directory at all is the common case, not an error (unlike plugins,
    # where an empty list is rejected in write_manifest — see builder.py).
    extensions: list[ExtensionRef] = Field(default_factory=list)
    # Which top-level directory `plugins` were embedded under inside this
    # artifact — read at build time from the source project's own
    # `integration.yaml` (`plugins.directory`, e.g. `./app`), so a project
    # that doesn't use the `plugins/` convention still round-trips through
    # build -> deploy correctly. Defaults to "plugins" so an artifact built
    # before this field existed (or a project that never overrides the
    # default) still parses the same as always — see packer/builder.py and
    # agent/pipeline.py/install_driver.py for where it's read back.
    plugins_dirname: str = "plugins"
    content_sha256: str

    @field_validator("plugins_dirname")
    @classmethod
    def _valid_plugins_dirname(cls, v: str) -> str:
        if not _PLUGINS_DIRNAME_RE.match(v):
            raise ValueError(f"invalid plugins_dirname {v!r}")
        return v

    @field_validator("project_id")
    @classmethod
    def _valid_project_id(cls, v: str) -> str:
        if not _PROJECT_ID_RE.match(v):
            raise ValueError(f"invalid project id {v!r}")
        return v

    @field_validator("version")
    @classmethod
    def _valid_version(cls, v: str) -> str:
        if not _SEMVER_RE.match(v):
            raise ValueError(f"invalid semantic version {v!r}")
        return v

    @field_validator("content_sha256")
    @classmethod
    def _valid_content_sha256(cls, v: str) -> str:
        return _validate_sha256(v)

    def plugin(self, plugin_id: str) -> PluginRef:
        for p in self.plugins:
            if p.id == plugin_id:
                return p
        raise KeyError(plugin_id)

    def extension(self, extension_id: str) -> ExtensionRef:
        for e in self.extensions:
            if e.id == extension_id:
                return e
        raise KeyError(extension_id)
