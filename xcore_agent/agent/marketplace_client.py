"""Client for the *real* xcore-team/marketplace API — not the invented
`.xdeploy`/DEK/Ed25519 contract in `hub_client.py`.

Verified against the actual backend (xcore-team/marketplace, app/marketplace
and app/xdevkeys). The two contracts are structurally different enough that
this is a separate client + separate pipeline (`marketplace_pipeline.py`)
rather than a drop-in `HubClient` implementation:

  - Auth is a static `X-API-Key: xdk_...` header (from `POST /xdevkeys/api-keys`),
    not a login exchange producing a bearer token.
  - There is no "project": one deployment fetches one plugin or one service
    (xservices calls these "extensions"), identified by its marketplace slug.
  - `GET /{plugins|services}/{slug}/install?version=latest|<version>` returns
    the plugin's source tree as a **plain ZIP** (GitHub's zipball, not an
    encrypted `.xdeploy` container) plus response headers:
      X-Signature: hmac_sha256:<hex>
      X-Plugin / X-Service: name@version
      X-Repo: owner/repo@tag
  - The signature is HMAC-SHA256, not Ed25519 — see
    `crypto.verify_hmac_sha256_hex` for what that means for the trust model.
  - Deployment status is reported via `POST /deployments/report`
    (`app/xdeployments` on the backend) — a log entry per attempt, scoped to
    the API key holder (the operator), not the plugin's publisher, since
    deploying a public plugin doesn't require owning it. `report_deployment`
    is best-effort: a reporting failure never fails a deployment that
    otherwise succeeded or failed on its own terms.
  - The Hub is an XCore instance: every plugin is mounted at a fixed
    `/app/<plugin-name>` prefix (root `integration.yaml`: `plugin_prefix:
    "/app"` — a framework-level convention, not a dev-only artifact, so this
    applies in production too, absent any reverse proxy rewriting paths).
    Plugin artifacts live under the `marketplace` plugin, service artifacts
    under `xservices`, and deployment reporting under a *third*, separate
    `xdeployments` plugin — `base_url` is therefore the Hub's bare root
    (e.g. `https://marketplace.xcorehub.dev`, no plugin segment), and each
    request below picks its own `/app/<plugin-name>` mount internally so
    callers never need to know this backend's internal plugin layout.
"""

from dataclasses import dataclass
from types import TracebackType
from typing import Literal

import httpx

from .errors import ArtifactError

Kind = Literal["plugin", "service"]
DeploymentStatus = Literal["success", "failed", "rolled_back"]

# XCore's fixed plugin-mount prefix (root integration.yaml: plugin_prefix: "/app").
_HUB_PLUGIN_PREFIX = "/app"

# Which XCore plugin serves each marketplace `Kind`'s artifacts.
_KIND_HUB_PLUGIN: dict[Kind, str] = {"plugin": "marketplace", "service": "xservices"}

# Deployment reporting lives in its own plugin, independent of `Kind`.
_DEPLOYMENTS_HUB_PLUGIN = "xdeployments"


@dataclass(frozen=True)
class FetchedArtifact:
    data: bytes
    signature_header: str  # raw "hmac_sha256:<hex>" header value
    plugin_header: str  # "name@version", from X-Plugin or X-Service
    repo_header: str  # "owner/repo@tag", from X-Repo


def _kind_path(kind: Kind) -> str:
    return "plugins" if kind == "plugin" else "services"


def _mount(plugin_name: str) -> str:
    """`/app/<plugin_name>` — where the given XCore plugin's routes live."""
    return f"{_HUB_PLUGIN_PREFIX}/{plugin_name}"


class MarketplaceClient:
    """HTTP client for the real xcore-team/marketplace API.

    `base_url` is the Hub's bare root (no `/app/...` segment — see module
    docstring); `transport` exists so tests can inject `httpx.MockTransport`
    instead of hitting the network, production callers leave it as `None`.
    """

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str,
        timeout: float = 60.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._api_key = api_key
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=timeout,
            transport=transport,
            # See HttpHubClient's identical setting for why — an unfollowed
            # HTTP->HTTPS redirect silently truncates a response to its
            # ~17-byte "Moved Permanently" body instead of raising, which
            # then fails signature verification with no hint that a
            # redirect (not a bad signature) was the real cause. No
            # security cost here either: every response this client trusts
            # is authenticated by content (HMAC-SHA256 over the fetched
            # bytes), not by transport.
            follow_redirects=True,
        )

    async def __aenter__(self) -> "MarketplaceClient":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def get_latest_version(self, *, slug: str, kind: Kind = "plugin") -> str:
        """Poll target for `agent.watcher.Watcher` — reads the public
        `GET /{kind}/{slug}` detail route, which reports `latest_version`."""
        mount = _mount(_KIND_HUB_PLUGIN[kind])
        response = await self._client.get(f"{mount}/{_kind_path(kind)}/{slug}")
        _raise_for_status(response, "get_latest_version")
        latest = response.json().get("latest_version")
        if not latest:
            raise ArtifactError(f"{kind} {slug!r} has no published version yet")
        return str(latest)

    async def fetch_artifact(
        self, *, slug: str, version: str = "latest", kind: Kind = "plugin"
    ) -> FetchedArtifact:
        mount = _mount(_KIND_HUB_PLUGIN[kind])
        response = await self._client.get(
            f"{mount}/{_kind_path(kind)}/{slug}/install",
            params={"version": version},
            headers={"X-API-Key": self._api_key},
        )
        if response.status_code == 401:
            raise ArtifactError(f"API key rejected: {_error_message(response)}")
        _raise_for_status(response, "fetch_artifact")

        signature = response.headers.get("X-Signature")
        if not signature:
            raise ArtifactError("Hub response is missing the X-Signature header")
        plugin_header = response.headers.get("X-Plugin") or response.headers.get("X-Service") or ""
        repo_header = response.headers.get("X-Repo", "")

        return FetchedArtifact(
            data=response.content,
            signature_header=signature,
            plugin_header=plugin_header,
            repo_header=repo_header,
        )

    async def report_deployment(
        self,
        *,
        kind: Kind,
        slug: str,
        version: str,
        status: DeploymentStatus,
        started_at: str,
        completed_at: str,
        host_id: str = "default",
        repo: str = "",
        error_message: str | None = None,
    ) -> None:
        """Report the outcome of one deployment attempt. `started_at`/`completed_at`
        are ISO-8601 strings (`MarketplaceDeploymentReport` already stores them that
        way). Raises ArtifactError on failure — callers that want "best-effort"
        (recommended; see class docstring) should catch it themselves rather than
        rely on this method swallowing errors, so tests and callers stay in control
        of that choice."""
        mount = _mount(_DEPLOYMENTS_HUB_PLUGIN)
        response = await self._client.post(
            f"{mount}/deployments/report",
            headers={"X-API-Key": self._api_key},
            json={
                "kind": kind,
                "slug": slug,
                "version": version,
                "status": status,
                "started_at": started_at,
                "completed_at": completed_at,
                "host_id": host_id,
                "repo": repo or None,
                "error_message": error_message,
            },
        )
        if response.status_code == 401:
            raise ArtifactError(f"API key rejected: {_error_message(response)}")
        _raise_for_status(response, "report_deployment")


def _error_message(response: httpx.Response) -> str:
    try:
        body = response.json()
        if isinstance(body, dict) and "detail" in body:
            return str(body["detail"])
        return str(body)
    except ValueError:
        return response.text[:200]


def _raise_for_status(response: httpx.Response, operation: str) -> None:
    if response.is_error:
        raise ArtifactError(
            f"{operation} failed: HTTP {response.status_code}: {_error_message(response)}"
        )
