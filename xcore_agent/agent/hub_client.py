"""Client interface for talking to XCore Hub.

`HubClient` is the contract the deployment pipeline depends on. `HttpHubClient`
implements it against a REST contract *proposed* here — inferred from the
project's architecture notes (XDevKey vs. deployment credential, the
authenticate -> request_artifact -> download -> obtain_deployment_key ->
notify sequence, the DeploymentReport shape) rather than from a published
Hub API spec, because XCore Hub itself does not exist yet. Treat the routes
below as a concrete starting point for building the real Hub against, or
adjust this client once the real Hub's endpoints are decided — nothing else
in xcore-agent needs to change either way, since everything else talks to
`HubClient` the protocol, not to `HttpHubClient` the implementation.

Proposed contract (all bodies JSON, bearer auth via the session's access
token except /v1/auth itself; binary fields are base64):

    POST /v1/auth
        -> {xdevkey, project_id}
        <- {access_token}

    GET /v1/projects/{project_id}/versions/latest
        <- {version}

    GET /v1/projects/{project_id}/artifacts/{version}
        <- {download_url, signature, signer_public_key}

    GET <download_url>                          (may be a different host,
        <- raw bytes                              e.g. signed blob storage)

    POST /v1/deployments/authorize
        -> {deployment_credential, artifact_signature}
        <- {dek}                                  (revocation is enforced here)

    POST /v1/deployments/report
        -> DeploymentReport fields
        <- {deployment_id}

    POST /v1/projects/{project_id}/publish                      (validated against
        -> multipart/form-data:                                   a real XCore Hub —
             version, project_name, content_sha256,                see app/xdeploy in
             dek (base64), signature (base64),                     the Marketplace repo)
             signer_public_key (base64), artifact (file)
        -> header: X-API-Key: <xdevkey>       (not session-bearer — publish is a
                                                 local build-time act, not a
                                                 deployment; no prior /v1/auth needed)
        <- {artifact_id, project_id, version, content_sha256, size_bytes, created_at}
"""

import base64
from dataclasses import dataclass
from types import TracebackType
from typing import Protocol

import httpx

from .errors import ArtifactError, AuthenticationError, DeploymentError, PublishError


@dataclass(frozen=True)
class Session:
    """An authenticated session against XCore Hub."""

    project_id: str
    access_token: str


@dataclass(frozen=True)
class ArtifactLocation:
    """Where to fetch a specific artifact version from, plus the outer
    signature so the agent can verify authenticity before spending time
    decrypting a (possibly large) ciphertext body."""

    download_url: str
    signature: bytes
    signer_public_key: bytes


@dataclass(frozen=True)
class PublishResult:
    """What XCore Hub confirms after accepting a newly published artifact."""

    artifact_id: str
    project_id: str
    version: str
    content_sha256: str
    size_bytes: int
    created_at: str


@dataclass(frozen=True)
class DeploymentReport:
    project_id: str
    deployment_id: str
    status: str  # "success" | "failed"
    version: str
    started_at: str
    completed_at: str
    plugins: list[dict]


class HubClient(Protocol):
    async def authenticate(self, *, xdevkey: str, project_id: str) -> Session: ...

    async def get_latest_version(self, session: Session, *, project_id: str) -> str:
        """Return the version/tag XCore Hub currently considers the latest
        release for this project. This is the primitive the CI/CD watch loop
        (`agent.watcher.Watcher`) polls to notice a new version has been
        published and trigger an automatic redeploy."""
        ...

    async def request_artifact(self, session: Session, *, version: str) -> ArtifactLocation: ...

    async def download(self, location: ArtifactLocation) -> bytes: ...

    async def obtain_deployment_key(
        self, session: Session, *, deployment_credential: str, artifact_signature: bytes
    ) -> bytes:
        """Ask the Hub to unwrap and return the artifact's DEK.

        The Hub is the only party that ever holds the KEK; this call is also
        where access revocation is enforced (a revoked XDevKey or expired
        deployment credential must be rejected here, before any bytes are
        decrypted) — see the project's architecture notes.
        """
        ...

    async def notify(self, session: Session, report: DeploymentReport) -> None: ...

    async def publish(
        self,
        *,
        xdevkey: str,
        project_id: str,
        project_name: str,
        version: str,
        ciphertext: bytes,
        content_sha256: str,
        dek: bytes,
        signature: bytes,
        signer_public_key: bytes,
    ) -> PublishResult:
        """Upload a freshly built artifact (see `packer.builder.build_artifact`)
        to XCore Hub for storage. Authenticated by raw `xdevkey`, not a
        `Session` — publishing is a local build-time act performed before
        any agent ever calls `authenticate`/`/v1/auth` for this artifact."""
        ...


@dataclass
class InMemoryHubClient:
    """`HubClient` implemented entirely in memory, serving one pre-built
    artifact — for exercising `DeploymentRunner` end-to-end (signature
    verification, AES-GCM decryption, manifest/content-hash checks,
    install/rollback) without a live Hub, since `HttpHubClient` speaks to a
    Hub that does not exist yet (see this module's docstring).

    Not a test-only mock kept private to one test file: it is the supported
    way to drive the real pipeline against a real, locally-built `.xdeploy`
    artifact — construct it with the exact `(ciphertext, dek, signature,
    signer_public_key)` tuple `packer.builder.build_artifact`/`seal_directory`
    returned, and it will behave, from `DeploymentRunner`'s point of view,
    like a Hub that already has that artifact stored and ready to serve.
    `notified` records every `notify()` call for the caller to assert on.
    """

    ciphertext: bytes
    dek: bytes
    signature: bytes
    signer_public_key: bytes
    notified: list[DeploymentReport] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.notified is None:
            self.notified = []

    async def authenticate(self, *, xdevkey: str, project_id: str) -> Session:
        return Session(project_id=project_id, access_token="in-memory-session")

    async def get_latest_version(self, session: Session, *, project_id: str) -> str:
        raise NotImplementedError(
            "InMemoryHubClient serves one fixed artifact — it has no notion of "
            "'latest version' distinct from what it was constructed with; the "
            "watch loop (agent.watcher.Watcher) has no use for this client"
        )

    async def request_artifact(self, session: Session, *, version: str) -> ArtifactLocation:
        return ArtifactLocation(
            download_url="in-memory://artifact",
            signature=self.signature,
            signer_public_key=self.signer_public_key,
        )

    async def download(self, location: ArtifactLocation) -> bytes:
        return self.ciphertext

    async def obtain_deployment_key(
        self, session: Session, *, deployment_credential: str, artifact_signature: bytes
    ) -> bytes:
        return self.dek

    async def notify(self, session: Session, report: DeploymentReport) -> None:
        self.notified.append(report)

    async def publish(
        self,
        *,
        xdevkey: str,
        project_id: str,
        project_name: str,
        version: str,
        ciphertext: bytes,
        content_sha256: str,
        dek: bytes,
        signature: bytes,
        signer_public_key: bytes,
    ) -> PublishResult:
        raise NotImplementedError(
            "InMemoryHubClient is pre-seeded with one fixed artifact for "
            "exercising DeploymentRunner — it has no publish-time storage to "
            "accept a new one into; nothing in the deployment pipeline calls "
            "publish() anyway (it's a CLI build-time act, see cli.py::publish)"
        )


def _auth_header(session: Session) -> dict[str, str]:
    return {"Authorization": f"Bearer {session.access_token}"}


def _error_message(response: httpx.Response) -> str:
    try:
        body = response.json()
        if isinstance(body, dict) and "error" in body:
            return str(body["error"])
        return str(body)
    except ValueError:
        return response.text[:200]


def _raise_for_status(response: httpx.Response, error_cls: type[Exception], operation: str) -> None:
    if response.is_error:
        raise error_cls(
            f"{operation} failed: HTTP {response.status_code}: {_error_message(response)}"
        )


_MOUNT = "/app/xdeploy"


class HttpHubClient:
    """HTTP implementation of `HubClient` against the real xcore-team/xdeploy
    plugin (`app/xdeploy`) — validated end to end against a live Hub
    (build -> publish -> a real `POST /app/xdeploy/v1/projects/{id}/publish`
    that stored the artifact).

    `base_url` is the Hub's bare root (no `/app/...` segment — same
    convention as `marketplace_client.MarketplaceClient`); every request
    below prepends its own `/app/xdeploy` mount internally so callers never
    need to know this backend's internal plugin layout. Every xcore plugin
    (including this one) is mounted under `/app/<plugin-name>` by the xcore
    router — the previous bare `/v1/...` paths here were a "proposed
    contract" written before any real Hub existed to validate against, and
    were 404ing against the real one.

    `transport` exists so tests can inject `httpx.MockTransport` instead of
    hitting the network; production callers leave it as `None`.
    """

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=timeout,
            transport=transport,
            # `download_url` (from request_artifact) has come back as a bare
            # `http://` URL in production while the Hub itself is HTTPS-only
            # — the reverse proxy 301s to https://, and httpx does NOT
            # follow redirects by default. Without this, `download()` was
            # silently returning the redirect response's ~17-byte HTML body
            # ("Moved Permanently") instead of the artifact, which then
            # failed signature verification with no indication that the
            # actual problem was a followed-nowhere redirect, not a bad
            # signature. Real artifacts should never redirect again after
            # this, but there is no security cost to allowing it either:
            # every response we actually trust is authenticated by content
            # (Ed25519 signature over the downloaded bytes, HMAC for the
            # marketplace) rather than by transport, so a redirect changes
            # where the bytes came from, never whether they're trusted.
            follow_redirects=True,
        )

    async def __aenter__(self) -> "HttpHubClient":
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

    async def authenticate(self, *, xdevkey: str, project_id: str) -> Session:
        response = await self._client.post(
            f"{_MOUNT}/v1/auth", json={"xdevkey": xdevkey, "project_id": project_id}
        )
        if response.status_code in (401, 403):
            raise AuthenticationError(f"authentication failed: {_error_message(response)}")
        _raise_for_status(response, DeploymentError, "authenticate")
        return Session(project_id=project_id, access_token=response.json()["access_token"])

    async def get_latest_version(self, session: Session, *, project_id: str) -> str:
        response = await self._client.get(
            f"{_MOUNT}/v1/projects/{project_id}/versions/latest", headers=_auth_header(session)
        )
        _raise_for_status(response, ArtifactError, "get_latest_version")
        return str(response.json()["version"])

    async def request_artifact(self, session: Session, *, version: str) -> ArtifactLocation:
        response = await self._client.get(
            f"{_MOUNT}/v1/projects/{session.project_id}/artifacts/{version}",
            headers=_auth_header(session),
        )
        _raise_for_status(response, ArtifactError, "request_artifact")
        data = response.json()
        return ArtifactLocation(
            download_url=data["download_url"],
            signature=base64.b64decode(data["signature"]),
            signer_public_key=base64.b64decode(data["signer_public_key"]),
        )

    async def download(self, location: ArtifactLocation) -> bytes:
        response = await self._client.get(location.download_url)
        _raise_for_status(response, ArtifactError, "download")
        return response.content

    async def obtain_deployment_key(
        self, session: Session, *, deployment_credential: str, artifact_signature: bytes
    ) -> bytes:
        response = await self._client.post(
            f"{_MOUNT}/v1/deployments/authorize",
            headers=_auth_header(session),
            json={
                "deployment_credential": deployment_credential,
                "artifact_signature": base64.b64encode(artifact_signature).decode("ascii"),
            },
        )
        if response.status_code in (401, 403):
            raise AuthenticationError(
                f"deployment key authorization denied: {_error_message(response)}"
            )
        _raise_for_status(response, ArtifactError, "obtain_deployment_key")
        return base64.b64decode(response.json()["dek"])

    async def notify(self, session: Session, report: DeploymentReport) -> None:
        response = await self._client.post(
            f"{_MOUNT}/v1/deployments/report",
            headers=_auth_header(session),
            json={
                "project_id": report.project_id,
                "deployment_id": report.deployment_id,
                "status": report.status,
                "version": report.version,
                "started_at": report.started_at,
                "completed_at": report.completed_at,
                "plugins": report.plugins,
            },
        )
        _raise_for_status(response, DeploymentError, "notify")

    async def publish(
        self,
        *,
        xdevkey: str,
        project_id: str,
        project_name: str,
        version: str,
        ciphertext: bytes,
        content_sha256: str,
        dek: bytes,
        signature: bytes,
        signer_public_key: bytes,
    ) -> PublishResult:
        response = await self._client.post(
            f"{_MOUNT}/v1/projects/{project_id}/publish",
            headers={"X-API-Key": xdevkey},
            data={
                "version": version,
                "project_name": project_name,
                "content_sha256": content_sha256,
                "dek": base64.b64encode(dek).decode("ascii"),
                "signature": base64.b64encode(signature).decode("ascii"),
                "signer_public_key": base64.b64encode(signer_public_key).decode("ascii"),
            },
            files={"artifact": ("artifact.xdeploy", ciphertext, "application/octet-stream")},
        )
        if response.status_code in (401, 403):
            raise AuthenticationError(f"publish denied: {_error_message(response)}")
        _raise_for_status(response, PublishError, "publish")
        data = response.json()
        return PublishResult(
            artifact_id=data["artifact_id"],
            project_id=data["project_id"],
            version=data["version"],
            content_sha256=data["content_sha256"],
            size_bytes=data["size_bytes"],
            created_at=data["created_at"],
        )
