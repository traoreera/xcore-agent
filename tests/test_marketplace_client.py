"""Tests for MarketplaceClient against the real xcore-team/marketplace API
contract (X-API-Key auth, HMAC-signed plain ZIP, no auth exchange, no DEK) —
see marketplace_client.py's module docstring for how this differs from the
proposed contract HttpHubClient speaks.
"""

import json

import httpx
import pytest

from xcore_agent.agent.errors import ArtifactError
from xcore_agent.agent.marketplace_client import MarketplaceClient


def _json_response(status_code: int, payload: dict) -> httpx.Response:
    return httpx.Response(status_code, json=payload)


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch):
    """Every retry test below exercises the real backoff loop — patch
    asyncio.sleep to a no-op so they run instantly instead of taking
    seconds, without touching the retry logic itself."""

    async def _instant_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr("xcore_agent.agent.marketplace_client.asyncio.sleep", _instant_sleep)


# ── Retry-with-backoff on transient status codes (404/5xx) — see the real- ──
# ── prod flakiness this guards against in _get_with_retry's docstring.    ──


async def test_fetch_artifact_retries_on_404_then_succeeds():
    zip_bytes = b"PK\x03\x04fake-zip-bytes"
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls < 3:
            return httpx.Response(404, json={"detail": "Not Found"})
        return httpx.Response(
            200, content=zip_bytes, headers={"X-Signature": "hmac_sha256:deadbeef"}
        )

    async with MarketplaceClient(
        "https://hub.example", api_key="xdk_test", transport=httpx.MockTransport(handler)
    ) as client:
        artifact = await client.fetch_artifact(slug="my-plugin", version="1.2.3")

    assert artifact.data == zip_bytes
    assert calls == 3


async def test_fetch_artifact_gives_up_after_exhausting_retries():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"detail": "Not Found"})

    async with MarketplaceClient(
        "https://hub.example", api_key="xdk_test", transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(ArtifactError, match="fetch_artifact failed"):
            await client.fetch_artifact(slug="my-plugin", version="1.2.3")


async def test_fetch_artifact_does_not_retry_on_401():
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(401, json={"detail": "invalid key"})

    async with MarketplaceClient(
        "https://hub.example", api_key="xdk_test", transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(ArtifactError, match="API key rejected"):
            await client.fetch_artifact(slug="my-plugin", version="1.2.3")

    assert calls == 1  # not a retryable status — fails on the first try


async def test_get_latest_version_retries_on_503_then_succeeds():
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls < 2:
            return httpx.Response(503, text="service unavailable")
        return _json_response(200, {"slug": "my-plugin", "latest_version": "2.0.0"})

    async with MarketplaceClient(
        "https://hub.example", api_key="xdk_test", transport=httpx.MockTransport(handler)
    ) as client:
        version = await client.get_latest_version(slug="my-plugin")

    assert version == "2.0.0"
    assert calls == 2


async def test_get_latest_version_reads_plugin_detail():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/app/marketplace/plugins/my-plugin"
        return _json_response(200, {"slug": "my-plugin", "latest_version": "1.2.3"})

    async with MarketplaceClient(
        "https://hub.example", api_key="xdk_test", transport=httpx.MockTransport(handler)
    ) as client:
        version = await client.get_latest_version(slug="my-plugin")

    assert version == "1.2.3"


async def test_get_latest_version_uses_services_path_for_service_kind():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/app/xservices/services/my-ext"
        return _json_response(200, {"latest_version": "2.0.0"})

    async with MarketplaceClient(
        "https://hub.example", api_key="xdk_test", transport=httpx.MockTransport(handler)
    ) as client:
        version = await client.get_latest_version(slug="my-ext", kind="service")

    assert version == "2.0.0"


async def test_get_latest_version_raises_when_unpublished():
    def handler(request: httpx.Request) -> httpx.Response:
        return _json_response(200, {"slug": "my-plugin", "latest_version": None})

    async with MarketplaceClient(
        "https://hub.example", api_key="xdk_test", transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(ArtifactError, match="no published version"):
            await client.get_latest_version(slug="my-plugin")


async def test_fetch_artifact_sends_api_key_and_parses_headers():
    zip_bytes = b"PK\x03\x04fake-zip-bytes"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/app/marketplace/plugins/my-plugin/install"
        assert request.url.params["version"] == "1.2.3"
        assert request.headers["x-api-key"] == "xdk_test"
        return httpx.Response(
            200,
            content=zip_bytes,
            headers={
                "X-Signature": "hmac_sha256:deadbeef",
                "X-Plugin": "my-plugin@1.2.3",
                "X-Repo": "acme/my-plugin@1.2.3",
            },
        )

    async with MarketplaceClient(
        "https://hub.example", api_key="xdk_test", transport=httpx.MockTransport(handler)
    ) as client:
        artifact = await client.fetch_artifact(slug="my-plugin", version="1.2.3")

    assert artifact.data == zip_bytes
    assert artifact.signature_header == "hmac_sha256:deadbeef"
    assert artifact.plugin_header == "my-plugin@1.2.3"
    assert artifact.repo_header == "acme/my-plugin@1.2.3"


async def test_fetch_artifact_follows_redirect_instead_of_returning_its_body():
    # Same real-prod failure mode as HttpHubClient.download: an unfollowed
    # 301 (e.g. a reverse proxy enforcing HTTPS) would silently return its
    # ~17-byte "Moved Permanently" body as if it were the plugin's ZIP,
    # which then fails HMAC verification with no hint a redirect happened.
    zip_bytes = b"PK\x03\x04fake-zip-bytes"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/app/marketplace/plugins/my-plugin/install":
            return httpx.Response(
                301,
                headers={
                    "Location": "https://hub.example/app/marketplace/plugins/my-plugin/install/"
                },
            )
        assert request.url.path == "/app/marketplace/plugins/my-plugin/install/"
        return httpx.Response(
            200, content=zip_bytes, headers={"X-Signature": "hmac_sha256:deadbeef"}
        )

    async with MarketplaceClient(
        "https://hub.example", api_key="xdk_test", transport=httpx.MockTransport(handler)
    ) as client:
        artifact = await client.fetch_artifact(slug="my-plugin", version="1.2.3")

    assert artifact.data == zip_bytes


async def test_fetch_artifact_uses_x_service_header_for_service_kind():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/app/xservices/services/my-ext/install"
        return httpx.Response(
            200,
            content=b"zip",
            headers={
                "X-Signature": "hmac_sha256:aa",
                "X-Service": "my-ext@1.0.0",
                "X-Repo": "a/b@1.0.0",
            },
        )

    async with MarketplaceClient(
        "https://hub.example", api_key="xdk_test", transport=httpx.MockTransport(handler)
    ) as client:
        artifact = await client.fetch_artifact(slug="my-ext", kind="service")

    assert artifact.plugin_header == "my-ext@1.0.0"


async def test_fetch_artifact_missing_signature_header_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"zip")

    async with MarketplaceClient(
        "https://hub.example", api_key="xdk_test", transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(ArtifactError, match="X-Signature"):
            await client.fetch_artifact(slug="my-plugin")


async def test_fetch_artifact_rejected_api_key_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        return _json_response(401, {"detail": "Clé API invalide ou révoquée"})

    async with MarketplaceClient(
        "https://hub.example", api_key="bad-key", transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(ArtifactError, match="Clé API invalide"):
            await client.fetch_artifact(slug="my-plugin")


async def test_fetch_artifact_server_error_raises_with_status_code():
    def handler(request: httpx.Request) -> httpx.Response:
        return _json_response(400, {"detail": "tag introuvable"})

    async with MarketplaceClient(
        "https://hub.example", api_key="xdk_test", transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(ArtifactError, match="400"):
            await client.fetch_artifact(slug="my-plugin", version="9.9.9")


async def test_report_deployment_sends_expected_body_and_api_key():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/app/xdeployments/deployments/report"
        assert request.headers["x-api-key"] == "xdk_test"
        body = json.loads(request.content)
        assert body == {
            "kind": "plugin",
            "slug": "my-plugin",
            "version": "1.2.3",
            "status": "success",
            "started_at": "2026-01-01T00:00:00+00:00",
            "completed_at": "2026-01-01T00:00:05+00:00",
            "host_id": "vps-1",
            "repo": "acme/my-plugin@1.2.3",
            "error_message": None,
        }
        return _json_response(201, {"id": "dep-1"})

    async with MarketplaceClient(
        "https://hub.example", api_key="xdk_test", transport=httpx.MockTransport(handler)
    ) as client:
        await client.report_deployment(
            kind="plugin",
            slug="my-plugin",
            version="1.2.3",
            status="success",
            started_at="2026-01-01T00:00:00+00:00",
            completed_at="2026-01-01T00:00:05+00:00",
            host_id="vps-1",
            repo="acme/my-plugin@1.2.3",
        )


async def test_report_deployment_rejected_api_key_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        return _json_response(401, {"detail": "Clé API invalide ou révoquée"})

    async with MarketplaceClient(
        "https://hub.example", api_key="bad-key", transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(ArtifactError, match="Clé API invalide"):
            await client.report_deployment(
                kind="plugin",
                slug="my-plugin",
                version="1.0.0",
                status="failed",
                started_at="2026-01-01T00:00:00+00:00",
                completed_at="2026-01-01T00:00:00+00:00",
            )
