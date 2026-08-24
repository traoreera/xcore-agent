"""Tests for HttpHubClient against the real xcore-team/xdeploy contract (see
hub_client.py's module docstring — validated end to end against a live
Hub), using httpx.MockTransport so no real network access is needed here.
Every path asserted below is prefixed with `/app/xdeploy`, the mount xcore
gives every plugin (see `_MOUNT` in hub_client.py).
"""

import base64
import json

import httpx
import pytest

from xcore_agent.agent.errors import ArtifactError, AuthenticationError
from xcore_agent.agent.hub_client import ArtifactLocation, DeploymentReport, HttpHubClient, Session


def _json_response(status_code: int, payload: dict) -> httpx.Response:
    return httpx.Response(status_code, json=payload)


async def test_authenticate_success():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/app/xdeploy/v1/auth"
        assert json.loads(request.content) == {"xdevkey": "xdev_x", "project_id": "prj_x"}
        return _json_response(200, {"access_token": "tok_123"})

    async with HttpHubClient(
        "https://hub.example", transport=httpx.MockTransport(handler)
    ) as client:
        session = await client.authenticate(xdevkey="xdev_x", project_id="prj_x")

    assert session == Session(project_id="prj_x", access_token="tok_123")


async def test_authenticate_rejected_raises_authentication_error():
    def handler(request):
        return _json_response(401, {"error": "invalid xdevkey"})

    async with HttpHubClient(
        "https://hub.example", transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(AuthenticationError, match="invalid xdevkey"):
            await client.authenticate(xdevkey="bad", project_id="prj_x")


async def test_get_latest_version_sends_bearer_token():
    def handler(request):
        assert request.headers["authorization"] == "Bearer tok_123"
        assert request.url.path == "/app/xdeploy/v1/projects/prj_x/versions/latest"
        return _json_response(200, {"version": "1.2.3"})

    async with HttpHubClient(
        "https://hub.example", transport=httpx.MockTransport(handler)
    ) as client:
        session = Session(project_id="prj_x", access_token="tok_123")
        version = await client.get_latest_version(session, project_id="prj_x")

    assert version == "1.2.3"


async def test_request_artifact_decodes_base64_fields():
    signature, public_key = b"sig-bytes", b"pub-key-bytes"

    def handler(request):
        assert request.url.path == "/app/xdeploy/v1/projects/prj_x/artifacts/1.0.0"
        return _json_response(
            200,
            {
                "download_url": "https://blob.example/artifact.enc",
                "signature": base64.b64encode(signature).decode(),
                "signer_public_key": base64.b64encode(public_key).decode(),
            },
        )

    async with HttpHubClient(
        "https://hub.example", transport=httpx.MockTransport(handler)
    ) as client:
        session = Session(project_id="prj_x", access_token="tok_123")
        location = await client.request_artifact(session, version="1.0.0")

    assert location.download_url == "https://blob.example/artifact.enc"
    assert location.signature == signature
    assert location.signer_public_key == public_key


async def test_download_returns_raw_bytes_from_arbitrary_url():
    def handler(request):
        assert str(request.url) == "https://blob.example/artifact.enc"
        return httpx.Response(200, content=b"raw-artifact-bytes")

    async with HttpHubClient(
        "https://hub.example", transport=httpx.MockTransport(handler)
    ) as client:
        location = ArtifactLocation(
            download_url="https://blob.example/artifact.enc",
            signature=b"x",
            signer_public_key=b"y",
        )
        data = await client.download(location)

    assert data == b"raw-artifact-bytes"


async def test_obtain_deployment_key_roundtrips_base64():
    dek = b"0" * 32

    def handler(request):
        body = json.loads(request.content)
        assert body["deployment_credential"] == "xdpk_x"
        assert base64.b64decode(body["artifact_signature"]) == b"sig"
        return _json_response(200, {"dek": base64.b64encode(dek).decode()})

    async with HttpHubClient(
        "https://hub.example", transport=httpx.MockTransport(handler)
    ) as client:
        session = Session(project_id="prj_x", access_token="tok_123")
        result = await client.obtain_deployment_key(
            session, deployment_credential="xdpk_x", artifact_signature=b"sig"
        )

    assert result == dek


async def test_obtain_deployment_key_denied_raises_authentication_error():
    def handler(request):
        return _json_response(403, {"error": "revoked deployment credential"})

    async with HttpHubClient(
        "https://hub.example", transport=httpx.MockTransport(handler)
    ) as client:
        session = Session(project_id="prj_x", access_token="tok_123")
        with pytest.raises(AuthenticationError, match="revoked"):
            await client.obtain_deployment_key(
                session, deployment_credential="xdpk_x", artifact_signature=b"sig"
            )


async def test_notify_posts_report_fields():
    def handler(request):
        body = json.loads(request.content)
        assert body["status"] == "success"
        assert body["plugins"] == [{"id": "demo"}]
        return _json_response(200, {"deployment_id": "dep_123"})

    async with HttpHubClient(
        "https://hub.example", transport=httpx.MockTransport(handler)
    ) as client:
        session = Session(project_id="prj_x", access_token="tok_123")
        report = DeploymentReport(
            project_id="prj_x",
            deployment_id="",
            status="success",
            version="1.0.0",
            started_at="",
            completed_at="",
            plugins=[{"id": "demo"}],
        )
        await client.notify(session, report)  # must not raise


async def test_publish_posts_multipart_and_decodes_result():
    dek, signature, public_key = b"d" * 32, b"sig-bytes", b"pub-key-bytes"

    def handler(request):
        assert request.url.path == "/app/xdeploy/v1/projects/prj_x/publish"
        assert request.headers["x-api-key"] == "xdev_x"
        return _json_response(
            201,
            {
                "artifact_id": "art_123",
                "project_id": "prj_x",
                "version": "1.0.0",
                "content_sha256": "a" * 64,
                "size_bytes": 42,
                "created_at": "2026-01-01T00:00:00Z",
            },
        )

    async with HttpHubClient(
        "https://hub.example", transport=httpx.MockTransport(handler)
    ) as client:
        result = await client.publish(
            xdevkey="xdev_x",
            project_id="prj_x",
            project_name="demo",
            version="1.0.0",
            ciphertext=b"ciphertext-bytes",
            content_sha256="a" * 64,
            dek=dek,
            signature=signature,
            signer_public_key=public_key,
        )

    assert result.artifact_id == "art_123"
    assert result.size_bytes == 42


async def test_publish_denied_raises_authentication_error():
    def handler(request):
        return _json_response(403, {"error": "key not bound to this project"})

    async with HttpHubClient(
        "https://hub.example", transport=httpx.MockTransport(handler)
    ) as client:
        with pytest.raises(AuthenticationError, match="not bound"):
            await client.publish(
                xdevkey="xdev_x",
                project_id="prj_x",
                project_name="demo",
                version="1.0.0",
                ciphertext=b"x",
                content_sha256="a" * 64,
                dek=b"d" * 32,
                signature=b"sig",
                signer_public_key=b"pub",
            )


async def test_server_error_raises_artifact_error_with_status_code():
    def handler(request):
        return _json_response(500, {"error": "internal error"})

    async with HttpHubClient(
        "https://hub.example", transport=httpx.MockTransport(handler)
    ) as client:
        session = Session(project_id="prj_x", access_token="tok_123")
        with pytest.raises(ArtifactError, match="500"):
            await client.get_latest_version(session, project_id="prj_x")
