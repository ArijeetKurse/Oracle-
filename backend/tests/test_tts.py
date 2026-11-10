import asyncio
import json

import httpx
import pytest

from oracle import main

REAL_ASYNC_CLIENT = httpx.AsyncClient


def wave_bytes(payload=b"mock audio"):
    return b"RIFF" + (len(payload) + 4).to_bytes(4, "little") + b"WAVE" + payload


class MockAsyncClient:
    response = None
    error = None
    captured = None
    started = None
    release = None

    def __init__(self, **kwargs):
        self.timeout = kwargs.get("timeout")

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def post(self, url, **kwargs):
        type(self).captured = (url, kwargs)
        if type(self).error:
            raise type(self).error
        if type(self).started is not None:
            type(self).started.set()
            await type(self).release.wait()
        return type(self).response


def provider_response(status=200, *, content=None, content_type="audio/wav"):
    request = httpx.Request("POST", "https://api.vachana.ai/api/v1/tts/inference")
    if content is None:
        content = wave_bytes() if status == 200 else b'{"error":"test-secret-key was rejected"}'
    headers = {"content-type": content_type} if content_type is not None else {}
    return httpx.Response(status, content=content, headers=headers, request=request)


def tts_client(monkeypatch, *, response=None, error=None, api_key="test-secret-key"):
    monkeypatch.setenv("GNANI_API_KEY", api_key)
    monkeypatch.delenv("GNANI_TTS_URL", raising=False)
    MockAsyncClient.response = response
    MockAsyncClient.error = error
    MockAsyncClient.captured = None
    MockAsyncClient.started = None
    MockAsyncClient.release = None
    monkeypatch.setattr(main.httpx, "AsyncClient", MockAsyncClient)
    return None


def post_tts():
    async def request():
        transport = httpx.ASGITransport(app=main.app)
        async with REAL_ASYNC_CLIENT(transport=transport, base_url="http://test") as client:
            return await client.post("/api/voice/speak", json={"command": "Read this report"})

    return asyncio.run(request())


async def post_tts_async():
    transport = httpx.ASGITransport(app=main.app)
    async with REAL_ASYNC_CLIENT(transport=transport, base_url="http://test") as client:
        return await client.post("/api/voice/speak", json={"command": "Read this report"})


def test_timbre_success_returns_binary_audio_and_uses_current_request(monkeypatch):
    expected_audio = wave_bytes()
    tts_client(monkeypatch, response=provider_response(content=expected_audio))

    response = post_tts()

    url, kwargs = MockAsyncClient.captured
    assert url == "https://api.vachana.ai/api/v1/tts/inference"
    assert kwargs["headers"]["X-API-Key-ID"] == "test-secret-key"
    assert "Authorization" not in kwargs["headers"]
    assert kwargs["json"]["model"] == "timbre-v2.5"
    assert kwargs["json"]["voice"] == "Kaveri"
    assert kwargs["json"]["audio_config"]["container"] == "wav"
    assert response.status_code == 200
    assert response.content == expected_audio
    assert response.headers["content-type"] == "audio/wav"
    assert response.headers["x-oracle-speech-provider"] == "Gnani Timbre v2.5"
    assert "authorization" not in response.headers
    assert "test-secret-key" not in response.content.decode("latin1")


def test_timbre_endpoint_can_be_configured_independently(monkeypatch):
    tts_client(monkeypatch, response=provider_response())
    monkeypatch.setenv("GNANI_TTS_URL", "https://tts.example.test/api/v1/tts/inference")

    response = post_tts()

    assert response.status_code == 200
    assert MockAsyncClient.captured[0] == "https://tts.example.test/api/v1/tts/inference"


@pytest.mark.parametrize(
    ("status", "message"),
    [
        (400, "rejected the synthesis request"),
        (401, "rejected the API key"),
        (403, "denied access"),
        (404, "endpoint or model was not found"),
        (429, "throttled this TTS request"),
        (500, "temporarily unavailable"),
        (502, "temporarily unavailable"),
        (503, "temporarily unavailable"),
    ],
)
def test_timbre_provider_errors_are_json_sanitized_and_keep_provider_status(monkeypatch, status, message):
    tts_client(monkeypatch, response=provider_response(status))

    response = post_tts()

    assert response.status_code == (status if status in (400, 401, 402, 403, 404, 429) else 502)
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["x-provider-status"] == str(status)
    assert message in response.json()["detail"]
    assert "test-secret-key" not in response.text


def test_timbre_429_exposes_sanitized_active_request_diagnostics(monkeypatch, caplog):
    tts_client(monkeypatch)
    MockAsyncClient.response = httpx.Response(
        429,
        json={"detail": {"error_code": "RATE_LIMITED", "message": "Only 1 active request is allowed at a time.", "status_code": 429}},
        headers={"content-type": "application/json", "retry-after": "12", "x-request-id": "req-test-123"},
        request=httpx.Request("POST", "https://api.vachana.ai/api/v1/tts/inference"),
    )

    response = post_tts()

    assert response.status_code == 429
    assert "another active synthesis" in response.json()["detail"]
    assert response.headers["retry-after"] == "12"
    assert response.headers["x-provider-content-type"] == "application/json"
    assert response.headers["x-provider-error-code"] == "RATE_LIMITED"
    assert response.headers["x-provider-request-id"] == "req-test-123"
    assert "Only 1 active request" in caplog.text
    assert "test-secret-key" not in caplog.text


def test_timbre_429_quota_wording_is_classified_without_assuming_credit_exhaustion(monkeypatch):
    tts_client(monkeypatch)
    MockAsyncClient.response = httpx.Response(
        429,
        json={"detail": {"error_code": "ACCOUNT_LIMIT", "message": "Account quota limit reached."}},
        headers={"content-type": "application/json"},
        request=httpx.Request("POST", "https://api.vachana.ai/api/v1/tts/inference"),
    )

    response = post_tts()

    assert response.status_code == 429
    assert "quota or account allowance" in response.json()["detail"]
    assert "Account quota limit reached" in response.json()["detail"]


def test_timbre_402_is_reported_as_insufficient_credit(monkeypatch):
    tts_client(monkeypatch)
    MockAsyncClient.response = httpx.Response(
        402,
        json={"detail": {"message": "Insufficient credit"}},
        headers={"content-type": "application/json"},
        request=httpx.Request("POST", "https://api.vachana.ai/api/v1/tts/inference"),
    )

    response = post_tts()

    assert response.status_code == 402
    assert "insufficient credits" in response.json()["detail"]
    assert "Insufficient credit" in response.json()["detail"]


def test_timbre_rejects_concurrent_provider_requests_locally(monkeypatch):
    tts_client(monkeypatch, response=provider_response())
    MockAsyncClient.started = asyncio.Event()
    MockAsyncClient.release = asyncio.Event()
    main._tts_request_active = False

    async def concurrent_requests():
        first = asyncio.create_task(post_tts_async())
        await MockAsyncClient.started.wait()
        second = await post_tts_async()
        MockAsyncClient.release.set()
        return await first, second

    first, second = asyncio.run(concurrent_requests())

    assert first.status_code == 200
    assert second.status_code == 409
    assert "already running" in second.json()["detail"]
    assert MockAsyncClient.captured[0] == "https://api.vachana.ai/api/v1/tts/inference"
    main._tts_request_active = False


@pytest.mark.parametrize(
    ("content", "content_type"),
    [
        (b"", "audio/wav"),
        (b'{"error":"failed"}', "application/json"),
        (wave_bytes(), None),
        (wave_bytes(), "audio/mpeg"),
        (b"not a WAV", "audio/wav"),
    ],
)
def test_timbre_rejects_empty_json_missing_type_and_malformed_audio(monkeypatch, content, content_type):
    tts_client(monkeypatch, response=provider_response(content=content, content_type=content_type))

    response = post_tts()

    assert response.status_code == 502
    assert response.headers["content-type"].startswith("application/json")
    assert "detail" in response.json()


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (httpx.ConnectError("Name or service not known"), "Could not resolve"),
        (httpx.TimeoutException("request contains test-secret-key"), "did not respond within 60 seconds"),
        (httpx.ConnectError("connection refused"), "Could not connect"),
    ],
)
def test_timbre_transport_errors_are_json_sanitized(monkeypatch, error, message):
    tts_client(monkeypatch, error=error)

    response = post_tts()

    assert response.status_code == 503
    assert response.headers["content-type"].startswith("application/json")
    assert message in response.json()["detail"]
    assert "test-secret-key" not in response.text


def test_timbre_missing_key_returns_structured_json(monkeypatch):
    monkeypatch.delenv("GNANI_API_KEY", raising=False)
    monkeypatch.setattr(main.httpx, "AsyncClient", MockAsyncClient)

    response = post_tts()

    assert response.status_code == 503
    assert response.headers["content-type"].startswith("application/json")
    assert "GNANI_API_KEY" in response.json()["detail"]
