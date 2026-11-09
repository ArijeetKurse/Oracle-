import asyncio

import httpx
import pytest
from fastapi import HTTPException

from oracle import main


class MockAsyncClient:
    response = None
    captured = None

    def __init__(self, **kwargs):
        self.timeout = kwargs.get("timeout")

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def post(self, url, **kwargs):
        type(self).captured = (url, kwargs)
        return type(self).response


def provider_response(status=200, *, content=b"RIFF-audio", content_type="audio/wav"):
    request = httpx.Request("POST", "https://api.gnani.ai/v1/tts/inference")
    return httpx.Response(status, content=content, headers={"content-type": content_type}, request=request)


def test_timbre_success_sends_current_request_and_returns_audio(monkeypatch):
    monkeypatch.setenv("GNANI_API_KEY", "unit-test-key")
    MockAsyncClient.response = provider_response(content=b"wav bytes")
    monkeypatch.setattr(main.httpx, "AsyncClient", MockAsyncClient)

    result = asyncio.run(main.speak(main.Command(command="Read this report")))

    url, kwargs = MockAsyncClient.captured
    assert url == "https://api.gnani.ai/v1/tts/inference"
    assert kwargs["headers"]["Authorization"] == "Bearer unit-test-key"
    assert kwargs["json"]["model"] == "timbre-2.5"
    assert result.body == b"wav bytes"
    assert result.media_type == "audio/wav"
    assert result.headers["X-Oracle-Speech-Provider"] == "Gnani Timbre v2.5"


@pytest.mark.parametrize(
    ("status", "message"),
    [
        (401, "rejected the API key"),
        (404, "endpoint or model was not found"),
        (429, "rate limit reached"),
        (500, "HTTP 500"),
    ],
)
def test_timbre_provider_failures_are_actionable(monkeypatch, status, message):
    monkeypatch.setenv("GNANI_API_KEY", "unit-test-key")
    MockAsyncClient.response = provider_response(status)
    monkeypatch.setattr(main.httpx, "AsyncClient", MockAsyncClient)

    with pytest.raises(HTTPException) as error:
        asyncio.run(main.speak(main.Command(command="Read this report")))

    assert error.value.status_code == 502
    assert message in error.value.detail


@pytest.mark.parametrize(
    ("content", "content_type"),
    [(b"", "audio/wav"), (b"not audio", "application/json")],
)
def test_timbre_rejects_empty_or_non_audio_success(monkeypatch, content, content_type):
    monkeypatch.setenv("GNANI_API_KEY", "unit-test-key")
    MockAsyncClient.response = provider_response(content=content, content_type=content_type)
    monkeypatch.setattr(main.httpx, "AsyncClient", MockAsyncClient)

    with pytest.raises(HTTPException, match="empty or non-audio"):
        asyncio.run(main.speak(main.Command(command="Read this report")))


def test_timbre_requires_api_key(monkeypatch):
    monkeypatch.delenv("GNANI_API_KEY", raising=False)

    with pytest.raises(HTTPException) as error:
        asyncio.run(main.speak(main.Command(command="Read this report")))

    assert error.value.status_code == 503
