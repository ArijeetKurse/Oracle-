import json

import httpx
import pytest

from oracle import llm


def response(content: str) -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {"content": content}}]}, request=httpx.Request("POST", llm.BASE_URL))


def error_response(status: int) -> httpx.Response:
    return httpx.Response(
        status,
        json={"error": {"message": "mock failure with test-secret-key and sensitive request data"}},
        request=httpx.Request("POST", llm.BASE_URL),
    )


def test_groq_default_model_and_environment_override(monkeypatch):
    monkeypatch.delenv("GROQ_MODEL", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)
    assert llm.provider_settings()["model"] == "openai/gpt-oss-120b"

    monkeypatch.setenv("GROQ_MODEL", "account-model")
    assert llm.provider_settings()["model"] == "account-model"


def test_groq_review_uses_configurable_model_and_sanitized_bundle(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "secret-test-value")
    monkeypatch.setenv("GROQ_MODEL", "test-model")
    sent = {}

    def post(url, **kwargs):
        sent.update(url=url, **kwargs)
        return response(json.dumps({"assessment": "Review this process.", "model_inference": "Uncertain.", "confidence": 0.4, "observed_facts": ["Path is under /tmp"], "likely_benign_causes": [], "potential_risks": ["Temporary executable"], "safe_checks": ["Check package source"], "missing_evidence": ["Signer"], "limitations": ["No file hash"]}))

    monkeypatch.setattr(llm.httpx, "post", post)
    event = {"pid": 7, "ppid": 2, "name": "worker", "executable": "/home/alice/.local/bin/worker", "username": "alice", "connections": [], "kind": "process_snapshot", "simulated": False, "rule": "USERSPACE_EXECUTABLE", "risk_score": 18, "reason": "User path"}
    investigation = {"evidence": [{"kind": "process", "source": "psutil", "polarity": "neutral", "detail": json.dumps({"pid": 7, "username": "alice", "cmdline": ["secret"], "executable": "/home/alice/.local/bin/worker"})}], "unknowns": [], "conclusion": "Review"}
    result = llm.review_investigation(event, investigation)

    assert result["provider"] == "groq" and result["model"] == "test-model"
    assert sent["url"] == "https://api.groq.com/openai/v1/chat/completions"
    assert sent["headers"]["Authorization"] == "Bearer secret-test-value"
    body = json.loads(sent["json"]["messages"][1]["content"])
    serialized = json.dumps(body)
    assert "alice" not in serialized and "username" not in serialized and "cmdline" not in serialized
    assert "/home/<user>/" in serialized


def test_groq_missing_key_is_clear(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    with pytest.raises(llm.LLMError, match="GROQ_API_KEY"):
        llm.test_connection()


@pytest.mark.parametrize(
    ("status", "message"),
    [
        (400, "rejected the request"),
        (401, "rejected the API credentials"),
        (403, "denied access"),
        (404, "could not find model"),
        (429, "rate limit"),
        (500, "temporarily unavailable"),
        (502, "temporarily unavailable"),
        (503, "temporarily unavailable"),
    ],
)
def test_groq_provider_statuses_are_clear_and_sanitized(monkeypatch, status, message):
    monkeypatch.setenv("GROQ_API_KEY", "test-secret-key")
    monkeypatch.setattr(llm.httpx, "post", lambda *args, **kwargs: error_response(status))

    with pytest.raises(llm.LLMError) as error:
        llm.test_connection()

    assert error.value.provider_status_code == status
    assert error.value.http_status_code == 502
    assert message in str(error.value)
    assert "test-secret-key" not in str(error.value)
    assert "sensitive request data" not in str(error.value)


def test_groq_connection_test_parses_success(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-secret-key")
    monkeypatch.setenv("GROQ_MODEL", "test-model")
    monkeypatch.setattr(llm.httpx, "post", lambda *args, **kwargs: response("ORACLE connection test passed."))

    result = llm.test_connection()

    assert result == {
        "ok": True,
        "provider": "groq",
        "model": "test-model",
        "message": "ORACLE connection test passed.",
    }


def test_groq_unexpected_success_shape_is_a_gateway_error(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-secret-key")
    malformed = httpx.Response(200, json={"choices": []}, request=httpx.Request("POST", llm.BASE_URL))
    monkeypatch.setattr(llm.httpx, "post", lambda *args, **kwargs: malformed)

    with pytest.raises(llm.LLMError) as error:
        llm.test_connection()

    assert "unexpected response" in str(error.value)
    assert error.value.http_status_code == 502


@pytest.mark.parametrize(
    ("exception", "message"),
    [
        (httpx.TimeoutException("request includes test-secret-key"), "did not respond"),
        (httpx.ConnectError("request includes test-secret-key"), "Could not connect"),
    ],
)
def test_groq_transport_errors_are_sanitized(monkeypatch, exception, message):
    monkeypatch.setenv("GROQ_API_KEY", "test-secret-key")

    def fail(*args, **kwargs):
        raise exception

    monkeypatch.setattr(llm.httpx, "post", fail)
    with pytest.raises(llm.LLMError) as error:
        llm.test_connection()

    assert message in str(error.value)
    assert error.value.http_status_code == 503
    assert "test-secret-key" not in str(error.value)


def test_monitoring_review_queue_skips_llm_without_key(monkeypatch):
    from oracle import core
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setattr(llm, "provider_settings", lambda: {"provider": "groq", "model": llm.DEFAULT_MODEL, "configured": False})
    assert core.queue_investigation_review("no-key-investigation") is False


def test_chat_is_bounded_and_has_no_tool_execution(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "not-returned")
    captured = {}

    def post(url, **kwargs):
        captured.update(kwargs)
        return response("This evidence is incomplete.")

    monkeypatch.setattr(llm.httpx, "post", post)
    history = [{"role": "user", "content": "earlier"}, {"role": "assistant", "content": "answer"}] * 6
    answer = llm.answer_question({"pid": 1, "name": "x", "connections": []}, {"evidence": [], "unknowns": ["parent missing"]}, history, "What next?")
    messages = captured["json"]["messages"]
    assert answer == "This evidence is incomplete."
    assert len(messages) == 11  # system, evidence, eight history messages, current question
    assert "tools" not in captured["json"]
    assert "not-returned" not in json.dumps(captured["json"])
