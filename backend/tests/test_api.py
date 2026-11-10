import pytest
from fastapi import HTTPException

from oracle import core, main


def test_chat_is_scoped_to_case_and_persists_ai_response(monkeypatch):
    event = core.simulate_event()
    investigation = core.create_investigation(event.id)
    captured = {}

    def answer(event_data, investigation_data, history, question):
        captured.update(event=event_data, investigation=investigation_data, history=history, question=question)
        return "This event is synthetic, so it is not a real finding."

    monkeypatch.setattr(main, "answer_question", answer)
    response = main.chat(investigation.id, main.ChatQuestion(question="Why was this flagged?"))
    assert response["generated_by_ai"] is True
    assert response["evidence_incomplete"] is True
    assert captured["question"] == "Why was this flagged?"
    messages = main.chat_history(investigation.id)["messages"]
    assert [m["role"] for m in messages] == ["user", "assistant"]
    assert messages[-1]["content"] == response["answer"]


def test_chat_rejects_unknown_investigation_and_missing_groq_key(monkeypatch):
    with pytest.raises(HTTPException) as missing:
        main.chat("missing", main.ChatQuestion(question="Explain this"))
    assert missing.value.status_code == 404

    event = core.simulate_event()
    investigation = core.create_investigation(event.id)
    monkeypatch.setattr(main, "answer_question", lambda *args: (_ for _ in ()).throw(main.LLMError("Groq is not configured.")))
    with pytest.raises(HTTPException) as unavailable:
        main.chat(investigation.id, main.ChatQuestion(question="What next?"))
    assert unavailable.value.status_code == 503
    assert "not configured" in unavailable.value.detail


def test_health_reports_provider_state_without_exposing_credentials(monkeypatch):
    monkeypatch.setenv('GROQ_API_KEY','groq-test-secret')
    monkeypatch.setenv('GNANI_API_KEY','gnani-test-secret')
    monkeypatch.setattr(main, 'daemon_status', lambda: {'running': False, 'pid': None})
    data=main.health()
    assert data['monitoring'] is False
    assert data['reasoning']['configured'] is True
    assert data['gnani']['configured'] is True
    assert 'groq-test-secret' not in str(data) and 'gnani-test-secret' not in str(data)
    monkeypatch.delenv('GROQ_API_KEY')
    with pytest.raises(HTTPException) as unavailable:
        main.llm_test()
    assert unavailable.value.status_code == 503


def test_resource_timeline_validates_windows_and_returns_actual_history(monkeypatch):
    now=__import__('time').time()
    sample={"sampled_at":now,"timestamp":"2026-01-01T00:00:00+00:00","cpu_percent":22.0,"memory_percent":40.0}
    monkeypatch.setattr(main.resource_history_store,"resource_history",lambda *args,**kwargs:{"samples":[sample],"processes":[],"process_history":[]})
    response=main.resource_timeline(window="5m")
    assert response["window"] == "5m"
    assert response["samples"] == [sample]
    assert response["events"] == []
    with pytest.raises(HTTPException) as invalid:
        main.resource_timeline(window="7d")
    assert invalid.value.status_code == 400


def test_alert_api_lists_and_changes_local_alert_state():
    connection=core.db()
    connection.execute("""INSERT INTO alerts(id,created_at,status,severity,detector_id,dedupe_key,pid,process_create_time,
        title,explanation,confidence,evidence_json) VALUES('api-alert',1000,'new','low','test.detector','test:1',1,1,
        'Test observation','Local evidence',0.5,'{}')""")
    connection.commit(); connection.close()
    assert main.read_alerts(status="new")[0]["id"] == "api-alert"
    assert main.change_alert("api-alert", {"status":"acknowledged"})["status"] == "acknowledged"
    with pytest.raises(HTTPException) as invalid:
        main.change_alert("api-alert", {"status":"not-a-state"})
    assert invalid.value.status_code == 400


def test_groq_endpoint_returns_sanitized_provider_error_without_stack_details(monkeypatch):
    monkeypatch.setattr(
        main,
        "test_connection",
        lambda: (_ for _ in ()).throw(
            main.LLMError("Groq denied access to this model or account.", provider_status_code=403, http_status_code=502)
        ),
    )

    with pytest.raises(HTTPException) as response:
        main.llm_test()

    assert response.value.status_code == 502
    assert response.value.headers["X-Provider-Status"] == "403"
    assert response.value.detail == "Groq denied access to this model or account."
    assert "Authorization" not in response.value.detail
    assert "Traceback" not in response.value.detail
