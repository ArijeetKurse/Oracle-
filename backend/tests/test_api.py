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
