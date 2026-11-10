import asyncio

import pytest
from fastapi import HTTPException

from oracle import core, main


def test_voice_transcription_does_not_execute_command(monkeypatch):
    class Upload:
        filename="voice.wav"; content_type="audio/wav"
        async def read(self): return b"recorded audio bytes"
    class Client:
        def __init__(self,**_kwargs): pass
        async def __aenter__(self): return self
        async def __aexit__(self,*_args): return None
        async def post(self,*_args,**_kwargs):
            import httpx
            return httpx.Response(200,json={"success":True,"transcript":"explain the selected investigation"},request=httpx.Request("POST","https://api.vachana.ai/stt/v3"))
    monkeypatch.setenv("GNANI_API_KEY","mock-key")
    monkeypatch.setattr(main.httpx,"AsyncClient",Client)
    monkeypatch.setattr(main,"_route_voice",lambda *_args:pytest.fail("Transcription must not execute a command"))
    result=asyncio.run(main.transcribe(Upload()))
    assert result["transcript"]=="explain the selected investigation"
    assert "command_result" not in result


def test_confirmed_voice_can_open_selected_investigation(monkeypatch):
    monkeypatch.setattr(main,"provider_settings",lambda:{"configured":False,"provider":"groq","model":"test"})
    event=core.simulate_event()
    inv=core.create_investigation(event.id,ai_review=False)
    result=main._route_voice("explain this investigation",main.Command(command="explain this investigation",selected_investigation_id=inv.id))
    assert result["type"]=="investigation"
    assert result["investigation"]["id"]==inv.id


def test_voice_case_explanation_falls_back_to_local_evidence_when_groq_fails(monkeypatch):
    event=core.simulate_event()
    inv=core.create_investigation(event.id,ai_review=False)
    monkeypatch.setattr(main,"provider_settings",lambda:{"configured":True,"provider":"groq","model":"test"})
    monkeypatch.setattr(main,"chat",lambda *_args:(_ for _ in ()).throw(HTTPException(503,"mock provider unavailable")))
    result=main._route_voice("explain this investigation",main.Command(command="explain this investigation",selected_investigation_id=inv.id))
    assert result["type"]=="investigation"
    assert result["investigation"]["id"]==inv.id
    assert "could not answer" in result["fallback"]


def test_confirmed_voice_historical_summary_uses_actual_data(monkeypatch):
    sample={"cpu_percent":12.0,"memory_percent":45.0,"network_recv_bps":120,"network_sent_bps":30}
    monkeypatch.setattr(main,"resource_timeline",lambda window:{"window":window,"samples":[sample],"events":[],"processes":[]})
    result=main._route_voice("summarize system activity in the last 15 minutes")
    assert result["type"]=="resource_summary"
    assert result["summary"]=="1 recorded system samples in 15m. CPU ranged from 12.0% to 12.0%. RAM utilization ranged from 45.0% to 45.0%. Peak combined network throughput was 150 bytes per second."


def test_voice_rejects_shell_execution_requests():
    with pytest.raises(HTTPException) as error:
        main._route_voice("run rm -rf /")
    assert error.value.status_code==400
