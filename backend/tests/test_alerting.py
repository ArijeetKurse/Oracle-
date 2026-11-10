import json
import time
from concurrent.futures import ThreadPoolExecutor

from fastapi import HTTPException

from oracle import alerting, core, settings
from oracle.voice_state import claim_tts_slot, release_tts_slot, tts_ready_at


def create_alert(*, alert_id="alert-1", severity="medium", detector="process.memory_growth"):
    evidence={"process_name":"worker","executable":"/usr/bin/worker","baseline_samples":8}
    conn=core.db()
    conn.execute("""INSERT INTO alerts(id,created_at,status,severity,detector_id,dedupe_key,pid,process_create_time,
        title,explanation,metric,observed_value,expected_value,deviation,confidence,evidence_json)
        VALUES(?,1000,'new',?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (alert_id,severity,detector,f"worker:{alert_id}",999999,123.5,"worker resource anomaly","Memory is above baseline.","memory_rss_bytes",300,100,200,0.65,json.dumps(evidence)))
    conn.commit(); conn.close()


def test_alert_links_to_one_deterministic_event_and_investigation():
    create_alert()
    settings.update_settings({"investigation_min_severity":"medium","groq_investigation_reviews":False})
    first=alerting.link_investigation("alert-1")
    second=alerting.link_investigation("alert-1")
    assert first == second
    conn=core.db()
    row=conn.execute("SELECT event_id,investigation_id FROM alerts WHERE id='alert-1'").fetchone()
    assert row["event_id"] == "resource-alert-alert-1"
    assert row["investigation_id"] == first
    assert conn.execute("SELECT COUNT(*) FROM investigations WHERE event_id=?",(row["event_id"],)).fetchone()[0] == 1
    conn.close()
    investigation=core.get_investigation(first)
    assert any(item.kind=="resource_anomaly" for item in investigation.evidence)


def test_concurrent_alert_actions_still_create_only_one_investigation():
    create_alert()
    settings.update_settings({"investigation_min_severity":"medium","groq_investigation_reviews":False})
    with ThreadPoolExecutor(max_workers=6) as pool:
        ids=list(pool.map(lambda _index:alerting.link_investigation("alert-1"),range(6)))
    assert len(set(ids))==1
    conn=core.db()
    assert conn.execute("SELECT COUNT(*) FROM investigations WHERE event_id='resource-alert-alert-1'").fetchone()[0]==1
    conn.close()


def test_alert_below_configured_investigation_threshold_is_not_linked():
    create_alert(severity="low")
    settings.update_settings({"investigation_min_severity":"medium"})
    assert alerting.link_investigation("alert-1") is None


def test_alert_investigation_does_not_attribute_a_reused_pid(monkeypatch):
    create_alert()
    settings.update_settings({"investigation_min_severity":"medium","groq_investigation_reviews":False})
    monkeypatch.setattr(core,"inspect_process",lambda _pid:{"pid":999999,"ppid":1,"name":"reused","executable":"/usr/bin/reused","create_time":999.0,"connections":[]})
    iid=alerting.link_investigation("alert-1")
    investigation=core.get_investigation(iid)
    assert any("different process identity" in unknown for unknown in investigation.unknowns)
    assert not any(item.kind=="process_details" for item in investigation.evidence)


def test_desktop_notification_works_without_dashboard_and_failure_is_nonfatal(monkeypatch):
    create_alert(severity="high")
    settings.update_settings({"desktop_notifications":True,"notification_min_severity":"high","alert_cooldown_seconds":300})
    calls=[]
    monkeypatch.setenv("GROQ_API_KEY","private-test-value")
    monkeypatch.setattr(alerting.shutil,"which",lambda name:"/usr/bin/notify-send")
    monkeypatch.setattr(alerting.subprocess,"run",lambda *args,**kwargs: calls.append((args,kwargs)) or type("Result",(),{"returncode":0})())
    alerting._notify("alert-1")
    alerting._notify("alert-1")
    assert calls and calls[0][0][0][0] == "/usr/bin/notify-send"
    assert "GROQ_API_KEY" not in calls[0][1]["env"]
    assert len(calls)==1
    assert alerting._alert("alert-1")["notified_at"] is not None

    create_alert(alert_id="alert-2",severity="critical",detector="other.detector")
    conn=core.db(); conn.execute("UPDATE provider_state SET next_allowed_at=0 WHERE provider='desktop_notification'"); conn.commit(); conn.close()
    monkeypatch.setattr(alerting.subprocess,"run",lambda *args,**kwargs: (_ for _ in ()).throw(OSError("desktop bus unavailable")))
    alerting._notify("alert-2")  # failure path never propagates


def test_notification_action_opens_linked_case_only_when_dashboard_is_reachable(monkeypatch):
    create_alert(severity="high")
    conn=core.db();conn.execute("UPDATE alerts SET investigation_id='case-linked' WHERE id='alert-1'");conn.commit();conn.close()
    settings.update_settings({"desktop_notifications":True,"notification_min_severity":"high"})
    monkeypatch.setattr(alerting.shutil,"which",lambda name:"/usr/bin/notify-send" if name=="notify-send" else "/usr/bin/xdg-open")
    monkeypatch.setattr(alerting.subprocess,"run",lambda *_args,**_kwargs:type("Result",(),{"returncode":0,"stdout":"default"})())
    class Response:
        status=200
        def __enter__(self):return self
        def __exit__(self,*_args):return None
    monkeypatch.setattr(alerting.urllib.request,"urlopen",lambda *_args,**_kwargs:Response())
    opened=[]
    monkeypatch.setattr(alerting.subprocess,"Popen",lambda args,**kwargs:opened.append((args,kwargs)))
    alerting._notify("alert-1")
    assert opened[0][0]==["/usr/bin/xdg-open","http://127.0.0.1:5173/?investigation=case-linked"]
    assert "GNANI_API_KEY" not in opened[0][1]["env"]


def test_spoken_alert_reuses_tts_stores_audio_and_replay(monkeypatch):
    create_alert(severity="critical")
    settings.update_settings({"spoken_alerts":True,"voice_muted":False,"spoken_alert_min_severity":"critical"})
    monkeypatch.setenv("GNANI_API_KEY","mock-key")
    async def fake_speech(command): return type("AudioResponse",(),{"body":b"RIFFmock-wav"})()
    monkeypatch.setattr("oracle.main._speak_once",fake_speech)
    alerting._speak("alert-1")
    assert alerting.replay_audio("alert-1") == b"RIFFmock-wav"
    assert alerting._alert("alert-1")["spoken_at"] is not None


def test_spoken_alert_provider_retry_after_is_persisted(monkeypatch):
    create_alert(severity="critical")
    settings.update_settings({"spoken_alerts":True,"spoken_alert_min_severity":"critical"})
    monkeypatch.setenv("GNANI_API_KEY","mock-key")
    async def failed(_command):
        raise HTTPException(429,"throttled",headers={"Retry-After":"19"})
    monkeypatch.setattr("oracle.main._speak_once",failed)
    before=time.time()
    alerting._speak("alert-1")
    assert tts_ready_at() >= before + 18
    assert claim_tts_slot() is False


def test_tts_single_flight_and_retry_after_parser():
    assert claim_tts_slot(now=100)
    assert not claim_tts_slot(now=101)
    release_tts_slot(retry_after="12",now=102)
    assert not claim_tts_slot(now=113)
    assert claim_tts_slot(now=114)
    release_tts_slot(now=115)

