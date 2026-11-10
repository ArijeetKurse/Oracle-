import asyncio
import os
import sqlite3
import threading
import time

from oracle import alerting, core, settings
from oracle.detection import create_synthetic_test_alert


def _valid_wav():
    return b"RIFF"+b"\x00\x00\x00\x00"+b"WAVE"+b"fmt "+b"\x00\x00\x00\x00"


def test_startup_starts_and_supervises_all_delivery_workers():
    alerting.start_workers(recover=False)
    try:
        states=alerting.ensure_workers()
        assert states=={"investigation":True,"desktop-notification":True,"spoken-alert":True}
        status=alerting.worker_status(os.getpid())
        assert all(item["state"] in {"running","busy"} for item in status["workers"].values())
        assert status["database_path"]==str(core.DB_PATH.resolve())
    finally:
        alerting.stop_workers(timeout=2)


def test_recovery_scan_error_does_not_kill_worker_and_supervisor_keeps_it_alive(monkeypatch):
    monkeypatch.setattr(alerting,"_POLL_SECONDS",0.01)
    recovered=[]
    observed=threading.Event()
    def flaky_recovery(kind=None):
        if kind=="notification" and not recovered:
            recovered.append("transient sqlite error")
            raise sqlite3.OperationalError("database is locked")
        if kind=="notification":observed.set()
    monkeypatch.setattr(alerting,"_fill_pending_queues",flaky_recovery)
    alerting.start_workers(recover=False)
    try:
        assert observed.wait(2)
        assert alerting.ensure_workers()["desktop-notification"]
        assert recovered==["transient sqlite error"]
    finally:
        alerting.stop_workers(timeout=2)


def test_future_retry_waits_then_is_recovered_by_polling(monkeypatch):
    settings.update_settings({"desktop_notifications":True,"notification_min_severity":"high",
        "spoken_alerts":True,"voice_muted":False,"spoken_alert_min_severity":"high"})
    monkeypatch.setenv("GNANI_API_KEY","mock-only-key")
    alert=create_synthetic_test_alert()
    monkeypatch_time=time.time()
    conn=core.db()
    conn.execute("UPDATE alerts SET notification_retry_at=?,delivery_retry_at=? WHERE id=?",(monkeypatch_time+30,monkeypatch_time+30,alert["id"]))
    conn.commit();conn.close()
    alerting._fill_pending_queues()
    assert alert["id"] not in list(alerting._notification_queue.queue)
    assert alert["id"] not in list(alerting._speech_queue.queue)
    conn=core.db();conn.execute("UPDATE alerts SET notification_retry_at=?,delivery_retry_at=? WHERE id=?",(time.time()-1,time.time()-1,alert["id"]));conn.commit();conn.close()
    alerting._fill_pending_queues()
    assert alert["id"] in list(alerting._notification_queue.queue)
    assert alert["id"] in list(alerting._speech_queue.queue)


def test_restart_recovery_delivers_synthetic_high_without_dashboard_or_live_provider(monkeypatch):
    settings.update_settings({"desktop_notifications":True,"notification_min_severity":"high",
        "spoken_alerts":True,"voice_muted":False,"spoken_alert_min_severity":"high",
        "notification_cooldown_seconds":30,"spoken_alert_cooldown_seconds":30})
    monkeypatch.setenv("GNANI_API_KEY","mock-only-key")
    alert=create_synthetic_test_alert()
    invoked=[]
    monkeypatch.setattr(alerting.shutil,"which",lambda name:{"notify-send":"/usr/bin/notify-send","pw-play":"/usr/bin/pw-play"}.get(name))
    def fake_player(command,**kwargs):
        invoked.append((command[0],kwargs.get("env",{})))
        return type("Result",(),{"returncode":0,"stdout":""})()
    monkeypatch.setattr(alerting.subprocess,"run",fake_player)
    async def fake_timbre(_command):
        return type("AudioResponse",(),{"body":_valid_wav()})()
    monkeypatch.setattr("oracle.main._speak_once",fake_timbre)

    # start_workers performs the same durable startup recovery used by a fresh daemon.
    alerting.start_workers(recover=True)
    try:
        alerting._notification_queue.join()
        alerting._speech_queue.join()
        delivered=alerting._alert(alert["id"])
        assert delivered["notification_attempts"]==1 and delivered["notified_at"] is not None
        assert delivered["spoken_attempts"]==1 and delivered["audio_blob"]==_valid_wav()
        assert delivered["playback_attempts"]==1 and delivered["played_at"] is not None
        assert len(invoked)==2 and {item[0] for item in invoked}=={"/usr/bin/notify-send","/usr/bin/pw-play"}
        assert all("GNANI_API_KEY" not in environment for _,environment in invoked)
        status=alerting.delivery_status(alert["id"])
        assert status["notification"]["state"]=="delivered"
        assert status["speech"]["state"]=="played"
    finally:
        alerting.stop_workers(timeout=2)
