"""Bounded daemon-side alert actions; no provider call runs in the collector."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import queue
import shutil
import sqlite3
import subprocess
import threading
import time
import urllib.request
from typing import Callable

from . import core
from .settings import get_settings

logger = logging.getLogger(__name__)
_CAPACITY = 64
_investigation_queue: queue.Queue[str] = queue.Queue(_CAPACITY)
_notification_queue: queue.Queue[str] = queue.Queue(_CAPACITY)
_speech_queue: queue.Queue[str] = queue.Queue(_CAPACITY)
_start_lock = threading.Lock()
_investigation_lock = threading.RLock()
_workers_started = False
_SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_DESKTOP_ENV_KEYS=("PATH","HOME","LANG","LC_ALL","DISPLAY","WAYLAND_DISPLAY","XAUTHORITY","XDG_RUNTIME_DIR",
                   "DBUS_SESSION_BUS_ADDRESS","XDG_CURRENT_DESKTOP","DESKTOP_STARTUP_ID")


def _desktop_environment() -> dict[str,str]:
    return {key:os.environ[key] for key in _DESKTOP_ENV_KEYS if os.environ.get(key)}


def start_workers() -> None:
    global _workers_started
    with _start_lock:
        if _workers_started: return
        for name, target in (("investigation", _investigation_loop),
                             ("desktop-notification", _notification_loop),
                             ("spoken-alert", _speech_loop)):
            threading.Thread(target=target, name=f"oracle-{name}", daemon=True).start()
        _workers_started = True
    # Requeue durable alerts that were created just before an unclean daemon stop.
    conn = core.db()
    try:
        for row in conn.execute("SELECT id FROM alerts WHERE created_at>? ORDER BY created_at DESC LIMIT 64", (time.time() - 86400,)):
            enqueue_alert(row["id"])
    finally: conn.close()


def enqueue_alert(alert_id: str) -> None:
    """Queue each action independently; a full queue never stalls monitoring."""
    start_workers_if_needed()
    for work_queue in (_investigation_queue, _notification_queue, _speech_queue):
        try: work_queue.put_nowait(alert_id)
        except queue.Full: logger.warning("Alert action queue full; action deferred or dropped (alert_id=%s)", alert_id)


def start_workers_if_needed() -> None:
    if not _workers_started: start_workers()


def _alert(alert_id: str) -> dict | None:
    conn = core.db()
    try:
        row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if not row: return None
        value = dict(row); value["evidence"] = json.loads(value.pop("evidence_json"))
        return value
    finally: conn.close()


def _eligible(severity: str, threshold: str) -> bool:
    return _SEVERITY.get(severity, -1) >= _SEVERITY.get(threshold, 4)


def _investigation_loop() -> None:
    while True:
        alert_id = _investigation_queue.get()
        try: link_investigation(alert_id)
        except Exception: logger.exception("Automatic alert investigation failed (alert_id=%s)", alert_id)
        finally: _investigation_queue.task_done()


def link_investigation(alert_id: str) -> str | None:
    """Idempotently create/link one deterministic event and investigation per alert."""
    with _investigation_lock:
        return _link_investigation_once(alert_id)


def _link_investigation_once(alert_id: str) -> str | None:
    alert = _alert(alert_id)
    if not alert: return None
    settings = get_settings()
    if not _eligible(alert["severity"], settings["investigation_min_severity"]): return None
    if alert["investigation_id"]: return alert["investigation_id"]
    from .core import Event, Evidence, create_investigation, get_event, get_investigation, persist_event
    event_id = f"resource-alert-{alert_id}"
    event = get_event(event_id)
    evidence = alert["evidence"]
    if event is None:
        from datetime import datetime, timezone
        event = Event(id=event_id, timestamp=datetime.fromtimestamp(alert["created_at"],timezone.utc).isoformat(),
                      pid=alert["pid"], process_create_time=alert["process_create_time"], name=str(evidence.get("process_name") or "unknown")[:256],
                      executable=evidence.get("executable"), connections=evidence.get("new_endpoints", [])[:30],
                      kind="resource_anomaly", severity=alert["severity"], rule=alert["detector_id"],
                      risk_score={"info":0,"low":20,"medium":45,"high":70,"critical":90}.get(alert["severity"],20),
                      reason=alert["explanation"])
        persist_event(event)
    conn = core.db()
    try:
        row = conn.execute("SELECT id FROM investigations WHERE event_id=? ORDER BY created_at LIMIT 1", (event_id,)).fetchone()
    finally: conn.close()
    investigation = get_investigation(row["id"]) if row else None
    if investigation is None:
        investigation = create_investigation(event_id, ai_review=False)
        investigation.evidence.append(Evidence(kind="resource_anomaly", source="ORACLE local detector",
            detail=json.dumps({"alert_id":alert_id,"detector_id":alert["detector_id"],
            "metric":alert["metric"],"observed":alert["observed_value"],"baseline":alert["expected_value"],
            "deviation":alert["deviation"],"evidence":evidence}, sort_keys=True), polarity="supporting"))
        core.persist_investigation(investigation)
    conn = core.db()
    try:
        conn.execute("UPDATE alerts SET event_id=COALESCE(event_id,?), investigation_id=COALESCE(investigation_id,?) WHERE id=?",
                     (event_id, investigation.id, alert_id)); conn.commit()
    finally: conn.close()
    if settings["groq_investigation_reviews"]: core.queue_investigation_review(investigation.id)
    return investigation.id


def _notification_loop() -> None:
    while True:
        alert_id = _notification_queue.get()
        try:
            try: link_investigation(alert_id)
            except Exception: logger.exception("Could not link alert before desktop notification (alert_id=%s)", alert_id)
            _notify(alert_id)
        except Exception: logger.exception("Desktop notification failed (alert_id=%s)", alert_id)
        finally: _notification_queue.task_done()


def _claim_cooldown(provider: str, cooldown: int) -> bool:
    now = time.time(); conn = core.db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT OR IGNORE INTO provider_state(provider,lock_until,next_allowed_at,updated_at) VALUES(?,0,0,?)", (provider, now))
        row = conn.execute("SELECT next_allowed_at FROM provider_state WHERE provider=?", (provider,)).fetchone()
        if row and row["next_allowed_at"] > now:
            conn.rollback(); return False
        conn.execute("UPDATE provider_state SET next_allowed_at=?,updated_at=? WHERE provider=?", (now + cooldown, now, provider))
        conn.commit(); return True
    finally: conn.close()


def _cooldown_remaining(provider: str) -> float:
    conn=core.db()
    try:
        row=conn.execute("SELECT next_allowed_at FROM provider_state WHERE provider=?",(provider,)).fetchone()
        return max(0.0,float(row["next_allowed_at"])-time.time()) if row else 0.0
    finally: conn.close()


def _set_cooldown(provider: str, cooldown: int) -> None:
    now=time.time();conn=core.db()
    try:
        conn.execute("INSERT INTO provider_state(provider,lock_until,next_allowed_at,updated_at) VALUES(?,0,?,?) ON CONFLICT(provider) DO UPDATE SET next_allowed_at=excluded.next_allowed_at,updated_at=excluded.updated_at",(provider,now+cooldown,now));conn.commit()
    finally:conn.close()


def _notify(alert_id: str) -> None:
    alert = _alert(alert_id)
    settings = get_settings()
    if not alert or alert["status"]!="new" or not settings["desktop_notifications"] or not _eligible(alert["severity"], settings["notification_min_severity"]): return
    if alert["notified_at"]: return
    executable = shutil.which("notify-send")
    if not executable: logger.info("notify-send unavailable; alert remains in inbox (alert_id=%s)", alert_id); return
    cooldown = settings["notification_cooldown_seconds"]
    if not _claim_cooldown("desktop_notification", cooldown): return
    urgency = "critical" if alert["severity"] == "critical" else "normal" if alert["severity"] in ("high", "medium") else "low"
    body = f"PID {alert['pid']} · {alert['explanation']}"
    command=[executable,"--app-name=ORACLE",f"--urgency={urgency}","--expire-time=10000",
             "--action=default=Open investigation",alert["title"][:160],body[:500]]
    try:
        result = subprocess.run(command,capture_output=True,text=True,timeout=12,check=False,env=_desktop_environment())
    except (OSError, subprocess.TimeoutExpired):
        logger.info("notify-send could not deliver alert (alert_id=%s)", alert_id)
        return
    # Older notify-send/libnotify versions may not support actions; retry the basic notification.
    if result.returncode!=0:
        try:
            result=subprocess.run([executable,"--app-name=ORACLE",f"--urgency={urgency}","--expire-time=10000",alert["title"][:160],body[:500]],
                                  capture_output=True,text=True,timeout=4,check=False,env=_desktop_environment())
        except (OSError,subprocess.TimeoutExpired):
            logger.info("notify-send could not deliver alert (alert_id=%s)",alert_id);return
    if result.returncode != 0:
        logger.info("Desktop notification service rejected an alert (alert_id=%s, status=%s)", alert_id, result.returncode)
        return
    investigation_id=alert.get("investigation_id")
    if investigation_id and getattr(result,"stdout","").strip()=="default":
        url=f"http://127.0.0.1:5173/?investigation={investigation_id}"
        try:
            with urllib.request.urlopen("http://127.0.0.1:5173/",timeout=1) as response:
                opener=shutil.which("xdg-open")
                if response.status==200 and opener:
                    subprocess.Popen([opener,url],env=_desktop_environment(),stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True,start_new_session=True)
        except Exception: logger.debug("Dashboard is not available for notification action")
    conn = core.db()
    try: conn.execute("UPDATE alerts SET notified_at=? WHERE id=? AND notified_at IS NULL", (time.time(), alert_id)); conn.commit()
    finally: conn.close()


def _spoken_summary(alert: dict) -> str:
    evidence = alert["evidence"]
    name = str(evidence.get("process_name") or "A process")[:80]
    text = f"ORACLE security alert. {name}. {alert['explanation']}"
    if alert["metric"] and alert["observed_value"] is not None:
        metric = alert["metric"].replace("_", " ")[:50]
        expected = f", compared with a recent baseline of {alert['expected_value']:.1f}" if isinstance(alert["expected_value"],(int,float)) else ""
        observed = f"{alert['observed_value']:.1f}"
        text += f" Observed {metric}: {observed}{expected}."
    return text[:700]


def _speech_loop() -> None:
    while True:
        alert_id = _speech_queue.get()
        try:
            delay=_speak(alert_id)
            if delay:
                # Only the speech worker waits; collection, notifications, and investigations continue.
                time.sleep(min(delay,86400))
                try: _speech_queue.put_nowait(alert_id)
                except queue.Full: logger.warning("Speech retry queue full after provider backoff (alert_id=%s)",alert_id)
        except Exception: logger.exception("Spoken alert failed (alert_id=%s)", alert_id)
        finally: _speech_queue.task_done()


def _speak(alert_id: str) -> float:
    alert = _alert(alert_id)
    settings = get_settings()
    if not alert or alert["spoken_at"] or alert["status"]!="new" or not settings["spoken_alerts"] or settings["voice_muted"]: return 0
    if not _eligible(alert["severity"], settings["spoken_alert_min_severity"]): return 0
    if not os.getenv("GNANI_API_KEY"): logger.info("Spoken alert skipped: Gnani is not configured (alert_id=%s)", alert_id); return 0
    spoken_wait=_cooldown_remaining("spoken_alert_cooldown")
    if spoken_wait:
        logger.info("Spoken alert suppressed by configured cooldown (alert_id=%s)",alert_id)
        return 0
    from fastapi import HTTPException
    from .voice_state import claim_tts_slot, release_tts_slot
    if not claim_tts_slot():
        from .voice_state import tts_ready_at
        logger.info("Spoken alert deferred because Timbre is busy or rate limited (alert_id=%s)", alert_id); return max(5,tts_ready_at()-time.time())
    conn=core.db()
    try:
        attempt=conn.execute("UPDATE alerts SET spoken_attempts=spoken_attempts+1 WHERE id=? AND spoken_attempts<3",(alert_id,))
        conn.commit()
        if attempt.rowcount!=1:
            from .voice_state import release_tts_slot
            release_tts_slot()
            logger.warning("Spoken alert retry limit reached (alert_id=%s)",alert_id)
            return 0
    finally: conn.close()
    try:
        # Reuse the interactive endpoint's already configured and validated synthesis implementation.
        from .main import Command, _speak_once
        response = asyncio.run(_speak_once(Command(command=_spoken_summary(alert))))
        audio = response.body
        if not audio or len(audio) > 1_000_000: raise ValueError("Timbre returned an empty or oversized alert recording")
        conn = core.db()
        try: conn.execute("UPDATE alerts SET audio_blob=?,spoken_at=? WHERE id=? AND spoken_at IS NULL", (audio,time.time(),alert_id)); conn.commit()
        finally: conn.close()
        _set_cooldown("spoken_alert_cooldown",settings["spoken_alert_cooldown_seconds"])
    except HTTPException as exc:
        retry = exc.headers.get("Retry-After") if exc.headers else None
        logger.warning("Spoken alert provider request failed status=%s (alert_id=%s)", exc.status_code, alert_id)
        release_tts_slot(retry_after=retry)
        if exc.status_code==429:
            from .voice_state import parse_retry_after
            return max(1,parse_retry_after(retry)) if attempt.rowcount==1 and alert.get("spoken_attempts",0)<2 else 0
        return 0
    except Exception:
        release_tts_slot()
        raise
    else:
        release_tts_slot()
        return 0


def replay_audio(alert_id: str) -> bytes | None:
    conn = core.db()
    try:
        row=conn.execute("SELECT audio_blob FROM alerts WHERE id=?",(alert_id,)).fetchone()
        return bytes(row["audio_blob"]) if row and row["audio_blob"] else None
    finally: conn.close()


def reset_workers_for_tests() -> None:
    # Threads are process-wide in the daemon. Tests use isolated DBs and direct workers.
    while True:
        try: _investigation_queue.get_nowait(); _investigation_queue.task_done()
        except queue.Empty: break
    while True:
        try: _notification_queue.get_nowait(); _notification_queue.task_done()
        except queue.Empty: break
    while True:
        try: _speech_queue.get_nowait(); _speech_queue.task_done()
        except queue.Empty: break
