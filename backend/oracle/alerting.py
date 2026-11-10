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
import tempfile
import threading
import time
import urllib.request

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
_workers_stop = threading.Event()
_worker_threads:dict[str,threading.Thread]={}
_worker_busy:set[str]=set()
_SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_DESKTOP_ENV_KEYS=("PATH","HOME","LANG","LC_ALL","DISPLAY","WAYLAND_DISPLAY","XAUTHORITY","XDG_RUNTIME_DIR",
                   "DBUS_SESSION_BUS_ADDRESS","XDG_CURRENT_DESKTOP","DESKTOP_STARTUP_ID","PIPEWIRE_REMOTE")
_MAX_DELIVERY_ATTEMPTS = 3
_POLL_SECONDS = 3


def _desktop_environment() -> dict[str,str]:
    return {key:os.environ[key] for key in _DESKTOP_ENV_KEYS if os.environ.get(key)}


def start_workers(*, recover:bool=True) -> None:
    ensure_workers()
    if recover:
        try:_fill_pending_queues()
        except Exception:logger.exception("Could not recover pending alert delivery at daemon startup; workers will poll again")


def enqueue_alert(alert_id: str) -> None:
    """Wake independent workers; SQLite remains the durable source of pending work."""
    start_workers_if_needed()
    for work_queue in (_investigation_queue, _notification_queue, _speech_queue):
        try: work_queue.put_nowait(alert_id)
        except queue.Full: logger.warning("Alert action queue full; alert remains pending in SQLite (alert_id=%s)", alert_id)


def start_workers_if_needed() -> None:
    # Collector callers only start thread objects and enqueue IDs; recovery DB scans
    # happen at daemon startup or on idle worker threads, never in the sampling path.
    _ensure_worker_threads()


def _targets()->dict[str,object]:
    return {"investigation":_investigation_loop,"desktop-notification":_notification_loop,"spoken-alert":_speech_loop}


def _write_worker_state(name:str,state:str,error:str|None=None)->None:
    conn=None
    try:
        conn=core.db()
        conn.execute("INSERT INTO daemon_worker_status(name,pid,state,heartbeat_at,last_error) VALUES(?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET pid=excluded.pid,state=excluded.state,heartbeat_at=excluded.heartbeat_at,last_error=CASE WHEN excluded.last_error='' THEN NULL ELSE COALESCE(excluded.last_error,daemon_worker_status.last_error) END",
                     (name,os.getpid(),state,time.time(),error))
        conn.commit()
    except Exception:
        logger.exception("Could not persist %s worker heartbeat",name)
    finally:
        if conn is not None:conn.close()


def _ensure_worker_threads()->None:
    global _workers_started
    with _start_lock:
        if _workers_stop.is_set():_workers_stop.clear()
        for name,target in _targets().items():
            current=_worker_threads.get(name)
            if current is not None and current.is_alive():
                continue
            if current is not None:
                logger.error("Alert worker thread exited; restarting worker=%s",name)
            thread=threading.Thread(target=_worker_entry,args=(name,target),name=f"oracle-{name}",daemon=True)
            _worker_threads[name]=thread
            thread.start()
            logger.info("Alert delivery worker started worker=%s thread_id=%s",name,thread.ident)
        _workers_started=True


def _worker_entry(name:str,target)->None:
    _write_worker_state(name,"running","")
    try:target()
    except BaseException as exc:
        logger.exception("Alert delivery worker terminated unexpectedly worker=%s",name)
        _write_worker_state(name,"failed",type(exc).__name__)
        raise
    else:_write_worker_state(name,"stopped")


def ensure_workers()->dict[str,bool]:
    """Supervise worker liveness; daemon calls periodically, enqueue can start threads cheaply."""
    _ensure_worker_threads()
    with _start_lock:threads=dict(_worker_threads)
    states={name:bool(thread and thread.is_alive()) for name,thread in threads.items()}
    for name,alive in states.items():
        if alive:
            state="busy" if name in _worker_busy else "running"
            _write_worker_state(name,state)
    return states


def stop_workers(timeout:float=1.0)->None:
    global _workers_started,_worker_threads
    _workers_stop.set()
    for work_queue in (_investigation_queue,_notification_queue,_speech_queue):
        try:work_queue.put_nowait(None)
        except queue.Full:pass
    threads=list(_worker_threads.values())
    deadline=time.monotonic()+max(0.0,timeout)
    for thread in threads:
        thread.join(max(0.0,deadline-time.monotonic()))
    for name in _worker_threads:
        _write_worker_state(name,"stopped")
    with _start_lock:
        _worker_threads={name:thread for name,thread in _worker_threads.items() if thread.is_alive()}
        _workers_started=bool(_worker_threads)


def _fill_pending_queues(kind: str | None = None) -> None:
    """Recover queued or interrupted deliveries from durable alert state."""
    now=time.time(); preferences=get_settings(); conn=core.db()
    try:
        if kind in (None,"notification") and preferences["desktop_notifications"]:
            severities=_eligible_values(preferences["notification_min_severity"]);marks=','.join('?' for _ in severities)
            rows=conn.execute(f"SELECT id,severity FROM alerts WHERE status='new' AND severity IN ({marks}) AND notified_at IS NULL AND notification_attempts<? AND (notification_retry_at IS NULL OR notification_retry_at<=?) ORDER BY created_at LIMIT ?",(*severities,_MAX_DELIVERY_ATTEMPTS,now,_CAPACITY)).fetchall()
            for row in rows:
                try:_notification_queue.put_nowait(row["id"])
                except queue.Full:break
        if kind in (None,"investigation"):
            severities=_eligible_values(preferences["investigation_min_severity"]);marks=','.join('?' for _ in severities)
            rows=conn.execute(f"SELECT id FROM alerts WHERE synthetic=0 AND severity IN ({marks}) AND event_id IS NULL AND investigation_id IS NULL ORDER BY created_at LIMIT ?",(*severities,_CAPACITY)).fetchall()
            for row in rows:
                try:_investigation_queue.put_nowait(row["id"])
                except queue.Full:break
        if (kind in (None,"speech") and preferences["spoken_alerts"] and not preferences["voice_muted"]
                and os.getenv("GNANI_API_KEY")):
            severities=_eligible_values(preferences["spoken_alert_min_severity"]);marks=','.join('?' for _ in severities)
            rows=conn.execute(f"SELECT id,severity,spoken_attempts,playback_attempts,(audio_blob IS NOT NULL) AS has_audio FROM alerts WHERE status='new' AND severity IN ({marks}) AND played_at IS NULL AND (delivery_retry_at IS NULL OR delivery_retry_at<=?) ORDER BY created_at LIMIT ?",(*severities,now,_CAPACITY)).fetchall()
            for row in rows:
                attempts=row["playback_attempts"] if row["has_audio"] else row["spoken_attempts"]
                if attempts < _MAX_DELIVERY_ATTEMPTS:
                    try:_speech_queue.put_nowait(row["id"])
                    except queue.Full:break
    finally:conn.close()


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


def _eligible_values(threshold:str)->tuple[str,...]:
    return tuple(value for value,rank in _SEVERITY.items() if rank>=_SEVERITY.get(threshold,4))


def _investigation_loop() -> None:
    _worker_loop("investigation",_investigation_queue,lambda alert_id:link_investigation(alert_id),"investigation")


def _worker_loop(name:str,work_queue:queue.Queue,handler,kind:str)->None:
    while not _workers_stop.is_set():
        try:
            try:alert_id=work_queue.get(timeout=_POLL_SECONDS)
            except queue.Empty:
                try:_fill_pending_queues(kind)
                except Exception as exc:
                    logger.exception("Pending alert recovery failed worker=%s",name)
                    _write_worker_state(name,"running",f"pending recovery {type(exc).__name__}")
                continue
            if alert_id is None:
                work_queue.task_done()
                break
            _worker_busy.add(name)
            _write_worker_state(name,"busy")
            failed=False
            try:handler(alert_id)
            except Exception as exc:
                failed=True
                logger.exception("Alert delivery action failed worker=%s alert_id=%s",name,alert_id)
                _write_worker_state(name,"running",f"alert action {type(exc).__name__}")
            finally:
                work_queue.task_done()
                _worker_busy.discard(name)
                if not failed and not _workers_stop.is_set():_write_worker_state(name,"running","")
        except Exception as exc:
            # Queue polling and SQLite recovery are guarded so a transient storage
            # error cannot silently kill a worker while _workers_started stays true.
            logger.exception("Alert worker loop recovered from error worker=%s",name)
            _worker_busy.discard(name)
            _write_worker_state(name,"running",f"worker loop {type(exc).__name__}")
            _workers_stop.wait(1)


def link_investigation(alert_id: str) -> str | None:
    """Idempotently create/link one deterministic event and investigation per alert."""
    with _investigation_lock:
        return _link_investigation_once(alert_id)


def _link_investigation_once(alert_id: str) -> str | None:
    alert = _alert(alert_id)
    if not alert: return None
    if alert.get("synthetic"): return None
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
    def deliver(alert_id:str)->None:
        try:link_investigation(alert_id)
        except Exception:logger.exception("Could not link alert before desktop notification (alert_id=%s)",alert_id)
        _notify(alert_id)
    _worker_loop("desktop-notification",_notification_queue,deliver,"notification")


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
    if alert.get("notification_retry_at") and alert["notification_retry_at"]>time.time():return
    if alert.get("notification_attempts",0)>=_MAX_DELIVERY_ATTEMPTS:return
    cooldown_remaining=_cooldown_remaining("desktop_notification")
    if cooldown_remaining:
        conn=core.db()
        try:conn.execute("UPDATE alerts SET notification_retry_at=? WHERE id=?",(time.time()+cooldown_remaining,alert_id));conn.commit()
        finally:conn.close()
        return
    conn=core.db()
    try:
        result=conn.execute("UPDATE alerts SET notification_attempts=notification_attempts+1 WHERE id=? AND notification_attempts<? AND notified_at IS NULL",(alert_id,_MAX_DELIVERY_ATTEMPTS))
        conn.commit()
        if result.rowcount!=1:return
        attempt=int(alert.get("notification_attempts",0))+1
    finally:conn.close()

    def failed(reason:str)->None:
        retry_at=time.time()+min(300,15*(2**(attempt-1))) if attempt<_MAX_DELIVERY_ATTEMPTS else None
        conn=core.db()
        try:conn.execute("UPDATE alerts SET notification_retry_at=? WHERE id=?",(retry_at,alert_id));conn.commit()
        finally:conn.close()
        logger.info("Desktop notification delivery failed (alert_id=%s, attempt=%s, reason=%s)",alert_id,attempt,reason)

    executable = shutil.which("notify-send")
    if not executable: failed("notify-send unavailable"); return
    cooldown = settings["notification_cooldown_seconds"]
    urgency = "critical" if alert["severity"] == "critical" else "normal" if alert["severity"] in ("high", "medium") else "low"
    prefix="SYNTHETIC TEST · " if alert.get("synthetic") else ""
    process=f"PID {alert['pid']} · " if alert.get("pid") is not None else ""
    body = f"{prefix}{process}{alert['explanation']}"
    command=[executable,"--app-name=ORACLE",f"--urgency={urgency}","--expire-time=10000",
             "--action=default=Open investigation",alert["title"][:160],body[:500]]
    try:
        result = subprocess.run(command,capture_output=True,text=True,timeout=12,check=False,env=_desktop_environment())
    except (OSError, subprocess.TimeoutExpired):
        failed("notify-send could not start or timed out")
        return
    # Older notify-send/libnotify versions may not support actions; retry the basic notification.
    if result.returncode!=0:
        try:
            result=subprocess.run([executable,"--app-name=ORACLE",f"--urgency={urgency}","--expire-time=10000",alert["title"][:160],body[:500]],
                                  capture_output=True,text=True,timeout=4,check=False,env=_desktop_environment())
        except (OSError,subprocess.TimeoutExpired):
            failed("fallback notification could not start or timed out");return
    if result.returncode != 0:
        failed(f"desktop service status {result.returncode}")
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
    try: conn.execute("UPDATE alerts SET notified_at=?,notification_retry_at=NULL WHERE id=? AND notified_at IS NULL", (time.time(), alert_id)); conn.commit()
    finally: conn.close()
    _set_cooldown("desktop_notification",cooldown)


def _spoken_summary(alert: dict) -> str:
    evidence = alert["evidence"]
    name = str(evidence.get("process_name") or "A process")[:80]
    marker="Synthetic test alert; this is not a real threat. " if alert.get("synthetic") else ""
    text = f"{marker}ORACLE security alert. {name}. {alert['explanation']}"
    if alert["metric"] and alert["observed_value"] is not None:
        metric = alert["metric"].replace("_", " ")[:50]
        expected = f", compared with a recent baseline of {alert['expected_value']:.1f}" if isinstance(alert["expected_value"],(int,float)) else ""
        observed = f"{alert['observed_value']:.1f}"
        text += f" Observed {metric}: {observed}{expected}."
    return text[:700]


def _speech_loop() -> None:
    _worker_loop("spoken-alert",_speech_queue,_speak,"speech")


def _schedule_speech_retry(alert_id:str, delay:float, reason:str)->None:
    conn=core.db()
    try:
        conn.execute("UPDATE alerts SET delivery_retry_at=? WHERE id=? AND played_at IS NULL",(time.time()+max(1,min(86400,delay)),alert_id));conn.commit()
    finally:conn.close()
    logger.info("Spoken alert deferred (alert_id=%s, retry_seconds=%s, reason=%s)",alert_id,int(delay),reason)


def _wav_bytes(audio:bytes)->bool:
    return len(audio)>=12 and audio[:4]==b"RIFF" and audio[8:12]==b"WAVE"


def _play_audio(audio:bytes, *, timeout:float=45.0)->bool:
    """Play a WAV in the current desktop session without passing provider secrets."""
    player=None;command_prefix=None
    for name,prefix in (("pw-play",[]),("aplay",["-q"]),("paplay",[])):
        executable=shutil.which(name)
        if executable:
            player=executable;command_prefix=prefix;break
    if not player:
        logger.warning("No supported desktop WAV player found (tried pw-play, aplay, paplay)")
        return False
    fd,path=tempfile.mkstemp(prefix="oracle-alert-",suffix=".wav")
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,"wb") as recording:
            recording.write(audio);recording.flush();os.fsync(recording.fileno())
        try:
            result=subprocess.run([player,*command_prefix,path],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,timeout=timeout,check=False,close_fds=True,env=_desktop_environment())
        except subprocess.TimeoutExpired:
            logger.warning("Alert playback timed out; the player process was terminated")
            return False
        except OSError as exc:
            logger.warning("Could not start desktop audio playback (%s)",type(exc).__name__)
            return False
        if result.returncode!=0:
            logger.warning("Desktop audio player failed (status=%s)",result.returncode)
            return False
        return True
    finally:
        try:os.unlink(path)
        except FileNotFoundError:pass


def _speak(alert_id: str) -> float:
    alert = _alert(alert_id)
    settings = get_settings()
    if not alert or alert.get("played_at") or alert["status"]!="new" or not settings["spoken_alerts"] or settings["voice_muted"]: return 0
    if not _eligible(alert["severity"], settings["spoken_alert_min_severity"]): return 0
    if alert.get("delivery_retry_at") and alert["delivery_retry_at"]>time.time():return 0
    audio=bytes(alert["audio_blob"]) if alert.get("audio_blob") else None
    if audio is None:
        if not os.getenv("GNANI_API_KEY"):
            logger.info("Spoken alert pending: Gnani is not configured (alert_id=%s)",alert_id);return 0
        if alert.get("spoken_attempts",0)>=_MAX_DELIVERY_ATTEMPTS:return 0
        cooldown=_cooldown_remaining("spoken_alert_cooldown")
        if cooldown:
            _schedule_speech_retry(alert_id,cooldown,"spoken alert cooldown")
            return cooldown
        from .voice_state import claim_tts_slot,release_tts_slot,tts_ready_at
        if not claim_tts_slot():
            delay=max(5,tts_ready_at()-time.time())
            _schedule_speech_retry(alert_id,delay,"Timbre single-flight or Retry-After")
            return delay
        conn=core.db()
        try:
            result=conn.execute("UPDATE alerts SET spoken_attempts=spoken_attempts+1 WHERE id=? AND spoken_attempts<? AND audio_blob IS NULL",(alert_id,_MAX_DELIVERY_ATTEMPTS));conn.commit()
            if result.rowcount!=1:
                release_tts_slot();return 0
            attempt=int(alert.get("spoken_attempts",0))+1
        finally:conn.close()
        try:
            # Reuse the configured provider implementation. Only the speech worker waits on the network.
            from .main import Command,_speak_once
            response=asyncio.run(_speak_once(Command(command=_spoken_summary(alert))))
            audio=bytes(response.body)
            if not _wav_bytes(audio) or len(audio)>1_000_000:raise ValueError("Timbre response is not a bounded WAV recording")
            conn=core.db()
            try:conn.execute("UPDATE alerts SET audio_blob=?,spoken_at=?,delivery_retry_at=NULL WHERE id=? AND audio_blob IS NULL",(audio,time.time(),alert_id));conn.commit()
            finally:conn.close()
        except Exception as exc:
            from .voice_state import release_tts_slot
            retry=None
            try:
                from fastapi import HTTPException
                from .voice_state import parse_retry_after
                if isinstance(exc,HTTPException):
                    retry=parse_retry_after(exc.headers.get("Retry-After") if exc.headers else None)
                    logger.warning("Timbre synthesis failed (status=%s, alert_id=%s)",exc.status_code,alert_id)
                else:logger.warning("Timbre synthesis failed (alert_id=%s, error=%s)",alert_id,type(exc).__name__)
            finally:release_tts_slot(retry_after=(str(retry) if retry else None))
            retryable=not isinstance(exc,HTTPException) or exc.status_code==429 or exc.status_code>=500 or exc.status_code==408
            if retryable and attempt<_MAX_DELIVERY_ATTEMPTS:
                delay=retry or min(300,15*(2**(attempt-1)))
                _schedule_speech_retry(alert_id,delay,"Timbre synthesis retry")
            elif not retryable:
                conn=core.db()
                try:conn.execute("UPDATE alerts SET spoken_attempts=? WHERE id=?",(_MAX_DELIVERY_ATTEMPTS,alert_id));conn.commit()
                finally:conn.close()
            return 0
        else:
            from .voice_state import release_tts_slot
            release_tts_slot()

    conn=core.db()
    try:
        result=conn.execute("UPDATE alerts SET playback_attempts=playback_attempts+1 WHERE id=? AND played_at IS NULL AND playback_attempts<? AND audio_blob IS NOT NULL",(alert_id,_MAX_DELIVERY_ATTEMPTS));conn.commit()
        if result.rowcount!=1:return 0
        attempt=int(alert.get("playback_attempts",0))+1
    finally:conn.close()
    if not _play_audio(audio):
        delay=min(300,15*(2**(attempt-1))) if attempt<_MAX_DELIVERY_ATTEMPTS else 0
        _schedule_speech_retry(alert_id,delay,"desktop speaker playback failed") if delay else None
        return 0
    conn=core.db()
    try:conn.execute("UPDATE alerts SET played_at=?,delivery_retry_at=NULL WHERE id=? AND played_at IS NULL",(time.time(),alert_id));conn.commit()
    finally:conn.close()
    # Cooldown is consumed only after the speakers accepted the complete WAV.
    _set_cooldown("spoken_alert_cooldown",settings["spoken_alert_cooldown_seconds"])
    return 0


def replay_audio(alert_id: str) -> bytes | None:
    conn = core.db()
    try:
        row=conn.execute("SELECT audio_blob FROM alerts WHERE id=?",(alert_id,)).fetchone()
        return bytes(row["audio_blob"]) if row and row["audio_blob"] else None
    finally: conn.close()


def delivery_status(alert_id:str)->dict|None:
    alert=_alert(alert_id)
    if not alert:return None
    preferences=get_settings()
    notification_enabled=preferences["desktop_notifications"] and _eligible(alert["severity"],preferences["notification_min_severity"])
    if alert["notified_at"]:notification_state="delivered"
    elif not preferences["desktop_notifications"]:notification_state="disabled"
    elif not notification_enabled:notification_state="below_threshold"
    elif alert["notification_attempts"]>=_MAX_DELIVERY_ATTEMPTS:notification_state="failed"
    else:notification_state="pending"
    speech_enabled=preferences["spoken_alerts"] and not preferences["voice_muted"] and _eligible(alert["severity"],preferences["spoken_alert_min_severity"])
    if alert.get("played_at"):speech_state="played"
    elif not preferences["spoken_alerts"] or preferences["voice_muted"]:speech_state="disabled"
    elif not _eligible(alert["severity"],preferences["spoken_alert_min_severity"]):speech_state="below_threshold"
    elif not os.getenv("GNANI_API_KEY"):speech_state="not_configured"
    elif alert.get("audio_blob") and alert["playback_attempts"]>=_MAX_DELIVERY_ATTEMPTS:speech_state="playback_failed"
    elif not alert.get("audio_blob") and alert["spoken_attempts"]>=_MAX_DELIVERY_ATTEMPTS:speech_state="synthesis_failed"
    else:speech_state="pending"
    return {"alert_id":alert_id,"synthetic":bool(alert["synthetic"]),
        "notification":{"state":notification_state,"attempts":alert["notification_attempts"],"delivered_at":alert["notified_at"]},
        "speech":{"state":speech_state,"attempts":alert["playback_attempts"],"generation_attempts":alert["spoken_attempts"],
                  "generated_at":alert["spoken_at"],"played_at":alert["played_at"],"retry_at":alert["delivery_retry_at"],
                  "player_available":any(shutil.which(name) for name in ("pw-play","aplay","paplay")) if speech_enabled else False}}


def worker_status(expected_pid:int|None=None)->dict:
    conn=core.db()
    try:rows={row["name"]:dict(row) for row in conn.execute("SELECT name,pid,state,heartbeat_at,last_error FROM daemon_worker_status").fetchall()}
    finally:conn.close()
    now=time.time();result={}
    for name in ("investigation","desktop-notification","spoken-alert"):
        row=rows.get(name)
        if not row:result[name]={"state":"no_heartbeat"};continue
        age=max(0.0,now-float(row["heartbeat_at"]))
        state=row["state"]
        if expected_pid is None:state="daemon_stopped"
        elif int(row["pid"])!=expected_pid:state="other_daemon"
        elif age>10 and state not in ("stopped","failed"):state="stale"
        result[name]={"state":state,"pid":row["pid"],"heartbeat_age_seconds":round(age,1),"last_error":row["last_error"]}
    return {"database_path":str(core.DB_PATH.resolve()),"expected_daemon_pid":expected_pid,"workers":result}


def reset_workers_for_tests() -> None:
    # Threads are process-wide in the daemon. Tests use isolated DBs and direct workers.
    stop_workers(timeout=1.0)
    while True:
        try: _investigation_queue.get_nowait(); _investigation_queue.task_done()
        except queue.Empty: break
    while True:
        try: _notification_queue.get_nowait(); _notification_queue.task_done()
        except queue.Empty: break
    while True:
        try: _speech_queue.get_nowait(); _speech_queue.task_done()
        except queue.Empty: break
