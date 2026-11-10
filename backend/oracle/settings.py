"""Validated local settings shared by the daemon and API process."""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone

from . import core

_cache: dict | None = None
_cache_until = 0.0
_SEVERITIES = ("info", "low", "medium", "high", "critical")


def defaults() -> dict:
    return {
        "resource_interval": core.RESOURCE_SAMPLE_INTERVAL,
        "process_resource_interval": core.PROCESS_RESOURCE_SAMPLE_INTERVAL,
        "resource_retention_hours": core.RESOURCE_RETENTION_HOURS,
        "max_resource_processes": core.MAX_RESOURCE_PROCESSES,
        "minimum_observation_minutes": int(os.getenv("ORACLE_MINIMUM_OBSERVATION_MINUTES", "2")),
        "minimum_baseline_samples": int(os.getenv("ORACLE_MINIMUM_BASELINE_SAMPLES", "6")),
        "network_persistence_samples": int(os.getenv("ORACLE_NETWORK_PERSISTENCE_SAMPLES", "2")),
        "cpu_sensitivity": float(os.getenv("ORACLE_CPU_SENSITIVITY", "3.0")),
        "memory_growth_percent": float(os.getenv("ORACLE_MEMORY_GROWTH_PERCENT", "30")),
        "desktop_notifications": os.getenv("ORACLE_DESKTOP_NOTIFICATIONS", "true").lower() not in ("0", "false", "no"),
        "notification_min_severity": os.getenv("ORACLE_NOTIFICATION_MIN_SEVERITY", "high").lower(),
        "investigation_min_severity": os.getenv("ORACLE_INVESTIGATION_MIN_SEVERITY", "medium").lower(),
        "spoken_alerts": os.getenv("ORACLE_SPOKEN_ALERTS", "false").lower() in ("1", "true", "yes"),
        "spoken_alert_min_severity": os.getenv("ORACLE_SPOKEN_ALERT_MIN_SEVERITY", "high").lower(),
        "voice_muted": False,
        "alert_cooldown_seconds": int(os.getenv("ORACLE_ALERT_COOLDOWN_SECONDS", "300")),
        "notification_cooldown_seconds": int(os.getenv("ORACLE_NOTIFICATION_COOLDOWN_SECONDS", "300")),
        "spoken_alert_cooldown_seconds": int(os.getenv("ORACLE_SPOKEN_ALERT_COOLDOWN_SECONDS", "300")),
        "alert_retention_days": int(os.getenv("ORACLE_ALERT_RETENTION_DAYS", "90")),
        "max_alerts": int(os.getenv("ORACLE_MAX_ALERTS", "5000")),
        "groq_investigation_reviews": True,
    }


def _validate(name: str, value):
    if name in {"desktop_notifications", "spoken_alerts", "voice_muted", "groq_investigation_reviews"}:
        if type(value) is not bool: raise ValueError(f"{name} must be a boolean")
        return value
    if name in {"notification_min_severity", "spoken_alert_min_severity", "investigation_min_severity"}:
        if not isinstance(value,str) or value.lower() not in _SEVERITIES: raise ValueError(f"{name} must be one of {', '.join(_SEVERITIES)}")
        return value.lower()
    if name in {"resource_interval","process_resource_interval","cpu_sensitivity","memory_growth_percent"}:
        if isinstance(value,bool) or not isinstance(value,(int,float)): raise ValueError(f"{name} must be numeric")
        value=float(value)
        ranges={"resource_interval":(1,60),"process_resource_interval":(5,300),"cpu_sensitivity":(1,10),"memory_growth_percent":(10,300)}
        low,high=ranges[name]
        if not low<=value<=high: raise ValueError(f"{name} must be between {low} and {high}")
        return value
    if name in {"resource_retention_hours","max_resource_processes","minimum_observation_minutes","minimum_baseline_samples","network_persistence_samples","alert_cooldown_seconds","notification_cooldown_seconds","spoken_alert_cooldown_seconds","alert_retention_days","max_alerts"}:
        if isinstance(value,bool) or not isinstance(value,int): raise ValueError(f"{name} must be an integer")
        ranges={"resource_retention_hours":(1,720),"max_resource_processes":(1,512),"minimum_observation_minutes":(1,60),"minimum_baseline_samples":(4,100),"network_persistence_samples":(2,3),"alert_cooldown_seconds":(30,3600),"notification_cooldown_seconds":(30,3600),"spoken_alert_cooldown_seconds":(30,3600),"alert_retention_days":(1,3650),"max_alerts":(100,50000)}
        low,high=ranges[name]
        if not low<=value<=high: raise ValueError(f"{name} must be between {low} and {high}")
        return value
    raise ValueError(f"Unknown setting: {name}")


def get_settings(*, refresh: bool = False) -> dict:
    global _cache, _cache_until
    now=time.monotonic()
    if not refresh and _cache is not None and now<_cache_until:
        return dict(_cache)
    result=defaults()
    connection=core.db()
    try:
        rows=connection.execute("SELECT key,value FROM app_settings").fetchall()
        for row in rows:
            try: result[row["key"]]=_validate(row["key"],json.loads(row["value"]))
            except (ValueError,TypeError,json.JSONDecodeError):
                continue
    finally: connection.close()
    _cache=result; _cache_until=now+5
    return dict(result)


def update_settings(changes: dict) -> dict:
    validated={name:_validate(name,value) for name,value in changes.items()}
    now=datetime.now(timezone.utc).isoformat()
    connection=core.db()
    try:
        connection.executemany("INSERT INTO app_settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",[(name,json.dumps(value),now) for name,value in validated.items()])
        connection.commit()
    finally: connection.close()
    return get_settings(refresh=True)


def reset_cache_for_tests() -> None:
    global _cache,_cache_until
    _cache=None; _cache_until=0
