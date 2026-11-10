"""Allowlisted local time-series context for one linked alert investigation."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from . import core, resources


def historical_context_for_investigation(investigation_id: str | None) -> dict | None:
    if not investigation_id: return None
    conn=core.db()
    try:
        row=conn.execute("SELECT id,created_at,pid,process_create_time,severity,detector_id,title,explanation,metric,observed_value,expected_value,deviation,evidence_json,event_id FROM alerts WHERE investigation_id=? ORDER BY created_at DESC LIMIT 1",(investigation_id,)).fetchone()
        if not row: return None
        alert=dict(row); alert_evidence=json.loads(alert.pop("evidence_json") or "{}")
        event_rows=conn.execute("SELECT data FROM events WHERE timestamp>=? AND timestamp<=? ORDER BY timestamp LIMIT 100",
            (datetime.fromtimestamp(max(0,alert['created_at']-300),timezone.utc).isoformat(),
             datetime.fromtimestamp(min(time.time(),alert['created_at']+900),timezone.utc).isoformat())).fetchall()
    finally: conn.close()
    start=max(0.0,float(alert["created_at"])-300)
    end=min(time.time(),float(alert["created_at"])+900)
    history=resources.resource_history(start,end,pid=alert["pid"],create_time=alert["process_create_time"])
    system_fields=("sampled_at","timestamp","cpu_percent","memory_percent","memory_used","memory_available","swap_percent","disk_percent","network_sent_bps","network_recv_bps","disk_read_bps","disk_write_bps","process_count")
    process_fields=("sampled_at","pid","create_time","name","cpu_percent","memory_rss","memory_percent","thread_count","open_fds")
    system=[{key:item.get(key) for key in system_fields} for item in history["samples"][-180:]]
    process=[{key:item.get(key) for key in process_fields} for item in history["process_history"][-80:]]
    events=[]
    for item in event_rows:
        try: event=json.loads(item["data"])
        except (ValueError,TypeError): continue
        events.append({key:event.get(key) for key in ("timestamp","pid","ppid","name","kind","rule","severity","reason","connections")})
    result={"alert":{"id":alert["id"],"timestamp":alert["created_at"],"severity":alert["severity"],
        "detector_id":alert["detector_id"],"title":alert["title"],"explanation":alert["explanation"],
        "metric":alert["metric"],"observed_value":alert["observed_value"],"expected_value":alert["expected_value"],
        "deviation":alert["deviation"],"evidence":{key:alert_evidence.get(key) for key in
            ("pid","process_create_time","process_name","executable","baseline_samples","new_endpoints","correlated_signals") if key in alert_evidence}},
        "window":{"start":start,"end":end,"system_sample_count":len(system),"process_sample_count":len(process)},
        "observed_system_samples":system,"observed_process_samples":process,"related_events":events,
        "limitations":[]}
    if not system: result["limitations"].append("No system resource samples were saved for the alert time window.")
    if alert["pid"] is not None and not process: result["limitations"].append("No per-process resource samples were saved for this process identity in the alert window.")
    if not events: result["limitations"].append("No stored process-start or investigation events were found in this time window.")
    return result
