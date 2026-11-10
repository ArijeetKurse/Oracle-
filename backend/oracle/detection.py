"""Explainable, baseline-based process resource detectors."""
from __future__ import annotations

import json
import logging
import statistics
import time
import uuid
from datetime import datetime, timezone

from . import core
from .settings import get_settings

logger = logging.getLogger(__name__)


def detect_process_anomalies(sampled_at: float | None = None) -> list[dict]:
    """Compare latest process samples with identity-specific prior observations."""
    now = float(sampled_at if sampled_at is not None else time.time())
    settings = get_settings()
    conn = core.db()
    created: list[dict] = []
    try:
        latest = conn.execute("""SELECT p.* FROM process_resource_samples p
            JOIN (SELECT pid,create_time,MAX(sampled_at) t FROM process_resource_samples GROUP BY pid,create_time) x
            ON p.pid=x.pid AND p.create_time=x.create_time AND p.sampled_at=x.t
            WHERE p.sampled_at >= ?""", (now - 60,)).fetchall()
        for row in latest:
            start = now - settings["minimum_observation_minutes"] * 60
            prior = conn.execute("""SELECT cpu_percent,memory_rss,memory_percent,connections FROM process_resource_samples
                WHERE pid=? AND create_time=? AND sampled_at>=? AND sampled_at<? ORDER BY sampled_at""",
                (row["pid"], row["create_time"], start, row["sampled_at"])).fetchall()
            if len(prior) < settings["minimum_baseline_samples"]:
                continue
            signals = []
            cpu = row["cpu_percent"]
            prior_cpu = [float(x["cpu_percent"]) for x in prior if x["cpu_percent"] is not None]
            if cpu is not None and len(prior_cpu) >= settings["minimum_baseline_samples"]:
                baseline = statistics.median(prior_cpu)
                deviations = [abs(value - baseline) for value in prior_cpu]
                mad = statistics.median(deviations) if deviations else 0.0
                threshold = max(30.0, baseline + settings["cpu_sensitivity"] * max(mad, 5.0))
                if float(cpu) >= threshold:
                    signals.append(("process.cpu_spike", "cpu_percent", float(cpu), baseline, float(cpu - baseline),
                                    "CPU use is substantially above this process identity's recent baseline."))
            old_mem = [int(x["memory_rss"]) for x in prior if x["memory_rss"] is not None]
            if row["memory_rss"] is not None and old_mem:
                baseline = statistics.median(old_mem)
                observed = int(row["memory_rss"])
                growth = ((observed - baseline) / max(baseline, 1)) * 100
                if observed - baseline >= 100 * 1024 * 1024 and growth >= settings["memory_growth_percent"]:
                    signals.append(("process.memory_growth", "memory_rss_bytes", float(observed), float(baseline), growth,
                                    "Resident memory grew materially compared with this process identity's recent baseline."))
            current_connections = set(json.loads(row["connections"] or "[]"))
            prior_connections = set()
            for item in prior[:-1]:
                prior_connections.update(json.loads(item["connections"] or "[]"))
            # Require the new endpoint to persist across recent samples; short-lived
            # connection churn is common and is not sufficient evidence by itself.
            recent = conn.execute("SELECT connections FROM process_resource_samples WHERE pid=? AND create_time=? ORDER BY sampled_at DESC LIMIT 3",
                                  (row["pid"], row["create_time"])).fetchall()
            endpoint_counts: dict[str, int] = {}
            for item in recent:
                for endpoint in json.loads(item["connections"] or "[]"):
                    endpoint_counts[endpoint] = endpoint_counts.get(endpoint, 0) + 1
            new_endpoints = sorted(endpoint for endpoint, count in endpoint_counts.items()
                                   if endpoint not in prior_connections and count >= 2)
            if new_endpoints:
                signals.append(("process.new_network_endpoint", "new_remote_endpoints", float(len(new_endpoints)), 0.0,
                                float(len(new_endpoints)), "A remote endpoint appeared that was not present in this process identity's sampled history."))
            # Correlation increases severity only when separate resource/network signals coincide.
            if len(signals) > 1:
                for index, signal in enumerate(signals):
                    signals[index] = (*signal, {"correlated_signals": len(signals)})
            for signal in signals:
                detector_id, metric, observed, expected, deviation, explanation, *extra = signal
                evidence = {"pid": row["pid"], "process_create_time": row["create_time"],
                            "process_name": row["name"], "executable": row["executable"],
                            "baseline_samples": len(prior), "observed_at": row["sampled_at"]}
                if detector_id == "process.new_network_endpoint": evidence["new_endpoints"] = new_endpoints
                if extra: evidence.update(extra[0])
                severity = "medium" if len(signals) > 1 else "low"
                if detector_id == "process.memory_growth" and deviation >= 100: severity = "medium"
                created_alert = _persist_alert(conn, now, detector_id, row, metric, observed, expected,
                                               deviation, severity, explanation, evidence, settings["alert_cooldown_seconds"])
                if created_alert: created.append(created_alert)
        conn.commit()
    finally:
        conn.close()
    return created


def _persist_alert(conn, now, detector_id, process, metric, observed, expected, deviation,
                   severity, explanation, evidence, cooldown):
    dedupe = f"{detector_id}:{process['pid']}:{process['create_time']}"
    existing = conn.execute("SELECT id FROM alerts WHERE dedupe_key=? AND created_at>=? ORDER BY created_at DESC LIMIT 1",
                            (dedupe, now - cooldown)).fetchone()
    if existing: return None
    alert = {"id": str(uuid.uuid4()), "created_at": now, "status": "new", "severity": severity,
             "detector_id": detector_id, "dedupe_key": dedupe, "pid": process["pid"],
             "process_create_time": process["create_time"], "title": f"{process['name']}: {detector_id.rsplit('.', 1)[-1].replace('_', ' ')}",
             "explanation": explanation, "metric": metric, "observed_value": observed,
             "expected_value": expected, "deviation": deviation, "confidence": 0.65,
             "evidence": evidence, "investigation_id": None, "notified_at": None,
             "spoken_at": None, "snoozed_until": None, "resolved_at": None}
    conn.execute("""INSERT INTO alerts(id,created_at,status,severity,detector_id,dedupe_key,pid,process_create_time,
        title,explanation,metric,observed_value,expected_value,deviation,confidence,evidence_json)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (alert["id"], now, "new", severity, detector_id, dedupe, process["pid"], process["create_time"],
         alert["title"], explanation, metric, observed, expected, deviation, alert["confidence"], json.dumps(evidence)))
    return alert


def list_alerts(*, status: str | None = None, severity: str | None = None, pid: int | None = None,
                since: float | None = None, limit: int = 100) -> list[dict]:
    clauses, values = [], []
    for column, value in (("status", status), ("severity", severity), ("pid", pid)):
        if value is not None: clauses.append(f"{column}=?"); values.append(value)
    if since is not None: clauses.append("created_at>=?"); values.append(since)
    sql = "SELECT * FROM alerts" + (" WHERE " + " AND ".join(clauses) if clauses else "") + " ORDER BY created_at DESC LIMIT ?"
    values.append(max(1, min(500, limit)))
    conn = core.db()
    try:
        rows = conn.execute(sql, values).fetchall()
        output = []
        for row in rows:
            item = dict(row); item["evidence"] = json.loads(item.pop("evidence_json")); output.append(item)
        return output
    finally: conn.close()


def update_alert(alert_id: str, status: str, *, snooze_seconds: int = 3600) -> dict | None:
    if status not in {"acknowledged", "snoozed", "resolved", "new"}:
        raise ValueError("status must be new, acknowledged, snoozed, or resolved")
    now = time.time()
    conn = core.db()
    try:
        cursor = conn.execute("UPDATE alerts SET status=?,snoozed_until=?,resolved_at=? WHERE id=?",
            (status, now + max(60, min(86400, int(snooze_seconds))) if status == "snoozed" else None,
             now if status == "resolved" else None, alert_id))
        conn.commit()
    finally: conn.close()
    return next((item for item in list_alerts(limit=500) if item["id"] == alert_id), None) if cursor.rowcount else None
