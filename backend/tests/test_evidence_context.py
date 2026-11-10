import json
import time
from datetime import datetime, timezone

from oracle import core, evidence_context, llm


def test_historical_context_contains_only_recorded_alert_window_measurements(monkeypatch):
    now=time.time()
    alert_id="history-alert"
    conn=core.db()
    conn.execute("""INSERT INTO alerts(id,created_at,status,severity,detector_id,dedupe_key,pid,process_create_time,
        title,explanation,metric,observed_value,expected_value,deviation,confidence,evidence_json,event_id,investigation_id)
        VALUES(?,?,'new','medium','process.memory_growth','d:pid:ctime',22,123.0,'Memory growth','RSS above baseline',
        'memory_rss_bytes',300,100,200,0.65,?,?,?)""",
        (alert_id,now,json.dumps({"pid":22,"process_name":"worker","process_create_time":123.0,"baseline_samples":6}),"event-history","inv-history"))
    conn.execute("""INSERT INTO resource_samples(sampled_at,timestamp,interval_seconds,cpu_percent,memory_percent,memory_total,memory_used,memory_available,process_count)
        VALUES(?,?,5,22.0,40.0,1000,400,600,1)""",(now,datetime.fromtimestamp(now,timezone.utc).isoformat()))
    conn.execute("""INSERT INTO process_resource_samples(sampled_at,pid,create_time,name,executable,cpu_percent,memory_rss,memory_percent,thread_count,open_fds,connections)
        VALUES(?,22,123.0,'worker','/usr/bin/worker',15.0,300,30.0,4,5,'[]')""",(now,))
    conn.commit();conn.close()

    context=evidence_context.historical_context_for_investigation("inv-history")
    assert context["window"]["system_sample_count"]==1
    assert context["observed_system_samples"][0]["cpu_percent"]==22.0
    assert context["observed_process_samples"][0]["memory_rss"]==300
    assert context["alert"]["evidence"]["baseline_samples"]==6

    monkeypatch.setenv("GROQ_API_KEY","mock-groq-key")
    captured={}
    monkeypatch.setattr(llm,"_completion",lambda messages,**_kwargs:captured.update(messages=messages) or "ok")
    llm.answer_question({"pid":22,"name":"worker","connections":[]},{"id":"inv-history","evidence":[],"unknowns":[]},[],"What happened?")
    submitted=json.loads(captured["messages"][1]["content"].split("\n",1)[1])
    assert submitted["historical_observations"]["observations"][0]["cpu_percent"]==22.0
    assert "mock-groq-key" not in json.dumps(submitted)
    assert "event-history" not in json.dumps(submitted)  # internal DB ids are not model context


def test_missing_history_is_reported_as_missing_not_fabricated():
    now=time.time()
    conn=core.db()
    conn.execute("""INSERT INTO alerts(id,created_at,status,severity,detector_id,dedupe_key,pid,process_create_time,
        title,explanation,confidence,evidence_json,investigation_id)
        VALUES('empty-history',?,'new','medium','test','d',1,1,'Alert','Observed',0.5,'{}','inv-empty')""",(now,))
    conn.commit();conn.close()
    context=evidence_context.historical_context_for_investigation("inv-empty")
    assert context["observed_system_samples"]==[]
    assert "No system resource samples" in context["limitations"][0]
