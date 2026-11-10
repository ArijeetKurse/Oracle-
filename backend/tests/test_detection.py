import json

from oracle import core, detection


def seed_process(times, *, memory=100_000_000, cpu=1.0, connections=None):
    conn = core.db()
    for timestamp in times:
        conn.execute("""INSERT INTO process_resource_samples
            (sampled_at,pid,create_time,name,executable,cpu_percent,memory_rss,memory_percent,thread_count,open_fds,connections)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (timestamp, 4242, 100.5, "worker", "/usr/bin/worker", cpu, memory, 1.0, 2, 5,
             json.dumps(connections or [])))
    conn.commit(); conn.close()


def test_insufficient_baseline_does_not_create_alert():
    seed_process([900, 915, 930], memory=100_000_000)
    seed_process([945], memory=350_000_000)
    assert detection.detect_process_anomalies(945) == []


def test_memory_growth_creates_explainable_alert_and_cooldown_dedupes():
    seed_process([900, 915, 930, 945, 960, 975], memory=100_000_000)
    seed_process([990], memory=350_000_000)
    result = detection.detect_process_anomalies(990)
    assert len(result) == 1
    assert result[0]["detector_id"] == "process.memory_growth"
    assert result[0]["evidence"]["baseline_samples"] == 6
    assert "baseline" in result[0]["explanation"]
    assert detection.detect_process_anomalies(991) == []


def test_cpu_spike_has_explicit_baseline_and_benign_high_value_alone_is_not_alert():
    seed_process([900, 915, 930, 945, 960, 975], cpu=2.0)
    seed_process([990], cpu=60.0)
    alerts = detection.detect_process_anomalies(990)
    assert any(alert["detector_id"] == "process.cpu_spike" for alert in alerts)
    assert all(alert["severity"] in {"low", "medium"} for alert in alerts)


def test_new_network_endpoint_alert_is_a_local_observation():
    seed_process([900, 915, 930, 945, 960, 975], connections=[])
    seed_process([990, 1005], connections=["203.0.113.4:443"])
    alerts = detection.detect_process_anomalies(1005)
    network = next(alert for alert in alerts if alert["detector_id"] == "process.new_network_endpoint")
    assert network["evidence"]["new_endpoints"] == ["203.0.113.4:443"]


def test_alert_state_transition_and_filtering():
    seed_process([900, 915, 930, 945, 960, 975], memory=100_000_000)
    seed_process([990], memory=350_000_000)
    alert = detection.detect_process_anomalies(990)[0]
    updated = detection.update_alert(alert["id"], "acknowledged")
    assert updated["status"] == "acknowledged"
    assert detection.list_alerts(status="resolved") == []
