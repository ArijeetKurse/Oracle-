from oracle import alerting, core, daemon


def test_daemon_starts_alert_workers_with_monitor_and_no_dashboard_dependency(tmp_path,monkeypatch):
    monkeypatch.setattr(daemon,"STATE_DIR",tmp_path)
    monkeypatch.setattr(daemon,"DAEMON_FILE",tmp_path/"daemon.json")
    monkeypatch.setattr(daemon,"db",lambda:core.db())
    called=[]
    monkeypatch.setattr(alerting,"start_workers",lambda:called.append("workers"))
    monkeypatch.setattr(daemon.collector,"start",lambda:called.append("collector"))
    monkeypatch.setattr(daemon.collector,"stop",lambda:called.append("stop"))
    monkeypatch.setattr(daemon.signal,"signal",lambda *_args:None)
    class StopImmediately:
        def wait(self,_timeout):return True
    monkeypatch.setattr(daemon.threading,"Event",StopImmediately)
    assert daemon.main()==0
    assert called==["workers","collector","stop"]
    assert not daemon.DAEMON_FILE.exists()
