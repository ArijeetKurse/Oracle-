from oracle import alerting, core, daemon


def test_daemon_starts_alert_workers_with_monitor_and_no_dashboard_dependency(tmp_path,monkeypatch):
    monkeypatch.setattr(daemon,"STATE_DIR",tmp_path)
    monkeypatch.setattr(daemon,"DAEMON_FILE",tmp_path/"daemon.json")
    monkeypatch.setattr(daemon,"db",lambda:core.db())
    called=[]
    monkeypatch.setattr(alerting,"start_workers",lambda:called.append("workers"))
    monkeypatch.setattr(daemon.collector,"start",lambda:called.append("collector"))
    monkeypatch.setattr(daemon.collector,"stop",lambda:called.append("stop"))
    monkeypatch.setattr("oracle.alerting.ensure_workers",lambda:called.append("supervised"))
    monkeypatch.setattr(daemon.signal,"signal",lambda *_args:None)
    class StopAfterOneLoop:
        def __init__(self):self.calls=0
        def wait(self,_timeout):self.calls+=1;return self.calls>1
    monkeypatch.setattr(daemon.threading,"Event",StopAfterOneLoop)
    assert daemon.main()==0
    assert called==["workers","collector","supervised","stop"]
    assert not daemon.DAEMON_FILE.exists()
