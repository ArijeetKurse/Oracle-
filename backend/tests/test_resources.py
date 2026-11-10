from types import SimpleNamespace

import psutil

from oracle import core, resources


class FakeProcess:
    def __init__(self, pid=7, created=100.0, *, fail=None, connections=()):
        self.pid = pid
        self.created = created
        self.fail = fail
        self._connections = connections

    def create_time(self):
        if self.fail == "create": raise psutil.NoSuchProcess(self.pid)
        return self.created

    def name(self): return "worker"
    def exe(self): return "/usr/bin/worker"
    def cpu_percent(self, interval=None): return 3.5
    def memory_info(self):
        if self.fail == "memory": raise psutil.AccessDenied(self.pid)
        return SimpleNamespace(rss=40_000_000)
    def memory_percent(self): return 1.5
    def num_threads(self): return 4
    def num_fds(self): return 12
    def net_connections(self, kind="inet"):
        if self.fail == "connections": raise psutil.AccessDenied(self.pid)
        return self._connections


def install_system_metrics(monkeypatch, *, cpu=23.0, sent=2000, received=3000):
    monkeypatch.setattr(resources.psutil, "cpu_percent", lambda interval=None: cpu)
    monkeypatch.setattr(resources.psutil, "virtual_memory", lambda: SimpleNamespace(percent=41.0,total=16_000,used=6_560,available=9_440))
    monkeypatch.setattr(resources.psutil, "swap_memory", lambda: SimpleNamespace(percent=10.0,total=4_000,used=400))
    monkeypatch.setattr(resources.psutil, "disk_usage", lambda path: SimpleNamespace(percent=62.0))
    monkeypatch.setattr(resources.psutil, "disk_io_counters", lambda: SimpleNamespace(read_bytes=1000,write_bytes=2000))
    monkeypatch.setattr(resources.psutil, "net_io_counters", lambda: SimpleNamespace(bytes_sent=sent,bytes_recv=received))
    monkeypatch.setattr(resources.psutil, "boot_time", lambda: 100.0)


def test_resource_collection_persists_real_system_and_process_metrics(monkeypatch):
    install_system_metrics(monkeypatch)
    endpoint = SimpleNamespace(raddr=SimpleNamespace(ip="192.0.2.8",port=443))
    process = FakeProcess(connections=[endpoint])

    first = resources.collect_resource_sample([process],sampled_at=200,monotonic_now=10)
    install_system_metrics(monkeypatch,sent=2600,received=3900)
    second = resources.collect_resource_sample([process],sampled_at=205,monotonic_now=15,include_processes=False)

    assert first["cpu_percent"] is None  # psutil's first nonblocking CPU reading is not meaningful.
    assert first["memory_percent"] == 41.0 and first["disk_percent"] == 62.0
    assert first["process_samples_saved"] == 1
    assert second["network_sent_bps"] == 120 and second["network_recv_bps"] == 180
    history = resources.resource_history(0,300)
    assert len(history["samples"]) == 2
    assert history["processes"][0]["pid"] == 7
    assert history["processes"][0]["connections"] == ["192.0.2.8:443"]


def test_process_disappearance_and_permission_errors_are_skipped_without_losing_system_sample(monkeypatch):
    install_system_metrics(monkeypatch)
    samples = resources.collect_resource_sample([FakeProcess(fail="create"),FakeProcess(pid=8,fail="memory")],sampled_at=200,monotonic_now=10)
    assert samples["process_count"] == 0
    assert samples["process_samples_saved"] == 0
    assert resources.resource_history(0,300)["samples"]


def test_pid_reuse_keeps_process_history_separated_by_creation_time(monkeypatch):
    install_system_metrics(monkeypatch)
    resources.collect_resource_sample([FakeProcess(pid=9,created=101)],sampled_at=200,monotonic_now=10)
    resources.collect_resource_sample([FakeProcess(pid=9,created=202)],sampled_at=205,monotonic_now=15)
    history=resources.resource_history(0,300)
    assert {(item["pid"],item["create_time"]) for item in history["processes"]} == {(9,101),(9,202)}


def test_retention_removes_old_resource_and_process_samples(monkeypatch):
    monkeypatch.setattr(core,"RESOURCE_RETENTION_HOURS",1)
    connection=core.db()
    connection.execute("INSERT INTO resource_samples(sampled_at,timestamp,interval_seconds,process_count) VALUES(?,?,?,0)",(1,"1970-01-01T00:00:01+00:00",5))
    connection.execute("INSERT INTO process_resource_samples(sampled_at,pid,create_time,name) VALUES(1,1,1,'old')")
    connection.commit(); connection.close()
    core.prune_database()
    connection=core.db()
    assert connection.execute("SELECT COUNT(*) FROM resource_samples").fetchone()[0] == 0
    assert connection.execute("SELECT COUNT(*) FROM process_resource_samples").fetchone()[0] == 0
    connection.close()


def test_database_initialization_adds_resource_tables_without_replacing_existing_events():
    event=core.Event(pid=1,name="before",executable="/usr/bin/before")
    core.persist_event(event)
    core.db().close()
    assert core.get_event(event.id).name == "before"
    connection=core.db()
    assert connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='resource_samples'").fetchone()
    assert connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='process_resource_samples'").fetchone()
    connection.close()
