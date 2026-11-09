import os
import sqlite3
import subprocess
import sys
import time

import pytest

from oracle import cli, lifecycle


@pytest.fixture
def isolated_runtime(tmp_path, monkeypatch):
    state = tmp_path / "state"
    monkeypatch.setattr(lifecycle, "STATE_DIR", state)
    monkeypatch.setattr(lifecycle, "DAEMON_FILE", state / "daemon.json")
    monkeypatch.setattr(lifecycle, "SERVICE_FILE", state / "services.json")
    monkeypatch.setattr(cli, "STATE_DIR", state)
    monkeypatch.setenv("ORACLE_STATE_DIR", str(state))
    monkeypatch.setenv("ORACLE_DB", str(tmp_path / "oracle.db"))
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    return state


def test_cli_help_and_command_options(capsys):
    with pytest.raises(SystemExit) as result:
        cli.build_parser().parse_args(["--help"])
    assert result.value.code == 0
    help_text = capsys.readouterr().out
    assert "--dash" in help_text and "--stop" in help_text and "--status" in help_text
    assert cli.build_parser().parse_args(["--dash"]).dash
    assert cli.build_parser().parse_args(["--status"]).status
    assert cli.build_parser().parse_args(["--stop"]).stop


def test_default_cli_starts_only_monitoring_and_repeat_is_idempotent(isolated_runtime, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["mrginu"])
    try:
        assert cli.main() == 0
        first = lifecycle.daemon_status()
        assert first["running"] and first["pid"]
        assert "dashboard was not started" in capsys.readouterr().out.lower()
        assert cli.main() == 0
        second = lifecycle.daemon_status()
        assert second == first
        assert "already running" in capsys.readouterr().out.lower()
        # The monitor itself operates without an API key.
        assert not os.getenv("GROQ_API_KEY")
        time.sleep(0.3)
        database = sqlite3.connect(os.environ["ORACLE_DB"])
        assert database.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events'").fetchone()
        database.close()
    finally:
        lifecycle.stop_daemon()
    assert not lifecycle.daemon_status()["running"]


def test_stale_or_reused_pid_is_not_treated_as_oracle(isolated_runtime):
    current = os.getpid()
    record = {"pid": current, "start_ticks": lifecycle.proc_identity(current) + 1, "marker": "oracle.daemon"}
    assert not lifecycle.process_matches(record)
    assert not lifecycle.stop_daemon()


def test_status_command_does_not_start_services(isolated_runtime, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["mrginu", "--status"])
    assert cli.main() == 0
    output = capsys.readouterr().out
    assert "Daemon:    stopped" in output
    assert "Monitoring: inactive" in output
    assert not lifecycle.daemon_status()["running"]


def test_dash_starts_missing_services_once_and_opens_local_url(isolated_runtime, monkeypatch, capsys):
    monkeypatch.setattr(lifecycle, "ensure_daemon", lambda: ({"running": True, "pid": 41}, True))
    monkeypatch.setattr(cli, "ensure_backend", lambda: (True, 42))
    monkeypatch.setattr(cli, "ensure_frontend", lambda: True)
    opened = []
    monkeypatch.setattr(cli.webbrowser, "open", lambda url, new=0: opened.append((url, new)) or True)
    monkeypatch.setattr(sys, "argv", ["mrginu", "--dash"])
    assert cli.main() == 0
    output = capsys.readouterr().out
    assert "Monitoring daemon started" in output and "Backend started" in output
    assert "Dashboard started" in output
    assert opened == [(cli.DASH_URL, 2)]


def test_stop_command_stops_managed_daemon(isolated_runtime, monkeypatch, capsys):
    lifecycle.ensure_daemon()
    monkeypatch.setattr(sys, "argv", ["mrginu", "--stop"])
    assert cli.main() == 0
    assert "Stopped ORACLE monitoring daemon" in capsys.readouterr().out
    assert not lifecycle.daemon_status()["running"]


def test_service_stop_only_targets_registered_process_group(isolated_runtime):
    managed = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(20)"], start_new_session=True)
    unrelated = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(20)"], start_new_session=True)
    try:
        lifecycle.record_service("test", managed, "time.sleep(20)")
        assert lifecycle.stop_managed_service("test")
        assert managed.poll() is not None
        assert unrelated.poll() is None
    finally:
        if managed.poll() is None:
            managed.terminate()
            managed.wait(timeout=2)
        unrelated.terminate()
        unrelated.wait(timeout=2)
