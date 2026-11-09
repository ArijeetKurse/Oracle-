"""Safe local process management for the explicitly invoked ORACLE CLI."""
from __future__ import annotations

import fcntl
import json
import os
import signal
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


ROOT = Path(os.getenv("ORACLE_PROJECT_ROOT", Path(__file__).resolve().parents[2])).resolve()
DEFAULT_STATE_DIR = Path(os.getenv("XDG_STATE_HOME", Path.home() / ".local/state")).expanduser() / "oracle"
STATE_DIR = Path(os.getenv("ORACLE_STATE_DIR", DEFAULT_STATE_DIR)).expanduser()
DAEMON_FILE = STATE_DIR / "daemon.json"
SERVICE_FILE = STATE_DIR / "services.json"


def ensure_state_dir() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        STATE_DIR.chmod(0o700)
    except OSError:
        pass


@contextmanager
def startup_lock() -> Iterator[None]:
    ensure_state_dir()
    with (STATE_DIR / "startup.lock").open("a+") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def _atomic_json(path: Path, data: dict[str, Any]) -> None:
    ensure_state_dir()
    temp = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    temp.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
    temp.chmod(0o600)
    os.replace(temp, path)


def read_json(path: Path, default: dict[str, Any] | None = None) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else (default or {})
    except (OSError, ValueError):
        return default or {}


def proc_identity(pid: int) -> int | None:
    """Return Linux /proc starttime ticks, stable across PID reuse."""
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        fields_after_comm = raw[raw.rfind(")") + 2:].split()
        return int(fields_after_comm[19])  # stat field 22, after fields 1 and 2
    except (OSError, ValueError, IndexError):
        return None


def process_matches(record: dict[str, Any]) -> bool:
    try:
        pid = int(record["pid"])
        if proc_identity(pid) != int(record["start_ticks"]):
            return False
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace")
        marker = str(record.get("marker", ""))
        return bool(marker and marker in cmdline)
    except (OSError, KeyError, TypeError, ValueError):
        return False


def process_group_exists(pgid: int) -> bool:
    # Treat zombies as exited; they cannot serve requests and are reaped by their parent/init.
    try:
        for entry in Path('/proc').iterdir():
            if not entry.name.isdigit():
                continue
            try:
                raw=(entry / 'stat').read_text(encoding='ascii')
                fields=raw[raw.rfind(')')+2:].split()
                if len(fields)>2 and fields[0] not in {'Z','X'} and int(fields[2])==pgid:
                    return True
            except (OSError,ValueError):
                continue
    except OSError:
        try: os.killpg(pgid,0); return True
        except (ProcessLookupError,PermissionError): return False
    return False


def daemon_status() -> dict[str, Any]:
    record = read_json(DAEMON_FILE)
    running = process_matches(record)
    if not running and record:
        try:
            DAEMON_FILE.unlink()
        except OSError:
            pass
    return {"running": running, "pid": int(record["pid"]) if running else None}


def _runtime_env() -> dict[str, str]:
    env = os.environ.copy()
    env["ORACLE_PROJECT_ROOT"] = str(ROOT)
    env["ORACLE_STATE_DIR"] = str(STATE_DIR)
    env["PYTHONUNBUFFERED"] = "1"
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(ROOT / "backend") + (os.pathsep + existing if existing else "")
    return env


def _rotate_log(path: Path, limit: int = 2_000_000) -> None:
    if path.exists() and path.stat().st_size >= limit:
        old = path.with_suffix(path.suffix + ".1")
        try:
            old.unlink(missing_ok=True)
            path.replace(old)
        except OSError:
            pass


def ensure_daemon() -> tuple[dict[str, Any], bool]:
    with startup_lock():
        current = daemon_status()
        if current["running"]:
            return current, False
        ensure_state_dir()
        log = STATE_DIR / "daemon.log"
        _rotate_log(log)
        proc = subprocess.Popen([sys.executable, "-m", "oracle.daemon"], cwd=ROOT, env=_runtime_env(), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            status = daemon_status()
            if status["running"]:
                return status, True
            if proc.poll() is not None:
                break
            time.sleep(0.1)
        raise RuntimeError(f"ORACLE daemon did not start. See {log} for details.")


def stop_daemon(timeout: float = 8) -> bool:
    status = daemon_status()
    if not status["running"]:
        return False
    record = read_json(DAEMON_FILE)
    if not process_matches(record):
        return False
    os.kill(int(record["pid"]), signal.SIGTERM)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not process_matches(record):
            return True
        time.sleep(0.1)
    raise RuntimeError(f"Daemon PID {record['pid']} did not stop gracefully; no force kill was sent.")


def _service_records() -> dict[str, Any]:
    return read_json(SERVICE_FILE, {"services": {}})


def _save_services(data: dict[str, Any]) -> None:
    _atomic_json(SERVICE_FILE, data)


def service_is_alive(name: str, records: dict[str, Any] | None = None) -> bool:
    records = records or _service_records()
    record = records.get("services", {}).get(name)
    return bool(record and process_matches(record))


def record_service(name: str, process: subprocess.Popen, marker: str) -> dict[str, Any]:
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and proc_identity(process.pid) is None:
        if process.poll() is not None:
            raise RuntimeError(f"Could not start {name} service (exit code {process.returncode}).")
        time.sleep(0.05)
    ticks = proc_identity(process.pid)
    if ticks is None:
        raise RuntimeError(f"Could not identify the new {name} service process safely.")
    records = _service_records()
    records.setdefault("services", {})[name] = {"pid": process.pid, "start_ticks": ticks, "marker": marker, "managed": True}
    _save_services(records)
    return records["services"][name]


def stop_managed_service(name: str, timeout: float = 7) -> bool:
    with startup_lock():
        records = _service_records()
        record = records.get("services", {}).get(name)
        if not record:
            return False
        if not process_matches(record):
            if process_group_exists(int(record.get("pid", -1))):
                raise RuntimeError(f"Refusing to signal {name}: the recorded process identity is stale while its process group still exists.")
            records["services"].pop(name, None)
            _save_services(records)
            return False
        pid = int(record["pid"])
        # Each managed command starts a new session, so this group contains only its own tree.
        try:
            if os.getpgid(pid) != pid:
                raise RuntimeError(f"Refusing to stop {name}: its process group is not isolated.")
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not process_matches(record) and not process_group_exists(pid):
                records["services"].pop(name, None)
                _save_services(records)
                return True
            time.sleep(0.1)
        raise RuntimeError(f"{name} service did not stop gracefully; no force kill was sent.")


def clean_service_records() -> dict[str, Any]:
    records = _service_records()
    records["services"] = {name: record for name, record in records.get("services", {}).items() if process_matches(record)}
    _save_services(records)
    return records
