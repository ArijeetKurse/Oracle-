"""The `mrginu` command for local ORACLE daemon and dashboard lifecycle."""
from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path
from typing import Any

from . import lifecycle
from .lifecycle import ROOT, STATE_DIR

API_URL = "http://127.0.0.1:8000"
DASH_URL = "http://127.0.0.1:5173"


def _get(url: str, timeout: float = 1.2) -> tuple[int, bytes] | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.status, response.read(1_000_000)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(1_000_000)
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


def _port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            return True
    except OSError:
        return False


def _backend_info() -> dict[str, Any] | None:
    response = _get(f"{API_URL}/api/health")
    if not response or response[0] != 200:
        return None
    try:
        import json
        value = json.loads(response[1])
        return value if value.get("status") == "running" else None
    except (ValueError, AttributeError):
        return None


def _dashboard_ready() -> bool:
    response = _get(DASH_URL)
    if not response or response[0] != 200:
        return False
    html = response[1].decode("utf-8", "replace")
    return 'id="root"' in html and "ORACLE" in html


def _spawn_service(name: str, command: list[str], cwd: Path, marker: str, log_name: str) -> None:
    log_path = STATE_DIR / log_name
    lifecycle._rotate_log(log_path)
    process = subprocess.Popen(command, cwd=cwd, env=lifecycle._runtime_env(), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
    try:
        lifecycle.record_service(name, process, marker)
    except Exception:
        try:
            process.terminate()
        except OSError:
            pass
        raise


def ensure_backend() -> tuple[bool, int | None]:
    with lifecycle.startup_lock():
        info = _backend_info()
        if info:
            return False, info.get("pid")
        records = lifecycle.clean_service_records()
        if lifecycle.service_is_alive("backend", records):
            raise RuntimeError(f"Backend process is running but its health endpoint is not ready. See {STATE_DIR / 'backend.log'}.")
        if _port_open(8000):
            raise RuntimeError("Port 8000 is in use by a service that did not identify as ORACLE. It was left untouched.")
        _spawn_service("backend", [sys.executable, "-m", "oracle.service", "backend"], ROOT, "oracle.service backend", "backend.log")
    deadline = time.monotonic() + 18
    while time.monotonic() < deadline:
        info = _backend_info()
        if info:
            return True, info.get("pid")
        if not lifecycle.service_is_alive("backend"):
            break
        time.sleep(0.2)
    raise RuntimeError(f"Backend failed to become ready. See {STATE_DIR / 'backend.log'}.")


def ensure_frontend() -> bool:
    with lifecycle.startup_lock():
        if _dashboard_ready():
            return False
        records = lifecycle.clean_service_records()
        if lifecycle.service_is_alive("frontend", records):
            raise RuntimeError(f"Dashboard process is running but not ready. See {STATE_DIR / 'frontend.log'}.")
        if _port_open(5173):
            raise RuntimeError("Port 5173 is in use by a service that did not identify as the ORACLE dashboard. It was left untouched.")
        frontend = ROOT / "frontend"
        if not (frontend / "node_modules").is_dir():
            raise RuntimeError("Frontend dependencies are missing. Run `npm install` in the frontend directory.")
        _spawn_service("frontend", [sys.executable, "-m", "oracle.service", "frontend"], ROOT, "oracle.service frontend", "frontend.log")
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if _dashboard_ready():
            return True
        if not lifecycle.service_is_alive("frontend"):
            break
        time.sleep(0.2)
    raise RuntimeError(f"Frontend failed to become ready. See {STATE_DIR / 'frontend.log'}.")


def status() -> int:
    daemon = lifecycle.daemon_status()
    backend = _backend_info()
    frontend = _dashboard_ready()
    records = lifecycle.read_json(lifecycle.SERVICE_FILE, {"services": {}}).get("services", {})
    managed_backend = records.get("backend") if backend else None
    managed_frontend = records.get("frontend") if frontend else None
    print(f"Daemon:    {'running (PID ' + str(daemon['pid']) + ')' if daemon['running'] else 'stopped'}")
    print(f"Monitoring: {'active' if daemon['running'] else 'inactive'}" + (f" (PID {daemon['pid']})" if daemon["running"] else ""))
    if backend:
        pid = backend.get("pid") or (managed_backend or {}).get("pid")
        print(f"Backend:   running" + (f" (PID {pid})" if pid else ""))
    else:
        print("Backend:   stopped")
    if frontend:
        pid = (managed_frontend or {}).get("pid")
        print(f"Dashboard: running at {DASH_URL}" + (f" (PID {pid})" if pid else ""))
    else:
        print("Dashboard: stopped")
    return 0


def stop() -> int:
    errors: list[str] = []
    for service in ("frontend", "backend"):
        try:
            if lifecycle.stop_managed_service(service):
                print(f"Stopped managed {service} service.")
        except RuntimeError as exc:
            errors.append(str(exc))
    try:
        if lifecycle.stop_daemon():
            print("Stopped ORACLE monitoring daemon.")
    except RuntimeError as exc:
        errors.append(str(exc))
    if not errors:
        print("ORACLE is stopped. Services that were already running before mrginu were left untouched.")
        return 0
    for error in errors:
        print(f"Error: {error}", file=sys.stderr)
    return 1


def dash() -> int:
    try:
        daemon, started = lifecycle.ensure_daemon()
        print(f"Monitoring daemon {'started' if started else 'already running'} (PID {daemon['pid']}).")
        backend_started, backend_pid = ensure_backend()
        print(f"Backend {'started' if backend_started else 'already running'}" + (f" (PID {backend_pid})" if backend_pid else "") + ".")
        frontend_started = ensure_frontend()
        print(f"Dashboard {'started' if frontend_started else 'already running'} at {DASH_URL}.")
        if not webbrowser.open(DASH_URL, new=2):
            print("Could not launch a browser automatically. Open the dashboard at " + DASH_URL)
        return 0
    except (RuntimeError, OSError) as exc:
        print(f"ORACLE startup error: {exc}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mrginu", description="Start and manage the local ORACLE security monitor.")
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--dash", action="store_true", help="Start monitoring and local dashboard, then open it in a browser")
    actions.add_argument("--stop", action="store_true", help="Gracefully stop the daemon and services started by mrginu")
    actions.add_argument("--status", action="store_true", help="Show daemon, monitoring, backend, and dashboard status")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.status:
            return status()
        if args.stop:
            return stop()
        if args.dash:
            return dash()
        daemon, started = lifecycle.ensure_daemon()
        print(f"ORACLE monitoring daemon {'started' if started else 'already running'} (PID {daemon['pid']}).")
        print("The dashboard was not started. Use `mrginu --dash` to open it.")
        return 0
    except (RuntimeError, OSError) as exc:
        print(f"ORACLE startup error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
