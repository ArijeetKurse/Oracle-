"""Foreground implementation for the detached, explicitly started monitor daemon."""
from __future__ import annotations

import fcntl
import json
import logging
import os
import signal
import threading
from pathlib import Path
from logging.handlers import RotatingFileHandler

from .core import POLL_INTERVAL, collector, db
from .lifecycle import DAEMON_FILE, STATE_DIR, proc_identity


def main() -> int:
    STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    logging.basicConfig(level=logging.INFO, handlers=[RotatingFileHandler(STATE_DIR / "daemon.log", maxBytes=2_000_000, backupCount=2, encoding="utf-8")], format="%(asctime)s %(levelname)s %(name)s %(message)s")
    lock_handle = (STATE_DIR / "daemon.lock").open("a+")
    try:
        fcntl.flock(lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return 0
    stop_event = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop_event.set())
    signal.signal(signal.SIGINT, lambda *_: stop_event.set())
    pid = os.getpid()
    record = {"pid": pid, "start_ticks": proc_identity(pid), "marker": "oracle.daemon", "managed": True}
    temp = DAEMON_FILE.with_suffix(f".json.{pid}.tmp")
    temp.write_text(json.dumps(record), encoding="utf-8")
    temp.chmod(0o600)
    os.replace(temp, DAEMON_FILE)
    try:
        connection = db()
        connection.close()
        collector.start()
        while not stop_event.wait(0.5):
            pass
    finally:
        collector.stop()
        try:
            current = json.loads(DAEMON_FILE.read_text(encoding="utf-8"))
            if current.get("pid") == pid and current.get("start_ticks") == record["start_ticks"]:
                DAEMON_FILE.unlink(missing_ok=True)
        except (OSError, ValueError):
            pass
        lock_handle.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
