"""Managed loopback-only API service process used by `mrginu --dash`."""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
from logging.handlers import RotatingFileHandler
from pathlib import Path

import uvicorn


def main() -> int:
    if len(os.sys.argv) != 2 or os.sys.argv[1] not in {"backend", "frontend"}:
        raise SystemExit("Usage: python -m oracle.service {backend|frontend}")
    service = os.sys.argv[1]
    state = Path(os.getenv("ORACLE_STATE_DIR", Path.home() / ".local/state/oracle"))
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    handler = RotatingFileHandler(state / f"{service}.log", maxBytes=2_000_000, backupCount=2, encoding="utf-8")
    logging.basicConfig(level=logging.INFO, handlers=[handler], format="%(asctime)s %(levelname)s %(name)s %(message)s")
    if service == "backend":
        uvicorn.run("oracle.main:app", host="127.0.0.1", port=8000, log_config=None, access_log=False)
    else:
        npm = shutil.which("npm")
        if not npm:
            logging.error("npm was not found; install Node.js/npm and retry mrginu --dash")
            return 1
        root = Path(os.getenv("ORACLE_PROJECT_ROOT", Path(__file__).resolve().parents[2]))
        command = [npm, "run", "dev", "--", "--host", "127.0.0.1", "--port", "5173", "--strictPort"]
        child = subprocess.Popen(command, cwd=root / "frontend", env=os.environ.copy(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        try:
            assert child.stdout is not None
            for line in child.stdout:
                logging.info("%s", line.rstrip())
            return child.wait()
        finally:
            if child.poll() is None:
                child.terminate()
                try: child.wait(timeout=3)
                except subprocess.TimeoutExpired: logging.error("Frontend child did not stop after SIGTERM; leaving it alone.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
