"""Bounded, local resource-history sampling and queries."""
from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Iterable

import psutil

from . import core

logger = logging.getLogger(__name__)
_last_system: dict[str, int | float] | None = None
_last_system_monotonic: float | None = None
_system_cpu_primed = False
_process_cpu_seen: set[tuple[int, float]] = set()


def _rate(current: int | float | None, previous: int | float | None, elapsed: float | None) -> float | None:
    if current is None or previous is None or not elapsed or elapsed <= 0 or current < previous:
        return None
    return (current - previous) / elapsed


def _optional_call(obj, method: str, *args, **kwargs):
    try:
        return getattr(obj, method)(*args, **kwargs)
    except (AttributeError, NotImplementedError, OSError, psutil.Error):
        return None


def _process_metric(process: psutil.Process) -> dict | None:
    try:
        pid = int(process.pid)
        create_time = float(process.create_time())
        name = process.name() or "unknown"
        executable = _optional_call(process, "exe")
        cpu = process.cpu_percent(interval=None)
        identity = (pid, create_time)
        if identity not in _process_cpu_seen:
            cpu = None
            _process_cpu_seen.add(identity)
        memory = process.memory_info()
        rss = int(memory.rss)
        memory_percent = float(process.memory_percent())
        threads = _optional_call(process, "num_threads")
        open_fds = _optional_call(process, "num_fds")
        return {
            "pid": pid, "create_time": create_time, "name": str(name)[:256],
            "executable": str(executable)[:1024] if executable else None,
            "cpu_percent": float(cpu) if cpu is not None else None,
            "memory_rss": rss, "memory_percent": memory_percent,
            "thread_count": int(threads) if threads is not None else None,
            "open_fds": int(open_fds) if open_fds is not None else None,
            "_process": process,
        }
    except (AttributeError, TypeError, ValueError, OSError, psutil.Error, ProcessLookupError):
        return None


def _connections(process: psutil.Process) -> list[str] | None:
    try:
        connections = process.net_connections(kind="inet")
        endpoints = set()
        for connection in connections:
            remote = getattr(connection, "raddr", None)
            if remote:
                ip = getattr(remote, "ip", None)
                port = getattr(remote, "port", None)
                if ip is not None and port is not None:
                    endpoints.add(f"{ip}:{port}")
        return sorted(endpoints)[:30]
    except (AttributeError, OSError, psutil.Error, ProcessLookupError):
        return None


def collect_resource_sample(processes: Iterable[psutil.Process], *, sampled_at: float | None = None,
                            monotonic_now: float | None = None, include_processes: bool = True) -> dict:
    """Capture one system sample and optionally a bounded top-process sample."""
    global _last_system, _last_system_monotonic, _system_cpu_primed
    now = float(sampled_at if sampled_at is not None else time.time())
    monotonic = float(monotonic_now if monotonic_now is not None else time.monotonic())
    timestamp = datetime.fromtimestamp(now, timezone.utc).isoformat()

    cpu_percent = _optional_call(psutil, "cpu_percent", interval=None)
    if not _system_cpu_primed:
        cpu_percent = None
        _system_cpu_primed = True
    memory = _optional_call(psutil, "virtual_memory")
    swap = _optional_call(psutil, "swap_memory")
    if memory is None or swap is None:
        logger.warning("Some system memory counters are unavailable")
    try:
        disk_percent = float(psutil.disk_usage("/").percent)
    except (OSError, psutil.Error):
        disk_percent = None
    disk_io = _optional_call(psutil, "disk_io_counters")
    network_io = _optional_call(psutil, "net_io_counters")
    current = {
        "disk_read_bytes": int(disk_io.read_bytes) if disk_io else None,
        "disk_write_bytes": int(disk_io.write_bytes) if disk_io else None,
        "network_sent_bytes": int(network_io.bytes_sent) if network_io else None,
        "network_recv_bytes": int(network_io.bytes_recv) if network_io else None,
    }
    elapsed = monotonic - _last_system_monotonic if _last_system_monotonic is not None else None
    previous = _last_system or {}
    sample = {
        "sampled_at": now, "timestamp": timestamp,
        "interval_seconds": float(elapsed) if elapsed and elapsed > 0 else 0.0,
        "cpu_percent": float(cpu_percent) if cpu_percent is not None else None,
        "memory_percent": float(memory.percent) if memory else None, "memory_total": int(memory.total) if memory else None,
        "memory_used": int(memory.used) if memory else None, "memory_available": int(memory.available) if memory else None,
        "swap_percent": float(swap.percent) if swap else None, "swap_total": int(swap.total) if swap else None,
        "swap_used": int(swap.used) if swap else None,
        "disk_percent": disk_percent,
        **current,
        "disk_read_bps": _rate(current["disk_read_bytes"], previous.get("disk_read_bytes"), elapsed),
        "disk_write_bps": _rate(current["disk_write_bytes"], previous.get("disk_write_bytes"), elapsed),
        "network_sent_bps": _rate(current["network_sent_bytes"], previous.get("network_sent_bytes"), elapsed),
        "network_recv_bps": _rate(current["network_recv_bytes"], previous.get("network_recv_bytes"), elapsed),
        "uptime_seconds": max(0.0, now - float(_optional_call(psutil, "boot_time") or now)),
    }
    _last_system, _last_system_monotonic = current, monotonic

    process_count = 0
    rows: list[dict] = []
    valid_identities: set[tuple[int, float]] = set()
    if include_processes:
        candidates = []
        for process in processes:
            metric = _process_metric(process)
            if metric is None:
                continue
            process_count += 1
            valid_identities.add((metric["pid"], metric["create_time"]))
            score = (metric["cpu_percent"] or 0.0) + (metric["memory_percent"] or 0.0)
            candidates.append((score, metric))
        candidates.sort(key=lambda item: item[0], reverse=True)
        from .settings import get_settings
        max_processes=get_settings()["max_resource_processes"]
        for _, metric in candidates[:max_processes]:
            process = metric.pop("_process")
            metric["connections"] = _connections(process)
            rows.append(metric)
        _process_cpu_seen.intersection_update(valid_identities)
    sample["process_count"] = process_count

    connection = core.db()
    try:
        connection.execute(
            """INSERT OR REPLACE INTO resource_samples (
                sampled_at,timestamp,interval_seconds,cpu_percent,memory_percent,memory_total,memory_used,memory_available,
                swap_percent,swap_total,swap_used,disk_percent,disk_read_bytes,disk_write_bytes,disk_read_bps,disk_write_bps,
                network_sent_bytes,network_recv_bytes,network_sent_bps,network_recv_bps,uptime_seconds,process_count
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            tuple(sample[key] for key in (
                "sampled_at","timestamp","interval_seconds","cpu_percent","memory_percent","memory_total","memory_used","memory_available",
                "swap_percent","swap_total","swap_used","disk_percent","disk_read_bytes","disk_write_bytes","disk_read_bps","disk_write_bps",
                "network_sent_bytes","network_recv_bytes","network_sent_bps","network_recv_bps","uptime_seconds","process_count"
            )),
        )
        if include_processes:
            connection.executemany(
                """INSERT OR REPLACE INTO process_resource_samples
                (sampled_at,pid,create_time,name,executable,cpu_percent,memory_rss,memory_percent,thread_count,open_fds,connections)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                [(now, item["pid"], item["create_time"], item["name"], item["executable"], item["cpu_percent"],
                  item["memory_rss"], item["memory_percent"], item["thread_count"], item["open_fds"],
                  json.dumps(item["connections"]) if item["connections"] is not None else None) for item in rows],
            )
        connection.commit()
    finally:
        connection.close()
    sample["process_samples_saved"] = len(rows)
    if include_processes and rows:
        try:
            from .detection import detect_process_anomalies
            detect_process_anomalies(now)
        except Exception:
            logger.exception("Resource anomaly evaluation failed")
    return sample


def resource_history(start: float, end: float, *, pid: int | None = None, create_time: float | None = None) -> dict:
    connection = core.db()
    try:
        samples = [dict(row) for row in connection.execute(
            "SELECT * FROM resource_samples WHERE sampled_at >= ? AND sampled_at <= ? ORDER BY sampled_at",
            (start, end),
        ).fetchall()]
        query = """WITH ranked AS (
            SELECT p.*, ROW_NUMBER() OVER (PARTITION BY pid,create_time ORDER BY sampled_at DESC) AS rank
            FROM process_resource_samples p WHERE sampled_at >= ? AND sampled_at <= ?
        ) SELECT * FROM ranked WHERE rank=1"""
        params: list = [start, end]
        if pid is not None:
            query += " AND pid = ?"
            params.append(pid)
        if create_time is not None:
            query += " AND create_time = ?"
            params.append(create_time)
        query += " ORDER BY memory_rss DESC LIMIT 64"
        processes = []
        for row in connection.execute(query, params).fetchall():
            item = dict(row)
            item.pop("rank", None)
            item["connections"] = json.loads(item["connections"]) if item.get("connections") else None
            processes.append(item)
        process_history = []
        if pid is not None and create_time is not None:
            process_history = [dict(row) for row in connection.execute(
                """SELECT sampled_at,pid,create_time,name,cpu_percent,memory_rss,memory_percent,thread_count,open_fds
                FROM process_resource_samples WHERE sampled_at >= ? AND sampled_at <= ? AND pid = ? AND create_time = ?
                ORDER BY sampled_at""",
                (start, end, pid, create_time),
            ).fetchall()]
        return {"samples": samples, "processes": processes, "process_history": process_history}
    finally:
        connection.close()


def latest_resource_sample() -> dict | None:
    connection = core.db()
    try:
        row = connection.execute("SELECT * FROM resource_samples ORDER BY sampled_at DESC LIMIT 1").fetchone()
        return dict(row) if row else None
    finally:
        connection.close()


def reset_sampler_state_for_tests() -> None:
    global _last_system, _last_system_monotonic, _system_cpu_primed
    _last_system = None
    _last_system_monotonic = None
    _system_cpu_primed = False
    _process_cpu_seen.clear()
