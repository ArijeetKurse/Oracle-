"""SQLite-backed Timbre single-flight and Retry-After coordination."""
from __future__ import annotations

import sqlite3
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from .core import db


def parse_retry_after(value: str | None, *, now: float | None = None) -> float:
    if not value: return 0.0
    current = time.time() if now is None else now
    try: return max(0.0, min(86400.0, float(value.strip())))
    except (TypeError, ValueError):
        try:
            parsed = parsedate_to_datetime(value)
            if parsed.tzinfo is None: parsed = parsed.replace(tzinfo=timezone.utc)
            return max(0.0, min(86400.0, parsed.timestamp() - current))
        except (TypeError, ValueError, OverflowError):
            return 0.0


def claim_tts_slot(*, now: float | None = None, lease_seconds: float = 90.0) -> bool:
    current = time.time() if now is None else now
    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT OR IGNORE INTO provider_state(provider,lock_until,next_allowed_at,updated_at) VALUES('gnani_tts',0,0,?)", (current,))
        result = conn.execute("UPDATE provider_state SET lock_until=?,updated_at=? WHERE provider='gnani_tts' AND lock_until<=? AND next_allowed_at<=?",
                              (current + lease_seconds, current, current, current))
        conn.commit()
        return result.rowcount == 1
    except sqlite3.Error:
        conn.rollback()
        raise
    finally: conn.close()


def release_tts_slot(*, retry_after: str | None = None, now: float | None = None) -> None:
    current = time.time() if now is None else now
    delay = parse_retry_after(retry_after, now=current)
    conn = db()
    try:
        conn.execute("UPDATE provider_state SET lock_until=0,next_allowed_at=?,updated_at=? WHERE provider='gnani_tts'",
                     (current + delay, current))
        conn.commit()
    finally: conn.close()


def tts_ready_at() -> float:
    conn = db()
    try:
        row = conn.execute("SELECT MAX(next_allowed_at,lock_until) FROM provider_state WHERE provider='gnani_tts'").fetchone()
        return float(row[0] or 0) if row else 0.0
    finally: conn.close()
