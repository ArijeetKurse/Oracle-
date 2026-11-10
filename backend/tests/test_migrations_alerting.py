import sqlite3

from oracle import core


def test_existing_investigation_and_alert_tables_gain_link_and_voice_columns(tmp_path,monkeypatch):
    database=tmp_path/"old-oracle.db"
    monkeypatch.setattr(core,"DB_PATH",database)
    conn=sqlite3.connect(database)
    conn.execute("CREATE TABLE investigations(id TEXT PRIMARY KEY,created_at TEXT,status TEXT,data TEXT)")
    conn.execute("INSERT INTO investigations VALUES('old-investigation','2025-01-01','COMPLETED','{}')")
    conn.execute("""CREATE TABLE alerts(id TEXT PRIMARY KEY,created_at REAL NOT NULL,status TEXT NOT NULL,severity TEXT NOT NULL,
        detector_id TEXT NOT NULL,dedupe_key TEXT NOT NULL,pid INTEGER,process_create_time REAL,title TEXT NOT NULL,
        explanation TEXT NOT NULL,metric TEXT,observed_value REAL,expected_value REAL,deviation REAL,confidence REAL NOT NULL,
        evidence_json TEXT NOT NULL,investigation_id TEXT,notified_at REAL,spoken_at REAL,snoozed_until REAL,resolved_at REAL,audio_blob BLOB)""")
    conn.execute("""INSERT INTO alerts(id,created_at,status,severity,detector_id,dedupe_key,title,explanation,confidence,evidence_json)
        VALUES('old-alert',1,'new','medium','test','dedupe','Existing alert','Existing evidence',0.5,'{}')""")
    conn.commit();conn.close()

    migrated=core.db()
    investigation_columns={row["name"] for row in migrated.execute("PRAGMA table_info(investigations)")}
    alert_columns={row["name"] for row in migrated.execute("PRAGMA table_info(alerts)")}
    assert "event_id" in investigation_columns
    assert {"event_id","spoken_attempts","notification_attempts","notification_retry_at",
            "playback_attempts","delivery_retry_at","played_at","synthetic"} <= alert_columns
    assert migrated.execute("SELECT id FROM investigations WHERE id='old-investigation'").fetchone()
    assert migrated.execute("SELECT id FROM alerts WHERE id='old-alert'").fetchone()
    assert migrated.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='daemon_worker_status'").fetchone()
    migrated.close()
