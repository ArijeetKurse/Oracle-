from datetime import datetime, timedelta, timezone

from oracle import core
from oracle.core import Event, detect, simulate_event, get_event, create_investigation, get_investigation

def test_detection_explainable():
    e=detect(Event(pid=12,name='x',executable='/tmp/x'))
    assert e.risk_score==45 and e.severity=='medium' and 'temporary' in e.reason

def test_simulation_persists_and_investigates():
    e=simulate_event(); assert e.simulated and get_event(e.id)
    i=create_investigation(e.id); assert i.status in ('NEEDS_REVIEW','COMPLETED')
    assert i.evidence and get_investigation(i.id)

def test_clean_event():
    e=detect(Event(pid=5,name='bash',executable='/usr/bin/bash'))
    assert e.risk_score==0 and e.severity=='info'

def test_database_retention_applies_count_caps(monkeypatch):
    monkeypatch.setattr(core, 'MAX_EVENTS', 100)
    monkeypatch.setattr(core, 'MAX_INVESTIGATIONS', 50)
    connection=core.db()
    now=datetime.now(timezone.utc)
    connection.executemany('INSERT INTO events VALUES (?,?,?,?)', [(f'e{i}',(now-timedelta(seconds=i)).isoformat(),i,'{}') for i in range(105)])
    connection.executemany('INSERT INTO investigations (id,created_at,status,data) VALUES (?,?,?,?)', [(f'i{i}',(now-timedelta(seconds=i)).isoformat(),'COMPLETED','{}') for i in range(55)])
    connection.commit(); connection.close()
    core.prune_database()
    connection=core.db()
    assert connection.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 100
    assert connection.execute('SELECT COUNT(*) FROM investigations').fetchone()[0] == 50
    connection.close()
