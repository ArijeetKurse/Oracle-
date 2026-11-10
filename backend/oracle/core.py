from __future__ import annotations
import json, logging, os, queue, sqlite3, threading, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
import psutil
from pydantic import BaseModel, Field

logger=logging.getLogger(__name__)

_env_file = Path(__file__).resolve().parents[2] / '.env'
if _env_file.is_file():
    for _line in _env_file.read_text(encoding='utf-8').splitlines():
        _line = _line.strip()
        if not _line or _line.startswith('#') or '=' not in _line: continue
        _key, _value = _line.split('=', 1)
        _key, _value = _key.strip(), _value.strip().strip('"\'')
        if _key and _key.replace('_','').isalnum(): os.environ.setdefault(_key, _value)

DB_PATH = Path(os.getenv("ORACLE_DB", Path(__file__).resolve().parents[1] / "oracle.db")).expanduser()
POLL_INTERVAL = max(0.5, min(float(os.getenv('ORACLE_POLL_INTERVAL', '3')), 3600.0))
EVENT_RETENTION_DAYS = max(1, int(os.getenv('ORACLE_EVENT_RETENTION_DAYS', '30')))
MAX_EVENTS = max(100, int(os.getenv('ORACLE_MAX_EVENTS', '10000')))
MAX_INVESTIGATIONS = max(50, int(os.getenv('ORACLE_MAX_INVESTIGATIONS', '2000')))
MAX_SEEN_IDENTITIES = 50000
RESOURCE_SAMPLE_INTERVAL = max(1.0, float(os.getenv('ORACLE_RESOURCE_INTERVAL', '5')))
PROCESS_RESOURCE_SAMPLE_INTERVAL = max(RESOURCE_SAMPLE_INTERVAL, float(os.getenv('ORACLE_PROCESS_RESOURCE_INTERVAL', '15')))
RESOURCE_RETENTION_HOURS = max(1, int(os.getenv('ORACLE_RESOURCE_RETENTION_HOURS', '24')))
MAX_RESOURCE_PROCESSES = max(1, min(512, int(os.getenv('ORACLE_MAX_RESOURCE_PROCESSES', '64'))))

class Event(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    pid: int
    ppid: int | None = None
    name: str
    executable: str | None = None
    username: str | None = None
    connections: list[str] = []
    kind: str = "process_snapshot"
    simulated: bool = False
    rule: str | None = None
    severity: Literal['info','low','medium','high','critical'] = 'info'
    risk_score: int = 0
    reason: str | None = None

class Evidence(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    kind: str
    source: str
    detail: str
    polarity: Literal['supporting','contradicting','neutral'] = 'neutral'

class Hypothesis(BaseModel):
    title: str
    rationale: str
    confidence: float = Field(ge=0, le=1)
    status: Literal['open','supported','weakened','unresolved'] = 'open'

class Investigation(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_id: str
    pid: int
    status: Literal['NEW','ANALYZING','COLLECTING_EVIDENCE','EVALUATING','COMPLETED','NEEDS_REVIEW','FAILED'] = 'NEW'
    summary: str
    hypotheses: list[Hypothesis] = []
    evidence: list[Evidence] = []
    actions: list[str] = []
    conclusion: str | None = None
    confidence: float = 0.0
    unknowns: list[str] = []
    llm_assessment: dict | None = None


def db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn=sqlite3.connect(DB_PATH, timeout=15); conn.row_factory=sqlite3.Row
    try: DB_PATH.chmod(0o600)
    except OSError: pass
    conn.execute('PRAGMA busy_timeout=15000')
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('''CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, timestamp TEXT, pid INTEGER, data TEXT)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS investigations (id TEXT PRIMARY KEY, created_at TEXT, status TEXT, data TEXT)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS chat_messages (id TEXT PRIMARY KEY, investigation_id TEXT, created_at TEXT, role TEXT, content TEXT)''')
    # Additive resource-history schema; existing installations migrate on first open.
    conn.execute('''CREATE TABLE IF NOT EXISTS resource_samples (
        sampled_at REAL PRIMARY KEY, timestamp TEXT NOT NULL, interval_seconds REAL NOT NULL,
        cpu_percent REAL, memory_percent REAL, memory_total INTEGER, memory_used INTEGER, memory_available INTEGER,
        swap_percent REAL, swap_total INTEGER, swap_used INTEGER, disk_percent REAL,
        disk_read_bytes INTEGER, disk_write_bytes INTEGER, disk_read_bps REAL, disk_write_bps REAL,
        network_sent_bytes INTEGER, network_recv_bytes INTEGER, network_sent_bps REAL, network_recv_bps REAL,
        uptime_seconds REAL, process_count INTEGER NOT NULL DEFAULT 0
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS process_resource_samples (
        sampled_at REAL NOT NULL, pid INTEGER NOT NULL, create_time REAL NOT NULL,
        name TEXT NOT NULL, executable TEXT, cpu_percent REAL, memory_rss INTEGER,
        memory_percent REAL, thread_count INTEGER, open_fds INTEGER, connections TEXT,
        PRIMARY KEY (sampled_at, pid, create_time)
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS app_settings (
        key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY, created_at REAL NOT NULL, status TEXT NOT NULL, severity TEXT NOT NULL,
        detector_id TEXT NOT NULL, dedupe_key TEXT NOT NULL, pid INTEGER, process_create_time REAL,
        title TEXT NOT NULL, explanation TEXT NOT NULL, metric TEXT, observed_value REAL,
        expected_value REAL, deviation REAL, confidence REAL NOT NULL, evidence_json TEXT NOT NULL,
        investigation_id TEXT, notified_at REAL, spoken_at REAL, snoozed_until REAL, resolved_at REAL,
        audio_blob BLOB
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_investigations_created ON investigations(created_at)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_chat_investigation ON chat_messages(investigation_id, created_at)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_resource_timestamp ON resource_samples(sampled_at)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_process_resource_identity ON process_resource_samples(pid, create_time, sampled_at)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_process_resource_time ON process_resource_samples(sampled_at)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_alert_status_created ON alerts(status,created_at)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_alert_dedupe_created ON alerts(dedupe_key,created_at)')
    conn.commit(); return conn

def persist_event(e: Event):
    c=db(); c.execute('INSERT OR REPLACE INTO events VALUES (?,?,?,?)',(e.id,e.timestamp,e.pid,e.model_dump_json())); c.commit(); c.close()
def persist_investigation(i: Investigation):
    i.updated_at=datetime.now(timezone.utc).isoformat(); c=db(); c.execute('INSERT OR REPLACE INTO investigations VALUES (?,?,?,?)',(i.id,i.created_at,i.status,i.model_dump_json())); c.commit(); c.close()
def get_event(id):
    c=db(); row=c.execute('SELECT data FROM events WHERE id=?',(id,)).fetchone(); c.close(); return Event.model_validate_json(row['data']) if row else None
def list_events(limit=100):
    c=db(); rows=c.execute('SELECT data FROM events ORDER BY timestamp DESC LIMIT ?',(limit,)).fetchall(); c.close(); return [Event.model_validate_json(r['data']) for r in rows]
def get_investigation(id):
    c=db(); row=c.execute('SELECT data FROM investigations WHERE id=?',(id,)).fetchone(); c.close(); return Investigation.model_validate_json(row['data']) if row else None
def list_investigations(limit=100):
    c=db(); rows=c.execute('SELECT data FROM investigations ORDER BY created_at DESC LIMIT ?',(limit,)).fetchall(); c.close(); return [Investigation.model_validate_json(r['data']) for r in rows]

def prune_database():
    """Apply age and hard-count retention to keep local storage bounded."""
    cutoff = datetime.now(timezone.utc).timestamp() - EVENT_RETENTION_DAYS * 86400
    cutoff_iso = datetime.fromtimestamp(cutoff, timezone.utc).isoformat()
    from .settings import get_settings
    resource_cutoff = datetime.now(timezone.utc).timestamp() - get_settings()["resource_retention_hours"] * 3600
    c = db()
    c.execute('DELETE FROM events WHERE timestamp < ?', (cutoff_iso,))
    c.execute('DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY timestamp DESC LIMIT ?)', (MAX_EVENTS,))
    c.execute('DELETE FROM investigations WHERE id NOT IN (SELECT id FROM investigations ORDER BY created_at DESC LIMIT ?)', (MAX_INVESTIGATIONS,))
    c.execute('DELETE FROM chat_messages WHERE investigation_id NOT IN (SELECT id FROM investigations)')
    c.execute('DELETE FROM chat_messages WHERE id NOT IN (SELECT id FROM chat_messages ORDER BY created_at DESC LIMIT 20000)')
    c.execute('DELETE FROM process_resource_samples WHERE sampled_at < ?', (resource_cutoff,))
    c.execute('DELETE FROM resource_samples WHERE sampled_at < ?', (resource_cutoff,))
    c.commit(); c.close()

def list_chat_messages(investigation_id: str, limit: int = 20):
    c = db(); rows = c.execute('SELECT role,content,created_at FROM chat_messages WHERE investigation_id=? ORDER BY created_at DESC LIMIT ?', (investigation_id, min(max(limit, 1), 40))).fetchall(); c.close()
    return [dict(row) for row in reversed(rows)]

def persist_chat_message(investigation_id: str, role: str, content: str):
    c = db(); c.execute('INSERT INTO chat_messages VALUES (?,?,?,?,?)', (str(uuid.uuid4()), investigation_id, datetime.now(timezone.utc).isoformat(), role, content[:4000])); c.commit(); c.close()
    c = db(); c.execute('DELETE FROM chat_messages WHERE investigation_id=? AND id NOT IN (SELECT id FROM chat_messages WHERE investigation_id=? ORDER BY created_at DESC LIMIT 16)', (investigation_id, investigation_id)); c.commit(); c.close()


def inspect_process(pid:int) -> dict:
    p=psutil.Process(pid)
    with p.oneshot():
        try: exe=p.exe()
        except (psutil.AccessDenied, psutil.NoSuchProcess): exe=None
        try: conns=p.net_connections(kind='inet')
        except (psutil.AccessDenied, psutil.NoSuchProcess): conns=[]
        try: parent=p.ppid()
        except psutil.NoSuchProcess: parent=None
        try: name=p.name()
        except psutil.NoSuchProcess: name='exited'
        endpoints=[]
        for c in conns:
            if c.raddr: endpoints.append(f'{c.raddr.ip}:{c.raddr.port}')
        return {'pid':pid,'ppid':parent,'name':name,'executable':exe,'connections':sorted(set(endpoints))[:30]}

def detect(e: Event) -> Event:
    path=(e.executable or '').lower(); score=0; reasons=[]; rule=[]
    if any(x in path for x in ('/tmp/','/var/tmp/','/dev/shm/')):
        score+=45; reasons.append('Executable is located in a temporary writable directory'); rule.append('TEMP_EXECUTABLE')
    if path.startswith('/home/') or path.startswith('/run/user/'):
        score+=18; reasons.append('Executable is outside common system binary directories'); rule.append('USERSPACE_EXECUTABLE')
    if e.connections and (path.startswith('/tmp/') or path.startswith('/var/tmp/') or path.startswith('/dev/shm/')):
        score+=30; reasons.append('Temporary-location executable has active network connections'); rule.append('TEMP_NETWORK')
    e.risk_score=min(score,100); e.reason='; '.join(reasons) if reasons else 'No configured suspicious behavior rule matched.'
    e.rule=','.join(rule) if rule else None
    e.severity='critical' if score>=80 else 'high' if score>=60 else 'medium' if score>=35 else 'low' if score else 'info'
    return e

_review_queue: queue.Queue[str] = queue.Queue(maxsize=8)
_review_worker_started = False
_review_worker_lock = threading.Lock()

def queue_investigation_review(investigation_id: str) -> bool:
    """Queue at most eight automatic reviews so the collector never waits on Groq."""
    global _review_worker_started
    from .llm import provider_settings
    if not provider_settings()['configured']:
        return False
    try: _review_queue.put_nowait(investigation_id)
    except queue.Full: return False
    with _review_worker_lock:
        if not _review_worker_started:
            threading.Thread(target=_review_loop, daemon=True, name='oracle-ai-review').start()
            _review_worker_started = True
    return True

def _review_loop():
    while True:
        investigation_id = _review_queue.get()
        try:
            investigation = get_investigation(investigation_id)
            event = get_event(investigation.event_id) if investigation else None
            if investigation and event:
                from .llm import review_investigation
                investigation.llm_assessment = review_investigation(event.model_dump(), investigation.model_dump())
                persist_investigation(investigation)
        except Exception:
            logger.exception('Automatic investigation review failed')
        finally:
            _review_queue.task_done()

class Collector:
    def __init__(self): self.seen={}; self.running=False; self.thread=None; self._lock=threading.Lock(); self._baseline=True; self._last_prune=0.0; self._last_resource_sample=0.0; self._last_process_resource_sample=0.0
    def snapshot(self):
        fresh=[]; alive=set(); resource_processes=[]
        for p in psutil.process_iter(['pid','ppid','name','exe','username']):
            try:
                d=p.info; exe=d.get('exe'); created=p.create_time(); identity=(d['pid'],created); alive.add(identity)
                resource_processes.append(p)
                if identity in self.seen: continue
                self.seen[identity]=time.time()
                # The first pass is a baseline, not a claim that existing processes just started.
                if self._baseline: continue
                try: conns=sorted({f'{c.raddr.ip}:{c.raddr.port}' for c in p.net_connections(kind='inet') if c.raddr})[:30]
                except (psutil.AccessDenied, psutil.NoSuchProcess): conns=[]
                e=detect(Event(pid=d['pid'],ppid=d.get('ppid'),name=d.get('name') or 'unknown',executable=exe,username=d.get('username'),connections=conns))
                persist_event(e); fresh.append(e)
                if e.risk_score>=35:
                    investigation=create_investigation(e.id, ai_review=False)
                    queue_investigation_review(investigation.id)
            except (psutil.NoSuchProcess, psutil.AccessDenied, ProcessLookupError): continue
        self._baseline=False
        self.seen={identity:timestamp for identity,timestamp in self.seen.items() if identity in alive}
        if len(self.seen)>MAX_SEEN_IDENTITIES:
            self.seen=dict(sorted(self.seen.items(),key=lambda pair:pair[1],reverse=True)[:MAX_SEEN_IDENTITIES])
        if time.time()-self._last_prune>3600:
            prune_database(); self._last_prune=time.time()
        monotonic=time.monotonic()
        from .settings import get_settings
        resource_settings=get_settings()
        if monotonic-self._last_resource_sample>=resource_settings["resource_interval"]:
            include_processes=monotonic-self._last_process_resource_sample>=resource_settings["process_resource_interval"]
            from .resources import collect_resource_sample
            collect_resource_sample(resource_processes,include_processes=include_processes)
            self._last_resource_sample=monotonic
            if include_processes: self._last_process_resource_sample=monotonic
        return fresh
    def start(self):
        with self._lock:
            if self.running:return
            self.running=True
            if self.thread and self.thread.is_alive(): return
        def loop():
            while self.running:
                try:self.snapshot()
                except Exception: logger.exception('Monitoring snapshot failed')
                deadline=time.monotonic()+POLL_INTERVAL
                while self.running and time.monotonic()<deadline: time.sleep(min(.2, deadline-time.monotonic()))
        self.thread=threading.Thread(target=loop,daemon=True,name='oracle-collector'); self.thread.start()
    def stop(self):
        with self._lock: self.running=False; thread=self.thread
        if thread and thread is not threading.current_thread(): thread.join(timeout=max(2, POLL_INTERVAL+1))
collector=Collector()


def create_investigation(event_id:str, *, ai_review:bool=True) -> Investigation:
    event=get_event(event_id)
    if not event: raise ValueError('event_not_found')
    i=Investigation(event_id=event.id,pid=event.pid,status='ANALYZING',summary=f"Investigating {event.name} (PID {event.pid}) after rule {event.rule or 'manual request'}.")
    i.hypotheses=[Hypothesis(title='Potentially unwanted or unauthorized execution',rationale='The executable path or associated behavior matched an explainable heuristic.',confidence=.42),Hypothesis(title='Legitimate software with unusual placement or behavior',rationale='Administrative tools, portable applications, and development workflows can trigger the same indicators.',confidence=.38),Hypothesis(title='Insufficient evidence to distinguish intent',rationale='A heuristic alone cannot establish malicious intent.',confidence=.20)]
    i.status='COLLECTING_EVIDENCE'; i.actions.append('get_process_details')
    try:
        if event.simulated:
            i.evidence.append(Evidence(kind='simulated_process_details',source='safe demo generator',detail=json.dumps({'pid':event.pid,'process_name':event.name,'executable':event.executable,'network_endpoints':event.connections,'notice':'Synthetic event data only; no process was launched and no endpoint was contacted.'},sort_keys=True),polarity='supporting'))
            i.actions.extend(['get_process_details (simulation fixture)','get_process_connections (simulation fixture)'])
            i.unknowns.append('This investigation uses synthetic demo evidence; it does not describe the current process at this PID.')
            positives=1
            i.status='EVALUATING'
            i.conclusion='The simulated event matched a temporary-path plus network indicator. This validates the workflow only; it is not a finding about a real process.'
            i.confidence=1.0
            i.hypotheses[0].status='supported'
            i.hypotheses[1].status='open'
            i.hypotheses[2].status='weakened'
            i.status='COMPLETED'
            persist_investigation(i)
            return i
        d=inspect_process(i.pid)
        i.evidence.append(Evidence(kind='process_details',source='psutil',detail=json.dumps(d,sort_keys=True),polarity='supporting' if event.risk_score>=35 else 'neutral'))
        i.actions.append('get_process_connections')
        i.evidence.append(Evidence(kind='network_connections',source='psutil',detail=json.dumps(d['connections']),polarity='supporting' if d['connections'] and event.rule and 'TEMP' in event.rule else 'neutral'))
        i.actions.append('get_parent_process')
        try:
            parent=inspect_process(d['ppid']) if d['ppid'] else None
            i.evidence.append(Evidence(kind='parent_process',source='psutil',detail=json.dumps(parent),polarity='neutral'))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            i.unknowns.append('Parent process details unavailable due to process exit or permissions.')
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        i.unknowns.append('Process details unavailable because the process exited or permissions restrict access.')
    i.status='EVALUATING'
    positives=sum(1 for e in i.evidence if e.polarity=='supporting')
    if event.risk_score>=60 and positives:
        i.conclusion='Suspicious behavior observed; available evidence supports further human review. This is not proof of malware.'; i.confidence=.67; i.status='NEEDS_REVIEW'
    elif event.risk_score>=35:
        i.conclusion='A heuristic indicator was observed, but available evidence is insufficient to determine intent.'; i.confidence=.48; i.status='NEEDS_REVIEW'
    else:
        i.conclusion='No suspicious behavior was established from collected evidence.'; i.confidence=.35; i.status='COMPLETED'
    i.hypotheses[0].status='supported' if positives else 'unresolved'; i.hypotheses[1].status='open'; i.hypotheses[2].status='supported' if not positives else 'weakened'
    if ai_review:
        from .llm import review_investigation
        i.llm_assessment = review_investigation(event.model_dump(), i.model_dump())
    persist_investigation(i); return i

def simulate_event():
    e=detect(Event(pid=os.getpid(),ppid=os.getppid(),name='oracle-demo-simulation',executable='/tmp/oracle-demo-simulation',username=os.getenv('USER'),connections=['198.51.100.10:443'],kind='simulated_demo',simulated=True))
    persist_event(e); return e
