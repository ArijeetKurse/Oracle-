import { FormEvent, useCallback, useEffect, useRef, useState } from 'react';
import { Activity, AlertTriangle, AudioLines, Bell, ChevronDown, ChevronRight, CircleHelp, Clock3, Command, FileSearch, Gauge, Mic, Moon, Network, Play, Radio, RefreshCw, Search, Shield, ShieldCheck, Sun, Volume2, X, MessageCircle, Send, Sparkles } from 'lucide-react';
import { createSingleFlight, retryAfterMilliseconds } from './tts-single-flight.js';
import './resources.css';
import './alerts.css';

type Event = { id: string; timestamp: string; pid: number; ppid: number | null; name: string; executable: string | null; connections: string[]; risk_score: number; severity: string; reason: string | null; simulated: boolean; kind: string; rule?: string };
type Inv = { id: string; status: string; summary: string; pid: number; created_at: string; conclusion: string | null; confidence: number; hypotheses: any[]; evidence: any[]; actions: string[]; unknowns: string[]; event_id: string; llm_assessment?: any };
type ResourceSample = { sampled_at: number; timestamp: string; cpu_percent: number | null; memory_percent: number; memory_used: number; memory_total: number; network_recv_bps: number | null; network_sent_bps: number | null; disk_percent: number | null; uptime_seconds: number };
type ResourceProcess = { pid: number; create_time: number; name: string; executable: string | null; cpu_percent: number | null; memory_rss: number; memory_percent: number; thread_count: number | null; open_fds: number | null; connections: string[] | null };
type ResourceResponse = { window: string; monitoring: boolean; sampling_interval_seconds: number; process_sampling_interval_seconds: number; samples: ResourceSample[]; processes: ResourceProcess[]; process_history: { sampled_at: number; cpu_percent: number | null; memory_rss: number; memory_percent: number }[]; events: Event[] };
type Health = { status?: string; monitoring?: boolean; resources?: Pick<ResourceSample, 'timestamp'|'cpu_percent'|'memory_percent'|'memory_used'|'memory_total'|'network_recv_bps'|'network_sent_bps'> | null; gnani?: { configured?: boolean }; reasoning?: { configured?: boolean; model?: string; provider?: string } };
type Theme = 'light' | 'dark' | 'system';
type Alert = { id:string; created_at:number; status:string; severity:string; detector_id:string; pid:number; title:string; explanation:string; evidence:Record<string, unknown> };
const fmt = (s: string) => new Date(s).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
const short = (id: string) => id.slice(0, 8).toUpperCase();
const activeStatuses = ['NEW', 'ANALYZING', 'COLLECTING_EVIDENCE', 'EVALUATING'];

function encodeWav(chunks: Float32Array[], sampleRate: number) {
  const source = new Float32Array(chunks.reduce((n, c) => n + c.length, 0)); let offset = 0;
  for (const c of chunks) { source.set(c, offset); offset += c.length; }
  const targetRate = 16000, ratio = sampleRate / targetRate, length = Math.floor(source.length / ratio), buffer = new ArrayBuffer(44 + length * 2), view = new DataView(buffer);
  const str = (at: number, s: string) => { for (let n = 0; n < s.length; n++) view.setUint8(at + n, s.charCodeAt(n)); };
  str(0, 'RIFF'); view.setUint32(4, 36 + length * 2, true); str(8, 'WAVE'); str(12, 'fmt '); view.setUint32(16, 16, true); view.setUint16(20, 1, true); view.setUint16(22, 1, true); view.setUint32(24, targetRate, true); view.setUint32(28, targetRate * 2, true); view.setUint16(32, 2, true); view.setUint16(34, 16, true); str(36, 'data'); view.setUint32(40, length * 2, true);
  for (let i = 0; i < length; i++) { const begin = Math.floor(i * ratio), end = Math.min(Math.floor((i + 1) * ratio), source.length); let sum = 0; for (let j = begin; j < end; j++) sum += source[j]; const sample = Math.max(-1, Math.min(1, sum / Math.max(1, end - begin))); view.setInt16(44 + i * 2, sample < 0 ? sample * 32768 : sample * 32767, true); }
  return new Blob([buffer], { type: 'audio/wav' });
}

export default function App() {
  const [events, setEvents] = useState<Event[]>([]), [invs, setInvs] = useState<Inv[]>([]), [health, setHealth] = useState<Health | null>(null);
  const [selected, setSelected] = useState<string | null>(null), [tab, setTab] = useState('Overview'), [command, setCommand] = useState(''), [busy, setBusy] = useState(false), [msg, setMsg] = useState(''), [query, setQuery] = useState(''), [rec, setRec] = useState(false), [audioSrc, setAudioSrc] = useState(''), [speechLoading, setSpeechLoading] = useState(false), [speechRetryUntil, setSpeechRetryUntil] = useState(0), [speechClock, setSpeechClock] = useState(Date.now());
  const audioRef = useRef<HTMLAudioElement>(null), speechGate = useRef(createSingleFlight());
  const [theme, setTheme] = useState<Theme>(() => { const saved = localStorage.getItem('oracle-theme'); return saved === 'light' || saved === 'dark' || saved === 'system' ? saved : 'system'; }), [llmTest, setLlmTest] = useState('');
  useEffect(() => {
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const apply = () => { const activeTheme = theme === 'system' ? (media.matches ? 'dark' : 'light') : theme; document.documentElement.dataset.theme = activeTheme; document.querySelector('meta[name="theme-color"]')?.setAttribute('content', activeTheme === 'dark' ? '#0c1216' : '#f5f7f8'); };
    apply(); media.addEventListener('change', apply); localStorage.setItem('oracle-theme', theme);
    return () => media.removeEventListener('change', apply);
  }, [theme]);
  const load = useCallback(async () => {
    try {
      const [e, i, h] = await Promise.all([fetch('/api/events').then(r => r.json()), fetch('/api/investigations').then(r => r.json()), fetch('/api/health').then(r => r.json())]);
      setEvents(e); setInvs(i); setHealth(h); setSelected(current => current && !i.some((v: Inv) => v.id === current) ? null : current);
    } catch { setHealth({ status: 'offline' }); }
  }, []);
  useEffect(() => { void load(); const t = setInterval(() => void load(), 4000); return () => clearInterval(t); }, [load]);
  useEffect(() => {
    if (tab !== 'Voice & Settings') {
      setAudioSrc('');
    }
  }, [tab]);
  useEffect(() => {
    if (!speechRetryUntil || speechRetryUntil <= speechClock) return;
    const timer = window.setInterval(() => setSpeechClock(Date.now()), 250);
    return () => window.clearInterval(timer);
  }, [speechRetryUntil, speechClock]);
  useEffect(() => {
    if (!audioSrc) return;
    const player = audioRef.current;
    let active = true;
    if (player) {
      try {
        void player.play().catch(() => {
          if (active) setMsg('Audio is ready, but playback was blocked. Press Play to listen.');
        });
      } catch { setMsg('Audio is ready, but playback was blocked. Press Play to listen.'); }
    }
    return () => {
      active = false;
      player?.pause();
      URL.revokeObjectURL(audioSrc);
    };
  }, [audioSrc]);
  const inv = invs.find(x => x.id === selected), suspicious = events.filter(e => e.risk_score >= 35), active = invs.filter(x => activeStatuses.includes(x.status));
  async function run(cmd = command) {
    if (!cmd.trim()) return; setBusy(true); setMsg('');
    try { const r = await fetch('/api/investigations', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ command: cmd }) }), d = await r.json(); if (!r.ok) throw Error(d.detail || 'Request failed'); setCommand(''); setSelected(d.id); setTab('Investigations'); await load(); }
    catch (e: any) { setMsg(e.message); } finally { setBusy(false); }
  }
  async function toggleMonitoring() {
    try { const r = await fetch('/api/monitoring', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled: !health?.monitoring }) }); if (!r.ok) throw Error((await r.json()).detail); await load(); }
    catch (e: any) { setMsg(e.message); }
  }
  async function demo() {
    setBusy(true); setMsg(''); try { const r = await fetch('/api/demo', { method: 'POST' }), d = await r.json(); if (!r.ok) throw Error(d.detail || 'Demo could not be started'); setSelected(d.investigation.id); setTab('Investigations'); setMsg(d.notice); await load(); }
    catch (e: any) { setMsg(e.message); } finally { setBusy(false); }
  }
  async function voice() {
    if (!navigator.mediaDevices?.getUserMedia) { setMsg('Microphone is unavailable in this browser.'); return; }
    let stream: MediaStream | undefined, context: AudioContext | undefined;
    try {
      stream = await navigator.mediaDevices.getUserMedia({ audio: true }); context = new AudioContext(); const source = context.createMediaStreamSource(stream), processor = context.createScriptProcessor(4096, 1, 1), chunks: Float32Array[] = [], silent = context.createGain();
      processor.onaudioprocess = e => chunks.push(new Float32Array(e.inputBuffer.getChannelData(0))); silent.gain.value = 0; source.connect(processor); processor.connect(silent); silent.connect(context.destination); setRec(true);
      window.setTimeout(async () => {
        try { processor.disconnect(); source.disconnect(); silent.disconnect(); stream?.getTracks().forEach(t => t.stop()); const rate = context?.sampleRate || 48000; await context?.close(); const form = new FormData(); form.append('audio', encodeWav(chunks, rate), 'command.wav'); setBusy(true); const r = await fetch('/api/voice/transcribe', { method: 'POST', body: form }), d = await r.json(); if (!r.ok) throw Error(d.detail); setCommand(d.transcript); setSelected(d.command_result.id); setTab('Investigations'); setMsg('Transcribed by Gnani Prisma v2.5'); await load(); }
        catch (e: any) { setMsg(e.message); } finally { setBusy(false); setRec(false); }
      }, 7000);
    } catch (e: any) { stream?.getTracks().forEach(t => t.stop()); await context?.close(); setMsg(e.message); }
  }
  async function speak() {
    return speechGate.current.run(async () => {
      if (!inv?.conclusion || speechRetryUntil > Date.now()) return;
      setSpeechLoading(true); setMsg('');
      try {
        const r = await fetch('/api/voice/speak', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ command: `${inv.summary}. ${inv.conclusion}` }) });
        if (!r.ok) {
          let detail = `Speech request failed (HTTP ${r.status}).`;
          try { const body = await r.json(); if (typeof body.detail === 'string') detail = body.detail; } catch { /* Keep the safe status fallback for non-JSON errors. */ }
          if (r.status === 429) {
            const delay = retryAfterMilliseconds(r.headers.get('Retry-After'));
            if (delay > 0) setSpeechRetryUntil(Date.now() + delay);
          }
          throw Error(detail);
        }
        const blob = await r.blob(), contentType = (r.headers.get('content-type') || blob.type).split(';', 1)[0].trim().toLowerCase();
        if (!blob.size || !contentType.startsWith('audio/')) throw Error('Gnani returned an empty or invalid audio response.');
        const playableBlob = blob.type === contentType ? blob : blob.slice(0, blob.size, contentType);
        setAudioSrc(URL.createObjectURL(playableBlob));
      }
      catch (e: unknown) { setMsg(e instanceof Error ? e.message : 'Could not prepare report audio.'); }
      finally { setSpeechLoading(false); }
    });
  }
  async function testLLM() {
    setLlmTest('Testing Groq connection…');
    try { const r = await fetch('/api/llm/test', { method: 'POST' }), d = await r.json(); if (!r.ok) throw Error(d.detail || 'Connection test failed.'); setLlmTest(`Connected · ${d.model}`); }
    catch (e: any) { setLlmTest(e.message); }
  }
  const nav = [{ name: 'Overview', icon: Activity }, { name: 'Live Activity', icon: Radio }, { name: 'Resources', icon: Gauge }, { name: 'Alerts', icon: Bell }, { name: 'Investigations', icon: FileSearch }, { name: 'Voice & Settings', icon: AudioLines }];
  const go = (name: string) => { setTab(name); setSelected(null); };
  return <div className="app-shell">
    <aside className="sidebar" aria-label="Main navigation">
      <a className="brand" href="#overview" onClick={e => { e.preventDefault(); go('Overview'); }}><span className="brand-mark">O</span><span><b>ORACLE</b><small>LOCAL SECURITY</small></span></a>
      <span className="nav-label">Workspace</span><nav>{nav.map(({ name, icon: Icon }) => <button key={name} className={`nav-item ${tab === name ? 'selected' : ''}`} onClick={() => go(name)} aria-current={tab === name ? 'page' : undefined}><Icon size={18}/><span>{name}</span>{name === 'Investigations' && active.length > 0 && <span className="nav-count">{active.length}</span>}</button>)}</nav>
      <div className="sidebar-bottom"><div className="local-state"><span className={`state-dot ${health?.status === 'running' ? 'ok' : 'down'}`}/><div><b>{health?.status === 'running' ? 'Agent connected' : 'Agent unavailable'}</b><small>{health?.monitoring ? 'Monitoring is on' : 'Monitoring is off'}</small></div></div><span className="version">ORACLE <span>v0.1.0</span></span></div>
    </aside>
    <main className="main-area">
      <header className="topbar"><div className="breadcrumb"><span>Workspace</span><ChevronRight size={14}/><b>{inv ? 'Investigation' : tab}</b></div><div className="top-actions"><span className={`system-status ${health?.status === 'running' ? 'online' : 'offline'}`}><i/>{health?.status === 'running' ? 'System online' : 'System offline'}</span><button className="icon-button" aria-label={`Theme: ${theme}. Change theme`} title={`Theme: ${theme}`} onClick={() => setTheme(theme === 'light' ? 'dark' : theme === 'dark' ? 'system' : 'light')}>{theme === 'dark' ? <Moon size={17}/> : <Sun size={17}/>}</button><button className="icon-button" aria-label="Refresh data" onClick={() => void load()}><RefreshCw size={17}/></button></div></header>
      <div className="page">
        <div className="page-heading"><div><h1>{inv ? 'Investigation' : tab}</h1><p>{inv ? 'Review the evidence and assessment for this process.' : tab === 'Overview' ? 'A clear view of what Oracle has observed on this device.' : tab === 'Live Activity' ? 'Process activity collected by the local monitor.' : tab === 'Investigations' ? 'Review evidence, or start an investigation by process ID.' : 'Voice commands and local integrations.'}</p></div><div className="heading-actions"><button className="button quiet" disabled={busy} onClick={() => void demo()}><Play size={16}/>{busy ? 'Working…' : 'Run safe demo'}</button><button className="button primary" onClick={() => { setTab('Investigations'); setSelected(null); document.getElementById('investigate-command')?.focus(); }}><FileSearch size={16}/>New investigation</button></div></div>
        {msg && <div className="notice" role="status"><span>{msg}</span><button aria-label="Dismiss message" onClick={() => setMsg('')}><X size={16}/></button></div>}
        {inv ? <InvestigationView inv={inv} events={events} onBack={() => setSelected(null)} onSpeak={() => void speak()} speechLoading={speechLoading} speechRetrySeconds={Math.max(0,Math.ceil((speechRetryUntil-speechClock)/1000))}/> : tab === 'Overview' ? <>
          <section className="system-summary" aria-label="System status"><div className="summary-main"><span className={`summary-icon ${health?.monitoring ? 'monitoring' : ''}`}>{health?.monitoring ? <ShieldCheck size={22}/> : <Shield size={22}/>}</span><div><strong>{health?.monitoring ? 'Monitoring is active' : 'Monitoring is paused'}</strong><p>{health?.monitoring ? 'Oracle is collecting local process snapshots.' : 'Start monitoring to collect process activity on this device.'}</p></div></div><button className={`button ${health?.monitoring ? 'quiet' : 'primary'}`} onClick={() => void toggleMonitoring()}>{health?.monitoring ? 'Pause monitoring' : 'Start monitoring'}</button><div className="summary-facts"><div><b>{events.length}</b><span>events observed</span></div><div><b>{suspicious.length}</b><span>signals to review</span></div><div><b>{active.length}</b><span>active investigations</span></div></div></section>
          <SystemResourceSummary resources={health?.resources || null} onOpen={() => go("Resources")}/>
          <section className="section-block"><div className="section-heading"><div><h2>Activity to review</h2><p>Rule matches are indicators for review, not confirmed threats.</p></div><button className="link-button" onClick={() => go('Live Activity')}>All activity <ChevronRight size={16}/></button></div><EventList events={suspicious.slice(0, 5)} onInvestigate={pid => void run(`Investigate PID ${pid}`)} empty="No rule matches in the observed events."/></section>
          <section className="section-block"><div className="section-heading"><div><h2>Recent investigations</h2><p>Evidence collected by your local agent.</p></div><button className="link-button" onClick={() => go('Investigations')}>All investigations <ChevronRight size={16}/></button></div><InvestigationList rows={invs.slice(0, 4)} onSelect={setSelected}/></section>
          <div className="plain-note"><CircleHelp size={17}/><p><b>How to read this page</b> Oracle flags activity with explainable rules. A signal asks for review; it does not mean a process is malicious.</p></div>
        </> : tab === 'Live Activity' ? <section className="section-block"><div className="section-heading"><div><h2>Observed processes</h2><p>Unprivileged psutil snapshots. Only activity recorded by the monitor appears here.</p></div><label className="search-field"><Search size={16}/><span className="sr-only">Filter processes</span><input value={query} onChange={e => setQuery(e.target.value)} placeholder="Filter by process or path"/></label></div><EventList events={events.filter(e => `${e.name} ${e.executable || ''} ${e.pid}`.toLowerCase().includes(query.toLowerCase()))} onInvestigate={pid => void run(`Investigate PID ${pid}`)} empty="No matching activity. Try another process name or path." showAll/></section> : tab === 'Resources' ? <ResourceTimeline/> : tab === 'Alerts' ? <AlertInbox/> : tab === 'Investigations' ? <>
          <section className="start-investigation"><div className="start-icon"><Command size={19}/></div><div className="start-content"><h2>Investigate a process</h2><p>Enter a PID or describe what you want Oracle to check.</p><div className="command-field"><label className="sr-only" htmlFor="investigate-command">Process ID or investigation request</label><input id="investigate-command" value={command} onChange={e => setCommand(e.target.value)} onKeyDown={e => e.key === 'Enter' && void run()} placeholder="For example: Investigate PID 4128"/><button className="button primary" disabled={busy || !command.trim()} onClick={() => void run()}>{busy ? 'Investigating…' : 'Investigate'}<ChevronRight size={16}/></button></div></div></section>
          <section className="section-block"><div className="section-heading"><div><h2>Investigation history</h2><p>{invs.length} saved {invs.length === 1 ? 'investigation' : 'investigations'}</p></div></div><InvestigationList rows={invs} onSelect={setSelected}/></section>
        </> : <section className="settings-layout"><div className="section-block voice-section"><div className="section-heading"><div><h2>Voice commands</h2><p>Record up to seven seconds. Audio is sent to Gnani Prisma v2.5 after you start recording.</p></div></div><button className={`record-button ${rec ? 'recording' : ''}`} onClick={() => void voice()} aria-label={rec ? 'Recording command' : 'Record voice command'}><Mic size={23}/></button><b>{rec ? 'Listening…' : 'Record a command'}</b><span>Example: “Oracle, investigate process 1234.”</span>{command && <div className="transcript"><small>Transcription</small><p>{command}</p></div>}</div><div className="section-block integrations"><div className="section-heading"><div><h2>Connections & collection</h2><p>Current backend configuration.</p></div></div><div className="theme-setting"><label htmlFor="theme-choice">Appearance</label><select id="theme-choice" value={theme} onChange={e => setTheme(e.target.value as Theme)}><option value="system">Use system setting</option><option value="light">Light</option><option value="dark">Dark</option></select></div><StatusRow label="Groq reasoning" status={health?.reasoning?.configured ? 'Connected' : 'Needs API key'} detail={`${health?.reasoning?.model || 'Configurable model'} · LLM analysis is separate from local rules.`}/><div className="llm-test-row"><button className="button quiet" onClick={() => void testLLM()}>Test Groq connection</button><span role="status">{llmTest}</span></div><StatusRow label="Gnani Prisma speech recognition" status={health?.gnani?.configured ? 'Configured' : 'Needs API key'} detail="Prisma v2.5 · speech to text"/><StatusRow label="Gnani Timbre speech output" status={health?.gnani?.configured ? 'Configured' : 'Needs API key'} detail="Timbre v2.5 · text to speech"/><StatusRow label="Process monitoring" status={health?.monitoring ? 'Active' : 'Paused'} detail="psutil snapshots · unprivileged · local rules continue without API keys."/><details className="technical-disclosure"><summary>Setup details <ChevronDown size={15}/></summary><p>Set <code>GROQ_API_KEY</code> and, optionally, <code>GROQ_MODEL</code> in the project root <code>.env</code>. Restart ORACLE to load changes. Set <code>GNANI_API_KEY</code> to enable speech.</p></details><div className="speech-actions"><button className="button quiet" onClick={() => void speak()} disabled={!inv || speechLoading}><Volume2 size={16}/>{speechLoading ? 'Preparing audio…' : 'Read selected report aloud'}</button>{audioSrc && <audio ref={audioRef} controls src={audioSrc} aria-label="Investigation report audio" onError={() => setMsg('Audio could not be played. Try generating it again.')}/>}</div></div></section>}
        {inv && audioSrc && <div className="speech-actions"><audio ref={audioRef} controls src={audioSrc} aria-label="Investigation report audio" onError={() => setMsg('Audio response was received but could not be played. Try generating it again.')}/></div>}
        <footer><span>Oracle · Local security intelligence</span><span>Evidence stays on this device</span></footer>
      </div>
    </main>
    <nav className="mobile-nav" aria-label="Main navigation">{nav.map(({ name, icon: Icon }) => <button key={name} className={tab === name ? 'active' : ''} onClick={() => go(name)} aria-label={name}><Icon size={19}/><span>{name === 'Voice & Settings' ? 'Settings' : name.split(' ')[0]}</span></button>)}</nav>
  </div>;
}

function AlertInbox() {
  const [rows,setRows]=useState<Alert[]>([]),[status,setStatus]=useState(''),[severity,setSeverity]=useState(''),[error,setError]=useState('');
  const load=useCallback(async()=>{const params=new URLSearchParams();if(status)params.set('status',status);if(severity)params.set('severity',severity);try{const response=await fetch(`/api/alerts?${params}`);if(!response.ok)throw new Error('Alerts could not be loaded.');setRows(await response.json());setError('')}catch(cause){setError(cause instanceof Error?cause.message:'Alerts could not be loaded.')}},[status,severity]);
  useEffect(()=>{void load()},[load]);
  async function transition(id:string,next:string){const response=await fetch(`/api/alerts/${id}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:next})});if(!response.ok){setError('Alert status could not be updated.');return}await load()}
  return <section className="section-block"><div className="section-heading"><div><h2>Alert inbox</h2><p>Local baseline detectors. Alerts are evidence for review, not malware verdicts.</p></div><div className="theme-setting"><label>Status <select value={status} onChange={event=>setStatus(event.target.value)}><option value="">All</option><option value="new">New</option><option value="acknowledged">Acknowledged</option><option value="snoozed">Snoozed</option><option value="resolved">Resolved</option></select></label><label>Severity <select value={severity} onChange={event=>setSeverity(event.target.value)}><option value="">All</option>{['low','medium','high','critical'].map(value=><option key={value}>{value}</option>)}</select></label></div></div>{error&&<p role="alert">{error}</p>}{rows.length===0?<p className="resource-empty">No matching alerts. A detector needs enough historical observations before it can compare behavior.</p>:rows.map(alert=><article className="alert-row" key={alert.id}><div><span className={`alert-severity severity-${alert.severity}`}>{alert.severity}</span><h3>{alert.title}</h3><p>{alert.explanation}</p><small>PID {alert.pid} · {new Date(alert.created_at*1000).toLocaleString()} · {alert.detector_id}</small><details><summary>Evidence</summary><pre>{JSON.stringify(alert.evidence,null,2)}</pre></details></div><div className="alert-actions"><b>{alert.status}</b>{alert.status!=='acknowledged'&&<button className="button quiet" onClick={()=>void transition(alert.id,'acknowledged')}>Acknowledge</button>}{alert.status!=='snoozed'&&<button className="button quiet" onClick={()=>void transition(alert.id,'snoozed')}>Snooze 1 hour</button>}{alert.status!=='resolved'&&<button className="button quiet" onClick={()=>void transition(alert.id,'resolved')}>Resolve</button>}</div></article>)}</section>
}

function SystemResourceSummary({ resources, onOpen }: { resources: Health['resources']; onOpen: () => void }) {
  return <section className="resource-mini-summary"><div className="section-heading"><div><h2>Latest system sample</h2><p>{resources?.timestamp ? `Collected ${new Date(resources.timestamp).toLocaleTimeString()}` : 'Resource history begins when monitoring starts.'}</p></div><button className="link-button" onClick={onOpen}>Resource history <ChevronRight size={16}/></button></div>{resources ? <div className="resource-mini-grid"><MetricCard label="CPU" value={resources.cpu_percent == null ? 'Warming up' : `${resources.cpu_percent.toFixed(1)}%`}/><MetricCard label="RAM" value={`${resources.memory_percent.toFixed(1)}%`} detail={`${(resources.memory_used/1024**3).toFixed(1)} / ${(resources.memory_total/1024**3).toFixed(1)} GiB`}/><MetricCard label="Network received" value={formatRate(resources.network_recv_bps)}/><MetricCard label="Network sent" value={formatRate(resources.network_sent_bps)}/></div> : <p className="resource-empty">No resource samples have been collected yet.</p>}</section>;
}

function MetricCard({ label, value, detail }: { label: string; value: string; detail?: string }) {
  return <div className="resource-metric"><small>{label}</small><b>{value}</b>{detail && <span>{detail}</span>}</div>;
}

function ResourceTimeline() {
  const [windowSize, setWindowSize] = useState('15m'), [data, setData] = useState<ResourceResponse | null>(null), [selected, setSelected] = useState<{ pid: number; create_time: number } | null>(null), [error, setError] = useState(''), [loading, setLoading] = useState(true);
  useEffect(() => {
    let cancelled = false;
    setLoading(true); setError('');
    const params = new URLSearchParams({ window: windowSize });
    if (selected) { params.set('pid', String(selected.pid)); params.set('create_time', String(selected.create_time)); }
    fetch(`/api/resources?${params}`).then(async response => { const body = await response.json(); if (!response.ok) throw new Error(body.detail || 'Resource history could not be loaded.'); return body as ResourceResponse; }).then(body => { if (!cancelled) setData(body); }).catch((cause: unknown) => { if (!cancelled) setError(cause instanceof Error ? cause.message : 'Resource history could not be loaded.'); }).finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [windowSize, selected]);
  const samples = data?.samples || [];
  const receive = samples.map(sample => sample.network_recv_bps == null ? null : sample.network_recv_bps / 1024);
  const send = samples.map(sample => sample.network_sent_bps == null ? null : sample.network_sent_bps / 1024);
  const processSamples = data?.process_history || [];
  return <div className="resource-page">
    <section className="resource-panel"><div className="section-heading"><div><h2>Resource timeline</h2><p>Measurements collected locally by the ORACLE daemon. No historical data is fabricated.</p></div><label className="search-field resource-range"><span className="sr-only">Timeline range</span><select value={windowSize} onChange={event => setWindowSize(event.target.value)}><option value="5m">Last 5 minutes</option><option value="15m">Last 15 minutes</option><option value="1h">Last hour</option><option value="24h">Last 24 hours</option></select></label></div>
      <div className="resource-sampling-note">Monitor {data?.monitoring ? 'running' : 'paused'} · system sample every {data?.sampling_interval_seconds ?? 5}s · process sample every {data?.process_sampling_interval_seconds ?? 15}s</div>
      {error && <p className="resource-error" role="alert">{error}</p>}
      {!loading && !error && samples.length === 0 && <div className="resource-empty">No samples in this time range. Start monitoring and allow a few sampling intervals to collect history.</div>}
      {samples.length > 0 && <div className="resource-charts"><ResourceChart title="CPU utilization" unit="%" values={samples.map(sample => sample.cpu_percent)} fixedMax={100} format={value => `${value.toFixed(0)}%`}/><ResourceChart title="Memory utilization" unit="%" values={samples.map(sample => sample.memory_percent)} fixedMax={100} format={value => `${value.toFixed(0)}%`}/><ResourceChart title="Network throughput" unit="KiB/s" values={receive} secondaryValues={send} secondaryLabel="Sent" primaryLabel="Received" format={value => `${value.toFixed(1)} KiB/s`}/><ResourceChart title="Root filesystem utilization" unit="%" values={samples.map(sample => sample.disk_percent)} fixedMax={100} format={value => `${value.toFixed(0)}%`}/></div>}
    </section>
    <section className="resource-panel"><div className="section-heading"><div><h2>Process resource samples</h2><p>Latest recorded values for process identities (PID plus creation time).</p></div></div>{data?.processes.length ? <div className="resource-process-list">{data.processes.map(process => <button className={`resource-process ${selected?.pid === process.pid && selected.create_time === process.create_time ? 'selected' : ''}`} key={`${process.pid}-${process.create_time}`} onClick={() => setSelected({ pid: process.pid, create_time: process.create_time })}><span><b>{process.name}</b><small>PID {process.pid} · {process.executable || 'Executable unavailable'}</small></span><span>{process.cpu_percent == null ? 'CPU warming' : `${process.cpu_percent.toFixed(1)}% CPU`}<br/>{(process.memory_rss/1024**2).toFixed(1)} MiB RAM</span></button>)}</div> : <div className="resource-empty">Process metrics are not available yet. They are sampled less often than system metrics to limit overhead.</div>}{selected && processSamples.length > 0 && <ResourceChart title={`PID ${selected.pid} memory history`} unit="MiB" values={processSamples.map(sample => sample.memory_rss/1024**2)} format={value => `${value.toFixed(0)} MiB`}/>}</section>
    <section className="resource-panel"><div className="section-heading"><div><h2>Observed events in this window</h2><p>Process starts and investigation events already recorded by ORACLE.</p></div><span className="evidence-count">{data?.events.length || 0}</span></div>{data?.events.length ? <div className="resource-events">{data.events.map(event => <article key={event.id}><time>{new Date(event.timestamp).toLocaleTimeString()}</time><b>{event.name} · PID {event.pid}</b><span>{event.reason || event.kind}</span></article>)}</div> : <div className="resource-empty">No recorded events in this time range.</div>}</section>
  </div>;
}

function ResourceChart({ title, unit, values, secondaryValues, primaryLabel = 'Value', secondaryLabel = 'Value', fixedMax, format }: { title: string; unit: string; values: (number|null)[]; secondaryValues?: (number|null)[]; primaryLabel?: string; secondaryLabel?: string; fixedMax?: number; format: (value: number) => string }) {
  const all = [...values, ...(secondaryValues || [])].filter((value): value is number => value != null && Number.isFinite(value));
  if (!all.length) return <article className="resource-chart"><h3>{title}</h3><p className="resource-empty">Waiting for enough samples to calculate this metric.</p></article>;
  const max = fixedMax || Math.max(1, ...all) * 1.1, width = 760, height = 170, top = 12, bottom = 24;
  const points = (series: (number|null)[]) => series.map((value, index) => value == null ? null : `${(index/(Math.max(1,series.length-1))*width).toFixed(1)},${(top+(1-Math.min(max,Math.max(0,value))/max)*(height-top-bottom)).toFixed(1)}`).filter((point): point is string => point !== null).join(' ');
  const latest = all[all.length-1];
  return <article className="resource-chart"><div className="resource-chart-heading"><h3>{title}</h3><b>{format(latest)}</b></div><svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img" aria-label={`${title}, units ${unit}`}><line x1="0" y1={height-bottom} x2={width} y2={height-bottom} className="chart-axis"/><line x1="0" y1={top} x2={width} y2={top} className="chart-grid"/><polyline points={points(values)} className="chart-line primary-line"/>{secondaryValues && <polyline points={points(secondaryValues)} className="chart-line secondary-line"/>}</svg><div className="resource-chart-footer"><span>{format(0)}</span><span>{unit}</span><span>{format(max)}</span></div>{secondaryValues && <div className="resource-legend"><span>{primaryLabel}</span><span>{secondaryLabel}</span></div>}</article>;
}

function formatRate(value: number | null | undefined) { return value == null ? 'Warming up' : `${(value/1024).toFixed(1)} KiB/s`; }

function EventList({ events, onInvestigate, empty, showAll = false }: { events: Event[]; onInvestigate: (pid: number) => void; empty: string; showAll?: boolean }) {
  if (!events.length) return <div className="empty-state"><ShieldCheck size={22}/><span>{empty}</span></div>;
  return <div className="event-list">{events.map(e => <article className="event-row" key={e.id}><div className={`event-symbol ${e.severity}`}><AlertTriangle size={17}/></div><div className="event-copy"><div className="event-title"><b>{e.name}</b>{e.simulated && <span className="simulated-tag">Simulated demo</span>}<span className={`risk-tag ${e.severity}`}>{e.severity} signal</span></div><p>{e.reason || 'Process activity observed'} <span>· PID {e.pid}</span></p>{showAll && <small className="event-path" title={e.executable || undefined}>{e.executable || 'Executable unavailable'}{e.connections.length > 0 && <> · <Network size={12}/> {e.connections.length} network endpoint{e.connections.length > 1 ? 's' : ''}</>}</small>}</div><span className="event-time"><Clock3 size={14}/>{fmt(e.timestamp)}</span><button className="button quiet row-action" onClick={() => onInvestigate(e.pid)}>Investigate <ChevronRight size={15}/></button></article>)}</div>;
}
function InvestigationList({ rows, onSelect }: { rows: Inv[]; onSelect: (id: string) => void }) {
  if (!rows.length) return <div className="empty-state"><FileSearch size={21}/><span>No investigations yet. Start with a process ID above.</span></div>;
  return <div className="investigation-list">{rows.map(i => <button className="investigation-row" key={i.id} onClick={() => onSelect(i.id)}><span className="case-mark"><FileSearch size={17}/></span><span className="case-copy"><b>{i.summary}</b><small>PID {i.pid} · {fmt(i.created_at)} · ORC-{short(i.id)}</small></span><span className="case-status">{i.status.replace(/_/g, ' ')}</span><ChevronRight size={17}/></button>)}</div>;
}
function StatusRow({ label, status, detail }: { label: string; status: string; detail: string }) { return <div className="status-row"><div><b>{label}</b><small>{detail}</small></div><span className={`connection-status ${status === 'Active' || status === 'Configured' || status === 'Connected' ? 'connected' : ''}`}>{status}</span></div>; }
function InvestigationView({ inv, events, onBack, onSpeak, speechLoading, speechRetrySeconds }: { inv: Inv; events: Event[]; onBack: () => void; onSpeak: () => void; speechLoading: boolean; speechRetrySeconds: number }) {
  const [showTechnical, setShowTechnical] = useState(false), event = events.find(e => e.id === inv.event_id);
  return <><button className="back-link" onClick={onBack}>‹ All investigations</button><div className="investigation-header"><div><div className="case-id">ORC-{short(inv.id)} <span>·</span> PID {inv.pid} <span>·</span> {fmt(inv.created_at)}</div><h2>{inv.summary}</h2><p>{inv.status.replace(/_/g, ' ')} <span>·</span> assessment confidence {Math.round(inv.confidence * 100)}%</p></div><button className="button quiet" onClick={onSpeak} disabled={speechLoading || speechRetrySeconds > 0}><Volume2 size={16}/>{speechLoading ? 'Preparing audio…' : speechRetrySeconds ? `Retry in ${speechRetrySeconds}s` : 'Read report'}</button></div>
    <div className="assessment-block"><div className="section-heading"><div><h3>Assessment</h3><p>Local rule assessment · observed facts remain below</p></div><span className="assessment-confidence">{Math.round(inv.confidence * 100)}% heuristic confidence</span></div><p className="conclusion">{inv.conclusion || 'No conclusion available.'}</p>{event && <div className="trigger-summary"><AlertTriangle size={16}/><span><b>Review signal:</b> {event.reason || event.rule || 'Manual investigation'}{event.simulated && <em> · Simulated demo event</em>}</span></div>}{inv.llm_assessment && <details className="technical-disclosure ai-review"><summary><span><Sparkles size={14}/>Groq AI assessment <small>Model inference · {inv.llm_assessment.model || 'configured model'}</small></span><ChevronDown size={15}/></summary>{inv.llm_assessment.error ? <p className="chat-error">{inv.llm_assessment.error}</p> : <><p className="ai-assessment">{inv.llm_assessment.assessment}</p>{inv.llm_assessment.model_inference && <p>{inv.llm_assessment.model_inference}</p>}<small>AI generated · {Math.round((inv.llm_assessment.confidence || 0) * 100)}% model confidence. This is an interpretation, not a finding of malware.</small>{[['Possible benign causes',inv.llm_assessment.likely_benign_causes],['Potential risks',inv.llm_assessment.potential_risks],['Safe checks',inv.llm_assessment.safe_checks],['Missing evidence',inv.llm_assessment.missing_evidence],['Limitations',inv.llm_assessment.limitations]].map(([label,items]: any) => items?.length ? <div className="ai-list" key={label}><b>{label}</b><ul>{items.map((x: string) => <li key={x}>{x}</li>)}</ul></div> : null)}</>}</details>}</div>
    <section className="evidence-section"><div className="section-heading"><div><h3>Evidence collected</h3><p>Observed facts from local, allowlisted process checks.</p></div><span className="evidence-count">{inv.evidence.length} items</span></div>{inv.evidence.length ? <div className="evidence-list">{inv.evidence.map((e: any) => <article className="evidence-row" key={e.id}><span className="evidence-dot"/><time>{fmt(e.timestamp)}</time><div><b>{String(e.kind).replace(/_/g, ' ')}</b><small>{e.source} · {e.polarity}</small><p>{e.detail}</p></div></article>)}</div> : <div className="empty-state">No process evidence could be collected.</div>}</section>
    <ChatPanel investigation={inv} evidenceIncomplete={!!(inv.unknowns.length || !inv.evidence.length)}/>
    <details className="technical-disclosure technical-details" open={showTechnical} onToggle={e => setShowTechnical((e.target as HTMLDetailsElement).open)}><summary>Technical details <ChevronDown size={15}/></summary><div className="technical-grid"><div><h3>Hypotheses</h3><p>Ranked possibilities, not confirmed facts.</p>{inv.hypotheses.map((h: any) => <div className="hypothesis-row" key={h.title}><b>{h.title}</b><span>{Math.round(h.confidence * 100)}%</span><p>{h.rationale}</p><small>{h.status}</small></div>)}</div><div><h3>Evidence gaps</h3><p>What this investigation could not establish.</p>{(inv.unknowns.length ? inv.unknowns : ['Intent cannot be established by heuristic signals.', 'System journal events are not collected.']).map((u: string) => <p className="unknown-item" key={u}>{u}</p>)}<h3>Investigation actions</h3><ul>{inv.actions.map((a: string) => <li key={a}>{a}</li>)}</ul><h3>Observed relationships</h3><div className="relationship"><span>Process {inv.pid}</span><ChevronDown size={14}/><span>{event?.ppid ? `Parent process ${event.ppid}` : event?.executable || 'Executable unavailable'}</span>{event?.connections?.map(x => <span key={x}><Network size={13}/> {x}</span>)}</div></div></div></details>
  </>;
}

function ChatPanel({ investigation, evidenceIncomplete }: { investigation: Inv; evidenceIncomplete: boolean }) {
  const [messages, setMessages] = useState<{ role: string; content: string; created_at?: string }[]>([]), [question, setQuestion] = useState(''), [loading, setLoading] = useState(false), [error, setError] = useState('');
  useEffect(() => { let cancelled = false; fetch(`/api/investigations/${investigation.id}/chat`).then(r => r.json()).then(d => { if (!cancelled) setMessages(d.messages || []); }).catch(() => { if (!cancelled) setError('Could not load the saved conversation.'); }); return () => { cancelled = true; }; }, [investigation.id]);
  async function send(e: FormEvent) {
    e.preventDefault(); if (!question.trim() || loading) return; const ask = question.trim(); setQuestion(''); setError(''); setLoading(true);
    try { const r = await fetch(`/api/investigations/${investigation.id}/chat`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ question: ask }) }), d = await r.json(); if (!r.ok) throw Error(d.detail || 'The assistant could not answer.'); setMessages(current => [...current, { role: 'user', content: ask }, { role: 'assistant', content: d.answer }].slice(-16)); }
    catch (err: any) { setQuestion(ask); setError(err.message); } finally { setLoading(false); }
  }
  return <section className="chat-panel"><div className="chat-header"><div className="chat-heading-icon"><MessageCircle size={17}/></div><div><h3>Ask about this investigation</h3><p>Groq reasons over this case’s evidence only. No commands are executed.</p></div><span className="ai-badge">AI assistant</span></div>{evidenceIncomplete && <div className="incomplete-note"><CircleHelp size={14}/>Evidence is incomplete; answers may be limited.</div>}{messages.length > 0 && <div className="chat-messages" aria-live="polite">{messages.map((m, i) => <article className={`chat-message ${m.role}`} key={`${i}-${m.created_at || ''}`}><small>{m.role === 'assistant' ? 'ORACLE · AI generated' : 'You'}</small><p>{m.content}</p></article>)}</div>}<form className="chat-form" onSubmit={send}><label className="sr-only" htmlFor="investigation-question">Ask a question about this investigation</label><input id="investigation-question" value={question} onChange={e => setQuestion(e.target.value)} maxLength={1200} placeholder="Why was this process flagged? What should I check next?" disabled={loading}/><button className="button primary" disabled={loading || !question.trim()} aria-label="Send question">{loading ? 'Thinking…' : 'Ask'}<Send size={15}/></button></form>{error && <p className="chat-error" role="alert">{error}</p>}</section>;
}
