import os, re, socket, logging, json, time
from datetime import datetime, timezone
from contextlib import asynccontextmanager
import httpx
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field
from .core import POLL_INTERVAL, RESOURCE_SAMPLE_INTERVAL, PROCESS_RESOURCE_SAMPLE_INTERVAL, list_events, list_investigations, get_investigation, get_event, create_investigation, simulate_event, db, list_chat_messages, persist_chat_message
from .lifecycle import daemon_status, ensure_daemon, stop_daemon
from .llm import LLMError, provider_settings, answer_question, test_connection
from . import resources as resource_history_store
from . import settings as app_settings
from . import detection as alert_store

@asynccontextmanager
async def lifespan(app):
    db().close(); yield
app=FastAPI(title='ORACLE Security Intelligence Agent',version='0.1.0',lifespan=lifespan)
app.add_middleware(CORSMiddleware,allow_origins=['http://127.0.0.1:5173','http://localhost:5173'],allow_methods=['*'],allow_headers=['*'])

# Protect the provider's documented one-active-request limit in this local API process.
_tts_request_active=False
_logger=logging.getLogger(__name__)

class Command(BaseModel): command:str = Field(min_length=1,max_length=500)
class ChatQuestion(BaseModel): question:str = Field(min_length=1,max_length=1200)

@app.get('/api/health')
def health():
    key=bool(os.getenv('GNANI_API_KEY')); daemon=daemon_status(); llm=provider_settings(); latest=resource_history_store.latest_resource_sample()
    summary={name:latest.get(name) for name in ('timestamp','cpu_percent','memory_percent','memory_used','memory_total','network_recv_bps','network_sent_bps')} if latest else None
    return {'status':'running','pid':os.getpid(),'monitoring':daemon['running'],'monitoring_pid':daemon['pid'],'collector':f'psutil process snapshots ({POLL_INTERVAL:g}s interval)','resources':summary,'gnani':{'configured':key,'provider':'Gnani Speech API','prisma':'configured' if key else 'needs GNANI_API_KEY','timbre':'configured' if key else 'needs GNANI_API_KEY'},'reasoning':llm}

@app.get('/api/resources')
def resource_timeline(window:str='15m',pid:int|None=None,create_time:float|None=None):
    durations={'5m':300,'15m':900,'1h':3600,'24h':86400}
    if window not in durations: raise HTTPException(400,'window must be one of 5m, 15m, 1h, or 24h')
    now=time.time(); start=now-durations[window]
    history=resource_history_store.resource_history(start,now,pid=pid,create_time=create_time)
    connection=db()
    try:
        rows=connection.execute('SELECT data FROM events WHERE timestamp >= ? ORDER BY timestamp LIMIT 500',(datetime.fromtimestamp(start,timezone.utc).isoformat(),)).fetchall()
        events=[json.loads(row['data']) for row in rows]
    finally: connection.close()
    preferences=app_settings.get_settings()
    return {'window':window,'monitoring':daemon_status()['running'],'sampling_interval_seconds':preferences['resource_interval'],'process_sampling_interval_seconds':preferences['process_resource_interval'],**history,'events':events}

@app.get('/api/settings')
def read_settings(): return app_settings.get_settings()

@app.patch('/api/settings')
def patch_settings(payload:dict):
    try: return app_settings.update_settings(payload)
    except ValueError as ex: raise HTTPException(400,str(ex)) from None

@app.get('/api/alerts')
def read_alerts(status:str|None=None,severity:str|None=None,pid:int|None=None,limit:int=100):
    if status is not None and status not in {'new','acknowledged','snoozed','resolved'}: raise HTTPException(400,'Invalid alert status.')
    if severity is not None and severity not in {'info','low','medium','high','critical'}: raise HTTPException(400,'Invalid severity.')
    return alert_store.list_alerts(status=status,severity=severity,pid=pid,limit=limit)

@app.patch('/api/alerts/{alert_id}')
def change_alert(alert_id:str,payload:dict):
    try: result=alert_store.update_alert(alert_id,payload.get('status',''),snooze_seconds=payload.get('snooze_seconds',3600))
    except (ValueError,TypeError) as exc: raise HTTPException(400,str(exc)) from None
    if result is None: raise HTTPException(404,'Alert not found.')
    return result
@app.post('/api/monitoring')
def monitoring(payload:dict):
    enabled=payload.get('enabled')
    if not isinstance(enabled,bool): raise HTTPException(400,'enabled must be a boolean')
    try:
        if enabled: ensure_daemon()
        else: stop_daemon()
    except (RuntimeError,OSError) as ex: raise HTTPException(503,str(ex)) from ex
    state=daemon_status()
    return {'monitoring':state['running'],'pid':state['pid'],'collector':f'psutil process snapshots ({POLL_INTERVAL:g}s interval)'}
@app.get('/api/events')
def events(limit:int=100): return [e.model_dump() for e in list_events(min(max(limit,1),500))]
@app.get('/api/investigations')
def investigations(limit:int=100): return [i.model_dump() for i in list_investigations(min(max(limit,1),500))]
@app.get('/api/investigations/{iid}')
def investigation(iid:str):
    i=get_investigation(iid)
    if not i: raise HTTPException(404,'Investigation not found')
    return i.model_dump()
@app.get('/api/investigations/{iid}/chat')
def chat_history(iid:str):
    if not get_investigation(iid): raise HTTPException(404,'Investigation not found')
    return {'messages':list_chat_messages(iid)}
@app.post('/api/investigations/{iid}/chat')
def chat(iid:str,payload:ChatQuestion):
    question=payload.question.strip()
    if not question: raise HTTPException(422,'Question cannot be empty.')
    inv=get_investigation(iid)
    if not inv: raise HTTPException(404,'Investigation not found')
    event=get_event(inv.event_id)
    if not event: raise HTTPException(404,'Investigation event is no longer available')
    history=list_chat_messages(iid,limit=12)
    try: answer=answer_question(event.model_dump(),inv.model_dump(),history,question)
    except LLMError as ex:
        headers={'X-Provider-Status':str(ex.provider_status_code)} if ex.provider_status_code else None
        raise HTTPException(ex.http_status_code,str(ex),headers=headers) from None
    persist_chat_message(iid,'user',question)
    persist_chat_message(iid,'assistant',answer)
    return {'answer':answer,'provider':'groq','model':provider_settings()['model'],'generated_by_ai':True,'evidence_incomplete':bool(inv.unknowns or not inv.evidence),'context_turns':len(history)//2}
@app.post('/api/llm/test')
def llm_test():
    try: return test_connection()
    except LLMError as ex:
        headers={'X-Provider-Status':str(ex.provider_status_code)} if ex.provider_status_code else None
        raise HTTPException(ex.http_status_code,str(ex),headers=headers) from None
@app.post('/api/investigations')
def investigate(payload:Command):
    m=re.search(r'\bpid\s*(\d+)\b|\bprocess\s+(\d+)\b',payload.command,re.I)
    if m:
        pid=int(m.group(1) or m.group(2))
        if pid<1 or pid>2_147_483_647: raise HTTPException(400,'PID must be a positive Linux process ID.')
        event=next((e for e in list_events(500) if e.pid==pid),None)
        if not event:
            from .core import Event,persist_event,detect
            try:
                from .core import inspect_process
                d=inspect_process(pid); event=detect(Event(pid=pid,ppid=d['ppid'],name=d['name'],executable=d['executable'],connections=d['connections'],kind='user_requested'))
                persist_event(event)
            except Exception as ex: raise HTTPException(404,f'Cannot inspect PID {pid}: process unavailable or permission denied') from ex
    elif 'suspicious' in payload.command.lower() or 'investigat' in payload.command.lower():
        event=next((e for e in list_events(500) if e.risk_score>=35),None)
        if not event: raise HTTPException(404,'No suspicious event available. Use the safe demo scenario or provide a PID.')
    else: raise HTTPException(400,'Supported command: “investigate PID 1234” or “investigate suspicious activity”.')
    try:return create_investigation(event.id).model_dump()
    except ValueError: raise HTTPException(404,'Trigger event no longer available')
@app.post('/api/demo')
def demo():
    e=simulate_event(); i=create_investigation(e.id); return {'event':e.model_dump(),'investigation':i.model_dump(),'notice':'SIMULATED benign demonstration event; no process or network connection was created.'}
@app.post('/api/voice/transcribe')
async def transcribe(audio:UploadFile=File(...),language_code:str=Form('en-IN')):
    key=os.getenv('GNANI_API_KEY')
    if not key: raise HTTPException(503,'Gnani is not configured. Add GNANI_API_KEY to .env and restart.')
    data=await audio.read()
    if len(data)>20_000_000: raise HTTPException(413,'Audio file exceeds 20 MB limit')
    if not data: raise HTTPException(400,'Audio is empty')
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            r=await client.post('https://api.vachana.ai/stt/v3',headers={'X-API-Key-ID':key},files={'audio_file':(audio.filename or 'recording.webm',data,audio.content_type or 'audio/webm')},data={'language_code':language_code})
        r.raise_for_status(); body=r.json()
        if not body.get('success') or not isinstance(body.get('transcript'),str): raise HTTPException(502,'Gnani returned an unsuccessful or unexpected transcription response')
        transcript=body['transcript']
        return {'transcript':transcript,'provider':'Gnani Prisma v2.5','request_id':body.get('request_id'),'command_result':_route_voice(transcript)}
    except HTTPException: raise
    except httpx.HTTPError as ex: raise HTTPException(502,'Gnani transcription request failed; check API access and try again') from ex

def _route_voice(transcript):
    clean=transcript.strip()
    clean=re.sub(r'^\s*oracle[, ]*','',clean,flags=re.I)
    if len(clean)>500: raise HTTPException(400,'Voice transcription is too long. Use a shorter investigation request.')
    if not re.search(r'\b(investigate|inspect|analy[sz]e)\b',clean,re.I): raise HTTPException(400,'Transcription received, but supported voice commands must ask ORACLE to investigate or inspect.')
    return investigate(Command(command=clean))
@app.post('/api/voice/command')
def voice_command(payload:Command): return {'transcript':payload.command,'provider':'typed fallback','command_result':_route_voice(payload.command)}
@app.post('/api/voice/speak')
async def speak(payload:Command):
    global _tts_request_active
    if _tts_request_active:
        raise HTTPException(409,'A Timbre synthesis request is already running. Wait for it to finish before starting another.')
    _tts_request_active=True
    try:
        return await _speak_once(payload)
    finally:
        _tts_request_active=False

def _provider_error_message(response, *, api_key:str, text:str)->tuple[str,str|None]:
    """Extract only the provider's short error code/message and redact request secrets."""
    code=None
    message=''
    try:
        body=response.json()
        detail=body.get('detail') if isinstance(body,dict) else None
        if isinstance(detail,dict):
            code=detail.get('error_code')
            message=detail.get('message','')
        elif isinstance(body,dict):
            message=body.get('message','')
            error=body.get('error')
            if isinstance(error,dict):
                code=error.get('type') or code
                message=error.get('message') or message
    except (ValueError,TypeError):
        pass
    if not isinstance(code,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}',code):
        code=None
    if not isinstance(message,str):
        message=''
    message=message.replace(api_key,'[redacted]') if api_key else message
    message=message.replace(text,'[request text redacted]') if text else message
    message=re.sub(r'(?i)(bearer\s+)[^\s,;]+',r'\1[redacted]',message)
    message=' '.join(''.join(ch for ch in message if ch.isprintable()).split())[:400]
    return message,code

def _provider_request_id(response)->str|None:
    for name in ('x-request-id','x-gnani-request-id','request-id','x-correlation-id'):
        value=response.headers.get(name,'').strip()
        if value and len(value)<=128 and all(ch.isalnum() or ch in '-_.:' for ch in value):
            return value
    return None

def _provider_rate_headers(response)->dict[str,str]:
    names=('ratelimit-limit','ratelimit-remaining','ratelimit-reset','x-ratelimit-limit','x-ratelimit-remaining','x-ratelimit-reset')
    result={}
    for name in names:
        value=response.headers.get(name,'').strip()
        if value and len(value)<=128 and all(ch.isprintable() for ch in value):
            result[name]=value
    return result

async def _speak_once(payload:Command):
    key=os.getenv('GNANI_API_KEY')
    if not key: raise HTTPException(503,'Timbre is not configured. Add GNANI_API_KEY to .env and restart.')
    text=payload.command[:3000]
    endpoint=os.getenv('GNANI_TTS_URL','https://api.vachana.ai/api/v1/tts/inference').strip()
    if not endpoint:
        raise HTTPException(503,'Gnani Timbre is not configured. Set GNANI_TTS_URL to the REST inference endpoint.')
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            r=await client.post(endpoint,headers={'X-API-Key-ID':key,'Content-Type':'application/json'},json={'text':text,'voice':'Kaveri','model':'timbre-v2.5','language':'en-IN','audio_config':{'encoding':'linear_pcm','container':'wav','num_channels':1,'sample_rate':48000,'sample_width':2}})
        r.raise_for_status()
        audio=r.content
        content_type=r.headers.get('content-type','').split(';',1)[0].strip().lower()
        if not audio:
            raise HTTPException(502,'Gnani Timbre returned an empty audio response.')
        if content_type not in ('audio/wav','audio/x-wav'):
            raise HTTPException(502,f'Gnani Timbre returned an unexpected audio format ({content_type or "missing content type"}); WAV was requested.')
        if len(audio)<12 or audio[:4]!=b'RIFF' or audio[8:12]!=b'WAVE':
            raise HTTPException(502,'Gnani Timbre returned malformed WAV audio.')
        return Response(content=audio,media_type=content_type,headers={'X-Oracle-Speech-Provider':'Gnani Timbre v2.5'})
    except httpx.HTTPStatusError as ex:
        status=ex.response.status_code
        provider_message,error_code=_provider_error_message(ex.response,api_key=key,text=text)
        request_id=_provider_request_id(ex.response)
        content_type=ex.response.headers.get('content-type','')[:128]
        if status==429:
            low=provider_message.lower()
            if any(term in low for term in ('credit','quota','subscription','entitlement')):
                detail='Gnani reported a quota or account allowance restriction.'
            elif error_code=='RATE_LIMITED' and ('active request' in low or 'current request' in low):
                detail='Gnani reports another active synthesis for this API key. Wait for it to finish, then retry.'
            else:
                detail='Gnani throttled this TTS request. Wait briefly before retrying.'
        elif status==402:
            detail='Gnani reports insufficient credits for this request. Check the Gnani dashboard or account billing.'
        elif status==401:
            detail='Gnani rejected the API key. Check GNANI_API_KEY.'
        elif status==403:
            detail='Gnani denied access to this service. Check TTS scope and account permissions.'
        elif status==400: detail='Gnani rejected the synthesis request. Check text, voice, language, and model settings.'
        elif status==404: detail='Gnani Timbre endpoint or model was not found. Check the API endpoint and model access.'
        elif status>=500: detail=f'Gnani Timbre is temporarily unavailable (HTTP {status}). Try again later.'
        else: detail=f'Gnani Timbre rejected the request with HTTP {status}. Check provider access and try again.'
        if provider_message:
            detail += f' Provider: {provider_message}'
        if request_id:
            detail += f' (request ID: {request_id})'
        headers={'X-Provider-Status':str(status),'X-Provider-Content-Type':content_type}
        if error_code: headers['X-Provider-Error-Code']=error_code
        if request_id: headers['X-Provider-Request-ID']=request_id
        retry_after=ex.response.headers.get('retry-after','').strip()
        if retry_after and len(retry_after)<=128 and all(ch.isprintable() for ch in retry_after):
            headers['Retry-After']=retry_after
        rate_headers=_provider_rate_headers(ex.response)
        for name,value in rate_headers.items():
            headers['X-Provider-'+name.removeprefix('x-').title().replace('-','')]=value
        _logger.warning('Gnani TTS provider error status=%s content_type=%s error_code=%s request_id=%s retry_after=%s rate_headers=%s message=%s',status,content_type,error_code or '-',request_id or '-',retry_after or '-',rate_headers or '-',provider_message or '-')
        outward_status=status if status in (400,401,402,403,404,429) else 502
        raise HTTPException(outward_status,detail,headers=headers) from None
    except httpx.TimeoutException:
        raise HTTPException(503,'Gnani Timbre did not respond within 60 seconds. Try again later.') from None
    except httpx.ConnectError as ex:
        cause=ex
        dns_failure=False
        while cause is not None:
            if isinstance(cause,socket.gaierror) or getattr(cause,'errno',None) in (getattr(socket,'EAI_NONAME',None),getattr(socket,'EAI_AGAIN',None)):
                dns_failure=True
                break
            cause=cause.__cause__ or cause.__context__
        if dns_failure or any(marker in str(ex).lower() for marker in ('name or service not known','temporary failure in name resolution','getaddrinfo failed','nodename nor servname')):
            raise HTTPException(503,'Could not resolve the Gnani Timbre hostname. Check DNS and GNANI_TTS_URL.') from None
        raise HTTPException(503,'Could not connect to Gnani Timbre. Check network access and try again.') from None
    except httpx.HTTPError:
        raise HTTPException(503,'Could not complete the Gnani Timbre request. Check network access and try again.') from None
