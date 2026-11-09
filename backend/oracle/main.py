import os, re
from contextlib import asynccontextmanager
import httpx
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field
from .core import POLL_INTERVAL, list_events, list_investigations, get_investigation, get_event, create_investigation, simulate_event, db, list_chat_messages, persist_chat_message
from .lifecycle import daemon_status, ensure_daemon, stop_daemon
from .llm import LLMError, provider_settings, answer_question, test_connection

@asynccontextmanager
async def lifespan(app):
    db().close(); yield
app=FastAPI(title='ORACLE Security Intelligence Agent',version='0.1.0',lifespan=lifespan)
app.add_middleware(CORSMiddleware,allow_origins=['http://127.0.0.1:5173','http://localhost:5173'],allow_methods=['*'],allow_headers=['*'])

class Command(BaseModel): command:str = Field(min_length=1,max_length=500)
class ChatQuestion(BaseModel): question:str = Field(min_length=1,max_length=1200)

@app.get('/api/health')
def health():
    key=bool(os.getenv('GNANI_API_KEY')); daemon=daemon_status(); llm=provider_settings()
    return {'status':'running','pid':os.getpid(),'monitoring':daemon['running'],'monitoring_pid':daemon['pid'],'collector':f'psutil process snapshots ({POLL_INTERVAL:g}s interval)','gnani':{'configured':key,'provider':'Gnani Speech API','prisma':'configured' if key else 'needs GNANI_API_KEY','timbre':'configured' if key else 'needs GNANI_API_KEY'},'reasoning':llm}
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
    except LLMError as ex: raise HTTPException(503,str(ex)) from ex
    persist_chat_message(iid,'user',question)
    persist_chat_message(iid,'assistant',answer)
    return {'answer':answer,'provider':'groq','model':provider_settings()['model'],'generated_by_ai':True,'evidence_incomplete':bool(inv.unknowns or not inv.evidence),'context_turns':len(history)//2}
@app.post('/api/llm/test')
def llm_test():
    try: return test_connection()
    except LLMError as ex: raise HTTPException(503,str(ex)) from ex
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
    key=os.getenv('GNANI_API_KEY')
    if not key: raise HTTPException(503,'Timbre is not configured. Add GNANI_API_KEY to .env and restart.')
    text=payload.command[:3000]
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            r=await client.post('https://api.gnani.ai/v1/tts/inference',headers={'Authorization':f'Bearer {key}','Content-Type':'application/json'},json={'text':text,'voice':'Nalini','model':'timbre-2.5','language':'en-IN','sample_rate':48000})
        r.raise_for_status()
        audio=r.content
        content_type=r.headers.get('content-type','audio/wav').split(';',1)[0].strip().lower()
        if not audio or not content_type.startswith('audio/'):
            raise HTTPException(502,'Gnani Timbre returned an empty or non-audio response.')
        return Response(content=audio,media_type=content_type,headers={'X-Oracle-Speech-Provider':'Gnani Timbre v2.5'})
    except httpx.HTTPStatusError as ex:
        status=ex.response.status_code
        if status in (401,403): detail='Gnani rejected the API key. Check GNANI_API_KEY and its TTS access.'
        elif status==404: detail='Gnani Timbre endpoint or model was not found. Check the Gnani API account and model access.'
        elif status==429: detail='Gnani TTS rate limit reached. Wait briefly, then try again.'
        else: detail=f'Gnani Timbre request failed with HTTP {status}. Check API access and try again.'
        raise HTTPException(502,detail) from ex
    except httpx.HTTPError as ex: raise HTTPException(502,'Gnani Timbre could not be reached. Check network access and try again.') from ex
