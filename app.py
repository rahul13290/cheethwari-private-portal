"""Cheethwari private polling-site operations portal.

No individual-level turnout records, political affiliations, or voter contact lists.
Designed for one Uvicorn worker and one Railway persistent volume.
"""
import asyncio
import base64
import csv
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import sqlite3
import time
import threading
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv('DATA_DIR', str(BASE / '.local_data')))
DB_PATH = DATA_DIR / 'operations.sqlite3'
SESSION_SECONDS = 12 * 3600
ROOM_TO_WARDS = {72:[2,3],73:[7,8,9],74:[5,6],75:[1,11,12],76:[14,15,16],77:[17,18,19],78:[4,10,13]}
WARD_VOTERS = {1:431,2:387,3:408,4:478,5:513,6:504,7:316,8:308,9:315,10:307,11:287,12:311,13:307,14:325,15:305,16:311,17:333,18:355,19:330}
ROOM_LABELS = {72:'कक्ष 1',73:'कक्ष 2',74:'कक्ष 3',75:'कक्ष 4',76:'कक्ष 8',77:'कक्ष 12',78:'कक्ष 13'}
ROOMS = sorted(ROOM_TO_WARDS)
assert sum(WARD_VOTERS.values()) == 6831
assert set(sum(ROOM_TO_WARDS.values(),[])) == set(range(1,20))
ROLE_TYPES = {'admin','reporter','viewer'}
CATEGORIES = {'queue':'लंबी कतार','access':'दिव्यांग सहायता','signage':'संकेत / मार्गदर्शन','water':'पानी / छाया','network':'नेटवर्क','staff':'स्टाफ','other':'अन्य'}
STATUSES = ('open','in_progress','resolved')
STATE_LABELS = {'normal':'सामान्य','busy':'भीड़','help':'सहायता आवश्यक'}
LOGIN_ATTEMPTS = {}
PASSWORD_WORKERS = threading.BoundedSemaphore(4)  # cap RAM/CPU under simultaneous sign-ins
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.mount('/assets', StaticFiles(directory=BASE/'static'), name='assets')
SUBSCRIBERS = set()


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def conn():
    db = sqlite3.connect(str(DB_PATH), timeout=10, check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA busy_timeout=10000')
    db.execute('PRAGMA foreign_keys=ON')
    return db


def pwd_hash(password: str):
    salt = secrets.token_bytes(16)
    with PASSWORD_WORKERS:
        raw = hashlib.scrypt(password.encode(),salt=salt,n=2**14,r=8,p=1,dklen=32)
    return 'scrypt$'+base64.b64encode(salt).decode()+'$'+base64.b64encode(raw).decode()


def pwd_verify(password:str, stored:str):
    try:
        _,a,b = stored.split('$')
        salt,valid=base64.b64decode(a),base64.b64decode(b)
        with PASSWORD_WORKERS:
            calc=hashlib.scrypt(password.encode(),salt=salt,n=2**14,r=8,p=1,dklen=32)
        return hmac.compare_digest(calc,valid)
    except Exception:
        return False


def setup():
    if os.getenv('RAILWAY_ENVIRONMENT') and not os.getenv('RAILWAY_VOLUME_MOUNT_PATH'):
        raise RuntimeError('Railway persistent volume is REQUIRED; mount one at /data before deploying')
    if os.getenv('RAILWAY_ENVIRONMENT') and str(DATA_DIR) != os.getenv('RAILWAY_VOLUME_MOUNT_PATH'):
        raise RuntimeError('DATA_DIR must equal RAILWAY_VOLUME_MOUNT_PATH for persistent records')
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with closing(conn()) as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript('''
        create table if not exists users (
          id integer primary key autoincrement,username text not null unique,
          password_hash text not null,role text not null check(role in ('admin','reporter','viewer')),
          booth integer,active integer not null default 1,must_change integer not null default 1,
          created_at text not null,
          check(role != 'reporter' or booth between 72 and 78));
        create table if not exists sessions (
          id_hash text primary key, user_id integer not null references users(id) on delete cascade,
          csrf text not null,expires integer not null);
        create table if not exists dhanis (
          id integer primary key autoincrement,name text not null unique,
          alternate text not null default '', wards text not null default '[]',
          verified integer not null default 0, updated_at text not null);
        create table if not exists room_conditions (
          room integer primary key check(room between 72 and 78),
          state text not null default 'normal', changed_by integer,updated_at text);
        create table if not exists issues (
          id integer primary key autoincrement, room integer not null,
          category text not null,status text not null default 'open',
          note text not null default '',version integer not null default 0,
          created_by integer not null,created_at text not null,updated_at text not null);
        create table if not exists official_reports (
          id integer primary key autoincrement,total integer not null,
          source text not null,reported_at text not null,
          entered_by integer not null,created_at text not null);
        create table if not exists audit (
          id integer primary key autoincrement,actor integer,action text not null,
          detail text not null,created_at text not null);
        create index if not exists idx_issues_room on issues(room,created_at);
        create index if not exists idx_sessions_expire on sessions(expires);
        ''')
        for room in ROOMS:
            db.execute('insert or ignore into room_conditions(room,state,updated_at) values(?,?,?)',(room,'normal',now()))
        if not db.execute('select 1 from users limit 1').fetchone():
            username=os.getenv('BOOTSTRAP_ADMIN_USERNAME','admin').strip().lower()
            password=os.getenv('BOOTSTRAP_ADMIN_PASSWORD','')
            if not re.fullmatch(r'[a-z0-9._-]{3,40}',username) or len(password)<16:
                raise RuntimeError('Set BOOTSTRAP_ADMIN_USERNAME and strong BOOTSTRAP_ADMIN_PASSWORD (min 16 chars)')
            db.execute('insert into users(username,password_hash,role,booth,must_change,created_at) values(?,?,?,?,?,?)', (username,pwd_hash(password),'admin',None,1,now()))
        db.commit()

@app.on_event('startup')
def startup():
    setup()


def http_error(code,message):
    raise HTTPException(status_code=code, detail=message)


def user_for(request:Request, require_admin=False, allow_password_change=False):
    token=request.cookies.get('cheethwari_session','')
    if len(token)<30: http_error(401,'Login required')
    with closing(conn()) as db:
        row=db.execute('''select u.id,u.username,u.role,u.booth,u.active,u.must_change,s.csrf,s.expires
            from sessions s join users u on u.id=s.user_id where s.id_hash=?''',(hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
    if not row or not row['active'] or row['expires']<time.time(): http_error(401,'Session expired')
    data=dict(row)
    if data['must_change'] and not allow_password_change: http_error(403,'Password change required')
    if require_admin and data['role']!='admin': http_error(403,'Admin only')
    return data


def verify_write(request:Request, u):
    if request.headers.get('x-csrf-token')!=u['csrf']:
        http_error(403,'Security token mismatch; refresh your session')
    # Requests from browsers are same-origin; CSRF token is still required when Origin absent.
    origin=request.headers.get('origin')
    if origin:
        o=urlsplit(origin)
        expected=request.headers.get('x-forwarded-host',request.headers.get('host','')).lower()
        if o.netloc.lower()!=expected:
            http_error(403,'Invalid request origin')


def audit(db,user_id,action,detail):
    db.execute('insert into audit(actor,action,detail,created_at) values(?,?,?,?)',(user_id,action,json.dumps(detail,ensure_ascii=False),now()))

async def broadcast(kind='refresh'):
    for q in tuple(SUBSCRIBERS):
        try: q.put_nowait({'kind':kind,'at':now()})
        except asyncio.QueueFull:
            try: q.get_nowait();q.put_nowait({'kind':'refresh','at':now()})
            except Exception: pass

class LoginBody(BaseModel):
    username:str=Field(min_length=3,max_length=40)
    password:str=Field(min_length=1,max_length=256)
class ChangePasswordBody(BaseModel):
    old:str=Field(min_length=1,max_length=256)
    new:str=Field(min_length=16,max_length=256)
class IssueBody(BaseModel):
    room:int
    category:str
    note:str=Field(default='',max_length=160)
class StatusBody(BaseModel):
    version:int=Field(ge=0)
    status:str
class ConditionBody(BaseModel):
    state:str
class DhaniBody(BaseModel):
    name:str=Field(min_length=2,max_length=100)
    alternate:str=Field(default='',max_length=200)
    wards:list[int]=Field(default_factory=list,max_length=19)
    verified:bool=False
class ReportBody(BaseModel):
    total:int=Field(ge=0,le=6831)
    source:str=Field(min_length=8,max_length=200)
    reported_at:str=Field(min_length=10,max_length=35)
class AddUserBody(BaseModel):
    username:str=Field(min_length=3,max_length=40)
    role:str
    booth:int|None=None
class BulkBody(BaseModel):
    role:str
    booth:int|None=None
    count:int=Field(ge=1,le=100)
    prefix:str=Field(min_length=3,max_length=22)

@app.get('/')
def index(): return FileResponse(BASE/'static/index.html')
@app.get('/health')
def health():
    try:
        with closing(conn()) as db: db.execute('select 1').fetchone()
        return {'ok':True,'service':'cheethwari-operations'}
    except Exception:
        return JSONResponse({'ok':False},status_code=503)

@app.post('/api/login')
def login(body:LoginBody,request:Request):
    username=body.username.strip().lower()
    ip=(request.client.host if request.client else 'unknown')
    k=(ip,username)
    attempts=[x for x in LOGIN_ATTEMPTS.get(k,[]) if time.time()-x<900]
    if len(attempts)>=7: http_error(429,'Too many attempts. Try later.')
    with closing(conn()) as db:
        user=db.execute('select * from users where username=?',(username,)).fetchone()
        good=pwd_verify(body.password,user['password_hash'] if user else pwd_hash('constant-dummy'))
        if not user or not user['active'] or not good:
            attempts.append(time.time());LOGIN_ATTEMPTS[k]=attempts
            http_error(401,'Invalid credentials')
        LOGIN_ATTEMPTS.pop(k,None)
        token=secrets.token_urlsafe(40)
        csrf=secrets.token_urlsafe(32)
        db.execute('delete from sessions where expires<?',(int(time.time()),))
        db.execute('insert into sessions(id_hash,user_id,csrf,expires) values(?,?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),user['id'],csrf,int(time.time())+SESSION_SECONDS))
        audit(db,user['id'],'login',{'username':username})
        db.commit()
    resp=JSONResponse({'ok':True,'must_change':bool(user['must_change'])})
    resp.set_cookie('cheethwari_session',token,httponly=True,secure=os.getenv('COOKIE_SECURE','1')=='1',samesite='strict',max_age=SESSION_SECONDS,path='/')
    return resp

@app.get('/api/me')
def me(request:Request):
    u=user_for(request,allow_password_change=True)
    return {k:u[k] for k in ['id','username','role','booth','must_change','csrf']}

@app.post('/api/password')
async def password_change(body:ChangePasswordBody,request:Request):
    u=user_for(request,allow_password_change=True)
    verify_write(request,u)
    if body.new==body.old or len(set(body.new))<8:
        http_error(400,'Choose a different strong password')
    with closing(conn()) as db:
        record=db.execute('select password_hash from users where id=?',(u['id'],)).fetchone()
        if not pwd_verify(body.old,record['password_hash']): http_error(403,'Incorrect current password')
        db.execute('update users set password_hash=?,must_change=0 where id=?',(pwd_hash(body.new),u['id']))
        # Keep this valid session but revoke the user's other sessions.
        current_hash=hashlib.sha256(request.cookies.get('cheethwari_session','').encode()).hexdigest()
        db.execute('delete from sessions where user_id=? and id_hash<>?',(u['id'],current_hash))
        audit(db,u['id'],'password_changed',{})
        db.commit()
    return {'ok':True}

@app.post('/api/logout')
def logout(request:Request):
    u=user_for(request,allow_password_change=True)
    verify_write(request,u)
    token=request.cookies.get('cheethwari_session','')
    with closing(conn()) as db:
        db.execute('delete from sessions where id_hash=?',(hashlib.sha256(token.encode()).hexdigest(),))
        db.commit()
    resp=JSONResponse({'ok':True})
    resp.delete_cookie('cheethwari_session',path='/')
    return resp

@app.get('/api/dashboard')
def dashboard(request:Request):
    u=user_for(request)
    with closing(conn()) as db:
        counts=db.execute('select room,state,updated_at from room_conditions order by room').fetchall()
        open_counts={r['room']:r['n'] for r in db.execute("select room,count(*) as n from issues where status!='resolved' group by room")}
        report=db.execute('select total,source,reported_at,created_at from official_reports order by id desc limit 1').fetchone()
        dhani_count=db.execute('select count(*) from dhanis where verified=1').fetchone()[0]
    return {'wards':WARD_VOTERS,'registered_total':6831,'verified_dhanis':dhani_count,
      'rooms':[{'number':r['room'],'label':ROOM_LABELS[r['room']],'wards':ROOM_TO_WARDS[r['room']],
      'registered':sum(WARD_VOTERS[w] for w in ROOM_TO_WARDS[r['room']]),'state':r['state'],'updated_at':r['updated_at'],
      'open_issues':open_counts.get(r['room'],0) if (u['role']=='admin' or u['booth']==r['room']) else None} for r in counts],
      'official_report':dict(report) if report else None}

@app.get('/api/dhanis')
def list_dhanis(request:Request):
    user_for(request)
    with closing(conn()) as db: rows=db.execute('select * from dhanis order by name').fetchall()
    return [{'id':x['id'],'name':x['name'],'alternate':x['alternate'],'wards':json.loads(x['wards']),
       'verified':bool(x['verified']),'updated_at':x['updated_at']} for x in rows]

@app.post('/api/dhanis')
async def add_dhani(body:DhaniBody,request:Request):
    u=user_for(request,require_admin=True);verify_write(request,u)
    if any(w not in WARD_VOTERS for w in body.wards) or len(set(body.wards))!=len(body.wards):http_error(400,'Invalid ward list')
    name=body.name.strip()
    if len(name)<2:http_error(400,'Dhani name required')
    try:
        with closing(conn()) as db:
            db.execute('insert into dhanis(name,alternate,wards,verified,updated_at) values(?,?,?,?,?)',
                 (name,body.alternate.strip(),json.dumps(sorted(body.wards)),int(body.verified),now()))
            audit(db,u['id'],'dhani_created',{'name':name,'wards':body.wards})
            db.commit()
    except sqlite3.IntegrityError: http_error(409,'Dhani already exists')
    await broadcast('dhanis');return {'ok':True}

@app.get('/api/issues')
def issues(request:Request):
    u=user_for(request)
    if u['role']=='viewer':return []
    with closing(conn()) as db:
        if u['role']=='admin': rows=db.execute('select * from issues order by id desc limit 300').fetchall()
        else: rows=db.execute('select * from issues where room=? order by id desc limit 200',(u['booth'],)).fetchall()
    return [dict(x) for x in rows]

@app.post('/api/issues')
async def add_issue(body:IssueBody,request:Request):
    u=user_for(request);verify_write(request,u)
    if u['role']=='viewer' or (u['role']=='reporter' and u['booth']!=body.room):http_error(403,'No access to this room')
    if body.room not in ROOMS or body.category not in CATEGORIES: http_error(400,'Invalid room/category')
    with closing(conn()) as db:
        cursor=db.execute('insert into issues(room,category,note,created_by,created_at,updated_at) values(?,?,?,?,?,?)',
          (body.room,body.category,body.note.strip(),u['id'],now(),now()))
        audit(db,u['id'],'issue_created',{'id':cursor.lastrowid,'room':body.room})
        db.commit()
    await broadcast('issues');return {'ok':True,'id':cursor.lastrowid}

@app.put('/api/issues/{issue_id}')
async def change_status(issue_id:int,body:StatusBody,request:Request):
    u=user_for(request);verify_write(request,u)
    if body.status not in STATUSES:http_error(400,'Invalid status')
    with closing(conn()) as db:
        db.execute('begin immediate')
        issue=db.execute('select * from issues where id=?',(issue_id,)).fetchone()
        if not issue: http_error(404,'Issue not found')
        if u['role']=='viewer' or (u['role']=='reporter' and u['booth']!=issue['room']):http_error(403,'No access to this room')
        if issue['version']!=body.version:http_error(409,'Changed by another user; refresh')
        allowable=(issue['status']=='open' and body.status=='in_progress') or (issue['status']=='in_progress' and body.status=='resolved') or (u['role']=='admin' and issue['status']=='resolved' and body.status=='open')
        if not allowable:http_error(400,'Invalid state transition')
        db.execute('update issues set status=?,version=version+1,updated_at=? where id=?', (body.status,now(),issue_id))
        audit(db,u['id'],'issue_changed',{'id':issue_id,'status':body.status})
        db.commit()
    await broadcast('issues');return {'ok':True}

@app.put('/api/rooms/{room}/condition')
async def condition(room:int,body:ConditionBody,request:Request):
    u=user_for(request);verify_write(request,u)
    if room not in ROOMS or body.state not in STATE_LABELS:http_error(400,'Invalid room/state')
    if u['role']=='viewer' or (u['role']=='reporter' and u['booth']!=room):http_error(403,'No access to this room')
    with closing(conn()) as db:
        db.execute('update room_conditions set state=?,changed_by=?,updated_at=? where room=?',(body.state,u['id'],now(),room))
        audit(db,u['id'],'room_condition',{'room':room,'state':body.state});db.commit()
    await broadcast('rooms');return {'ok':True}

@app.post('/api/official-report')
async def report(body:ReportBody,request:Request):
    u=user_for(request,require_admin=True);verify_write(request,u)
    try:datetime.fromisoformat(body.reported_at.replace('Z','+00:00'))
    except ValueError:http_error(400,'Date invalid')
    with closing(conn()) as db:
        db.execute('insert into official_reports(total,source,reported_at,entered_by,created_at) values(?,?,?,?,?)',
          (body.total,body.source.strip(),body.reported_at,u['id'],now()))
        audit(db,u['id'],'official_report',{'total':body.total,'source':body.source.strip()})
        db.commit()
    await broadcast('official');return {'ok':True}


def create_account(db, username,role,booth,actor):
    username=username.strip().lower()
    if not re.fullmatch(r'[a-z0-9._-]{3,40}',username):http_error(400,'Username: 3–40 letters/numbers/._-')
    if role not in ROLE_TYPES or (role=='reporter' and booth not in ROOMS):http_error(400,'Invalid role/booth')
    if role != 'reporter':booth=None
    password=secrets.token_urlsafe(18)+'!A8'
    try:
        db.execute('insert into users(username,password_hash,role,booth,must_change,created_at) values(?,?,?,?,?,?)',
          (username,pwd_hash(password),role,booth,1,now()))
    except sqlite3.IntegrityError:http_error(409,f'Username exists: {username}')
    audit(db,actor,'user_created',{'username':username,'role':role,'booth':booth})
    return {'username':username,'temporary_password':password,'role':role,'booth':booth}

@app.get('/api/users')
def users(request:Request):
    user_for(request,require_admin=True)
    with closing(conn()) as db:rows=db.execute('select id,username,role,booth,active,must_change from users order by id').fetchall()
    return [dict(x) for x in rows]

@app.post('/api/users')
def add_user(body:AddUserBody,request:Request):
    u=user_for(request,require_admin=True);verify_write(request,u)
    with closing(conn()) as db:
        row=create_account(db,body.username,body.role,body.booth,u['id']);db.commit()
    return row

@app.post('/api/users/bulk')
def add_bulk(body:BulkBody,request:Request):
    u=user_for(request,require_admin=True);verify_write(request,u)
    if not re.fullmatch(r'[a-z0-9_-]{3,22}',body.prefix.lower()):http_error(400,'Invalid prefix')
    if body.role not in ROLE_TYPES or (body.role=='reporter' and body.booth not in ROOMS):http_error(400,'Invalid role/booth')
    with closing(conn()) as db:
        db.execute('begin immediate')
        entries=[]
        for i in range(1,body.count+1):
            username=f'{body.prefix.lower()}-{i:03d}'
            if db.execute('select 1 from users where username=?',(username,)).fetchone():
                http_error(409,'Existing username; choose another prefix')
            entries.append(create_account(db,username,body.role,body.booth,u['id']))
        db.commit()
    output=io.StringIO();writer=csv.DictWriter(output,fieldnames=['username','temporary_password','role','booth']);writer.writeheader();writer.writerows(entries)
    data=output.getvalue().encode('utf-8-sig')
    return StreamingResponse(iter([data]), media_type='text/csv', headers={'Content-Disposition':'attachment; filename="cheethwari-team-credentials.csv"','Cache-Control':'no-store'})

@app.patch('/api/users/{user_id}/access')
async def toggle_user(user_id:int,body:dict,request:Request):
    u=user_for(request,require_admin=True);verify_write(request,u)
    if user_id==u['id']:http_error(400,'Cannot deactivate yourself')
    if type(body.get('active')) is not bool:http_error(400,'Provide active true/false')
    with closing(conn()) as db:
        existing=db.execute('select role,active from users where id=?',(user_id,)).fetchone()
        if existing and existing['role']=='admin' and existing['active'] and not body['active']:
            if db.execute("select count(*) from users where role='admin' and active=1").fetchone()[0]<=1:
                http_error(400,'Cannot disable the last active administrator')
        res=db.execute('update users set active=? where id=?',(int(body['active']),user_id))
        if res.rowcount==0:http_error(404,'User not found')
        if not body['active']:db.execute('delete from sessions where user_id=?',(user_id,))
        audit(db,u['id'],'access_changed',{'user_id':user_id,'active':body['active']});db.commit()
    await broadcast('accounts');return {'ok':True}

@app.get('/api/audit')
def audit_log(request:Request):
    user_for(request,require_admin=True)
    with closing(conn()) as db: rows=db.execute('select a.id,a.action,a.detail,a.created_at,u.username from audit a left join users u on u.id=a.actor order by a.id desc limit 120').fetchall()
    return [dict(x) for x in rows]

@app.websocket('/ws')
async def ws_feed(ws:WebSocket):
    origin=ws.headers.get('origin','')
    if origin and urlsplit(origin).netloc.lower()!=ws.headers.get('x-forwarded-host',ws.headers.get('host','')).lower():
        await ws.close(code=1008);return
    token=ws.cookies.get('cheethwari_session','')
    if not token:
        await ws.close(code=1008);return
    with closing(conn()) as db:
        rec=db.execute('select s.expires,u.active,u.must_change from sessions s join users u on u.id=s.user_id where s.id_hash=?',(hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
    if not rec or not rec['active'] or rec['must_change'] or rec['expires']<time.time():
        await ws.close(code=1008);return
    await ws.accept()
    q=asyncio.Queue(maxsize=12)
    SUBSCRIBERS.add(q)
    try:
        await ws.send_json({'kind':'connected','at':now()})
        while True:
            try: event=await asyncio.wait_for(q.get(), timeout=25)
            except asyncio.TimeoutError: event={'kind':'heartbeat','at':now()}
            with closing(conn()) as db:
                live=db.execute('select 1 from sessions s join users u on u.id=s.user_id where s.id_hash=? and s.expires>? and u.active=1',
                    (hashlib.sha256(token.encode()).hexdigest(),int(time.time()))).fetchone()
            if not live:
                await ws.close(code=1008);break
            await ws.send_json(event)
    except (WebSocketDisconnect,RuntimeError,Exception):
        pass
    finally:
        SUBSCRIBERS.discard(q)
