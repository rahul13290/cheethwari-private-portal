import importlib.util
import os
import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

MODULE=Path(__file__).resolve().parents[1]/'app.py'
spec=importlib.util.spec_from_file_location('ch_app',MODULE)
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)

@pytest.fixture
def client(monkeypatch,tmp_path):
    monkeypatch.setattr(a,'DATA_DIR',tmp_path)
    monkeypatch.setattr(a,'DB_PATH',tmp_path/'operations.sqlite3')
    monkeypatch.setenv('BOOTSTRAP_ADMIN_USERNAME','admin')
    monkeypatch.setenv('BOOTSTRAP_ADMIN_PASSWORD','temporary-strong-password-2026!')
    monkeypatch.setenv('COOKIE_SECURE','0')
    monkeypatch.delenv('RAILWAY_ENVIRONMENT',raising=False)
    a.LOGIN_ATTEMPTS.clear()
    with TestClient(a.app) as c:
        yield c

def login(c,user='admin',password='temporary-strong-password-2026!'):
    r=c.post('/api/login',json={'username':user,'password':password});assert r.status_code==200,r.text
    r=c.get('/api/me');assert r.status_code==200,r.text
    m=r.json()
    if m['must_change']:
        r=c.post('/api/password',json={'old':password,'new':'new-strong-password-2026-PRIVATE!'},headers={'X-CSRF-Token':m['csrf']})
        assert r.status_code==200,r.text
        m=c.get('/api/me').json()
    return m

def add(c,csrf,username,role,booth=None):
    r=c.post('/api/users',json={'username':username,'role':role,'booth':booth},headers={'X-CSRF-Token':csrf});assert r.status_code==200,r.text;return r.json()

def test_data_and_login(client):
    assert client.get('/health').status_code==200
    assert client.get('/api/dashboard').status_code==401
    assert client.post('/api/login',json={'username':'admin','password':'wrong'}).status_code==401
    m=login(client)
    assert m['role']=='admin'
    d=client.get('/api/dashboard').json()
    assert d['registered_total']==6831
    assert len(d['rooms'])==7
    assert sum(x['registered'] for x in d['rooms'])==6831
    assert len(d['wards'])==19
    assert client.get('/api/users').status_code==200

def test_csrf_permissions_and_issues(client):
    admin=login(client)
    # unauthenticated post impossible, and writes require CSRF even logged in
    assert client.post('/api/dhanis',json={'name':'प्रयोग ढाणी','wards':[1]}).status_code==403
    r=client.post('/api/dhanis',json={'name':'प्रयोग ढाणी','wards':[1],'verified':False},headers={'X-CSRF-Token':admin['csrf']});assert r.status_code==200,r.text
    r72=add(client,admin['csrf'],'reporter72','reporter',72)
    r78=add(client,admin['csrf'],'reporter78','reporter',78)
    view=add(client,admin['csrf'],'viewuser','viewer')
    client.post('/api/logout',headers={'X-CSRF-Token':admin['csrf']})
    u72=login(client,'reporter72',r72['temporary_password'])
    issue={'room':72,'category':'queue','note':'परीक्षण कतार'}
    assert client.post('/api/issues',json={**issue,'room':78},headers={'X-CSRF-Token':u72['csrf']}).status_code==403
    r=client.post('/api/issues',json=issue,headers={'X-CSRF-Token':u72['csrf']});assert r.status_code==200,r.text
    idx=r.json()['id'];assert len(client.get('/api/issues').json())==1
    assert client.put('/api/issues/'+str(idx),json={'version':5,'status':'in_progress'},headers={'X-CSRF-Token':u72['csrf']}).status_code==409
    assert client.put('/api/issues/'+str(idx),json={'version':0,'status':'in_progress'},headers={'X-CSRF-Token':u72['csrf']}).status_code==200
    assert client.put('/api/issues/'+str(idx),json={'version':0,'status':'resolved'},headers={'X-CSRF-Token':u72['csrf']}).status_code==409
    assert client.post('/api/official-report',json={'total':30,'source':'आधिकारिक स्रोत','reported_at':'2026-10-20T12:00:00Z'},headers={'X-CSRF-Token':u72['csrf']}).status_code==403
    assert client.get('/api/users').status_code==403
    client.post('/api/logout',headers={'X-CSRF-Token':u72['csrf']})
    u78=login(client,'reporter78',r78['temporary_password'])
    assert client.get('/api/issues').json()==[]
    assert client.put('/api/issues/'+str(idx),json={'version':1,'status':'resolved'},headers={'X-CSRF-Token':u78['csrf']}).status_code==403
    client.post('/api/logout',headers={'X-CSRF-Token':u78['csrf']})
    v=login(client,'viewuser',view['temporary_password'])
    assert client.get('/api/issues').json()==[]
    assert client.post('/api/issues',json=issue,headers={'X-CSRF-Token':v['csrf']}).status_code==403

def test_official_report_and_revoke(client):
    admin=login(client)
    c=add(client,admin['csrf'],'member1','reporter',73)
    official={'total':75,'source':'District RO official 10 AM','reported_at':'2026-10-20T10:00:00+05:30'}
    assert client.post('/api/official-report',json=official,headers={'X-CSRF-Token':admin['csrf']}).status_code==200
    assert client.get('/api/dashboard').json()['official_report']['total']==75
    assert client.post('/api/official-report',json={**official,'total':9999},headers={'X-CSRF-Token':admin['csrf']}).status_code==422
    members=client.get('/api/users').json();mid=next(x['id'] for x in members if x['username']=='member1')
    assert client.patch(f'/api/users/{admin["id"]}/access',json={'active':False},headers={'X-CSRF-Token':admin['csrf']}).status_code==400
    assert client.patch(f'/api/users/{mid}/access',json={'active':False},headers={'X-CSRF-Token':admin['csrf']}).status_code==200
    client.post('/api/logout',headers={'X-CSRF-Token':admin['csrf']})
    assert client.post('/api/login',json={'username':'member1','password':c['temporary_password']}).status_code==401

def test_bulk_and_websocket(client):
    admin=login(client)
    with client.websocket_connect('/ws') as ws:
        assert ws.receive_json()['kind']=='connected'
        r=client.post('/api/issues',json={'room':72,'category':'signage','note':'test'},headers={'X-CSRF-Token':admin['csrf']})
        assert r.status_code==200,r.text
        assert ws.receive_json()['kind']=='issues'
    r=client.post('/api/users/bulk',json={'prefix':'testroom','count':5,'role':'reporter','booth':72},headers={'X-CSRF-Token':admin['csrf']});assert r.status_code==200
    assert 'testroom-001' in r.text
    assert 'temporary_password' in r.text
    assert len(client.get('/api/users').json())==6
    # Reusing prefix must fail atomically, not add partial accounts
    assert client.post('/api/users/bulk',json={'prefix':'testroom','count':8,'role':'reporter','booth':72},headers={'X-CSRF-Token':admin['csrf']}).status_code==409
    assert len(client.get('/api/users').json())==6
