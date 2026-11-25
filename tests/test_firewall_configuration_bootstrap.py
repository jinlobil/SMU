"""Cold-start refresh through real routes, Collector and parsers; only HTTPS transport is mocked."""
import copy
import io
import json
import threading
import time
import urllib.error
import xml.etree.ElementTree as ET
from collections import Counter

import pytest
from fastapi.testclient import TestClient

from backend.services.firewall import FIREWALL_DEFINITIONS, FirewallClient
from backend.services.firewall_path_check import FirewallPathCheckService
from backend.services.firewall_rule_export import ENTITIES
from test_firewall_rule_export import env

NAMES=tuple(FIREWALL_DEFINITIONS)
ENTITY_NAMES=('FirewallRule',*ENTITIES,'UnicastRoute','NATRule','Interface','Alias','Zone','GatewayConfiguration')
OK='<Response><Status code="200">OK</Status></Response>'


@pytest.fixture
def native(tmp_path,monkeypatch):
    env(tmp_path)
    payloads={entity:OK for entity in ENTITY_NAMES}
    payloads['FirewallRule']='<Response><Status code="200">OK</Status><FirewallRule><Name>Fixture Allow</Name><Status>Enable</Status><Position>1</Position><NetworkPolicy><Action>Accept</Action></NetworkPolicy></FirewallRule></Response>'
    payloads['Interface']='<Response><Status code="200">OK</Status><Interface><Name>LAN</Name><Hardware>LAN</Hardware><IPAddress>10.0.0.1</IPAddress><Netmask>255.255.255.0</Netmask><NetworkZone>LAN</NetworkZone></Interface><Interface><Name>WAN</Name><Hardware>WAN</Hardware><IPAddress>192.0.2.1</IPAddress><Netmask>255.255.255.0</Netmask><NetworkZone>WAN</NetworkZone></Interface></Response>'
    payloads['UnicastRoute']='<Response><Status code="200">OK</Status><UnicastRoute><Destination>0.0.0.0</Destination><Netmask>0.0.0.0</Netmask><Interface>WAN</Interface><Gateway>192.0.2.254</Gateway></UnicastRoute></Response>'
    calls=[];state={'hook':None,'overrides':{}}
    def post(client,request):
        entity=list(ET.fromstring(request).find('Get'))[0].tag
        calls.append((client.name,entity))
        if state['hook']:state['hook'](client.name,entity)
        return state['overrides'].get((client.name,entity),payloads[entity])
    monkeypatch.setattr(FirewallClient,'_post_xml',post)
    current=FirewallPathCheckService(tmp_path)
    import backend.app as app
    monkeypatch.setattr(app,'firewall_path_check_service',current)
    monkeypatch.setattr(app,'firewall_service',current.firewalls)
    return current,TestClient(app.app),calls,state


def finished(client):
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
        response=client.get('/api/firewall/configuration/status')
        assert response.status_code==200
        state=response.json()['data']
        assert isinstance(state['running'],bool)
        if not state['running']:return state
        time.sleep(.01)
    pytest.fail('refresh did not finish')


def test_zero_snapshot_refresh_uses_online_collector_all_four_devices_and_keeps_legacy_get(native,tmp_path,monkeypatch):
    current,client,calls,state=native
    assert not current.configuration.directory.exists()
    # An accidental call into the Snapshot-only reader during refresh must fail.
    monkeypatch.setattr(current,'_snapshot',lambda *args:pytest.fail('refresh used Snapshot-only guard'))
    assert client.post('/api/firewall/configuration/refresh').status_code==202
    status=finished(client)
    assert all(status['firewalls'][name]['refresh_status']=='success' for name in NAMES)
    assert Counter(calls)==Counter((name,entity) for name in NAMES for entity in ENTITY_NAMES)
    for name in NAMES:
        path=current.configuration.path(name)
        assert path.exists()
        payload=json.loads(path.read_text())
        assert payload['rules'][0]['Rule Name']=='Fixture Allow'
        assert current.configuration.index(name).snapshot_id==payload['metadata']['snapshot_id']
    legacy=client.get('/api/firewall/configuration').json()['data']
    assert isinstance(legacy['firewalls'],list) and 'running' not in legacy
    assert all(item['configured'] for item in legacy['firewalls'])
    import backend.app as app
    routes=[(route.path,method) for route in app.app.routes for method in getattr(route,'methods',())]
    assert len(routes)==len(set(routes))


def test_refresh_stage_order_and_analysis_stays_offline_after_bootstrap(native,monkeypatch):
    current,client,calls,state=native;events=[]
    import backend.services.firewall_configuration as module
    from backend.services.refresh import RefreshService
    original_validate=module.validate;original_index=module.ConfigurationIndex;original_save=RefreshService.save_json_atomic
    def validate(snapshot,**kwargs):
        events.append(('validate',snapshot['metadata']['firewall']))
        return original_validate(snapshot,**kwargs)
    def save(self,path,payload):
        if path.name!='status.json':events.append(('save',payload['metadata']['firewall']))
        return original_save(self,path,payload)
    def index(snapshot):
        events.append(('index',snapshot['metadata']['firewall']))
        return original_index(snapshot)
    monkeypatch.setattr(module,'validate',validate);monkeypatch.setattr(module,'ConfigurationIndex',index)
    monkeypatch.setattr(RefreshService,'save_json_atomic',save)
    client.post('/api/firewall/configuration/refresh');finished(client)
    assert events==[(stage,name) for name in NAMES for stage in ('validate','save','index')]
    count=len(calls)
    result=client.post('/api/firewall/path-check',json={'source':'10.0.0.10','destination':'203.0.113.10','protocol':'TCP','port':443}).json()['data']
    assert len(calls)==count
    assert result['configuration']['refreshedAt']
    assert len(result['configuration']['snapshots'])==4


@pytest.mark.parametrize('kind,expected',[('http',403),('api','529')])
def test_entity_http_api_failures_are_diagnosed_safely_and_other_devices_bootstrap(native,caplog,kind,expected):
    current,client,calls,state=native
    marker='DO_NOT_LOG_CREDENTIAL_OR_BODY'
    if kind=='http':
        def hook(name,entity):
            if name=='Seoul' and entity=='NATRule':
                raise urllib.error.HTTPError('https://private.invalid/?password='+marker,403,marker,None,io.BytesIO(marker.encode()))
        state['hook']=hook
    else:state['overrides'][('Seoul','NATRule')]=f'<Response><Status code="529">{marker}</Status></Response>'
    client.post('/api/firewall/configuration/refresh');status=finished(client)
    failure=status['firewalls']['Seoul']
    assert failure['refresh_status']=='failed'
    diagnostic=next(item for item in failure['diagnostics'] if item['entity']=='NATRule')
    assert diagnostic['firewall']=='Seoul'
    assert diagnostic['http_status' if kind=='http' else 'api_code']==expected
    assert diagnostic['stage']=='api_request' if kind=='http' else diagnostic['stage']=='response_validation'
    assert all(current.configuration.path(name).exists() for name in NAMES if name!='Seoul')
    assert not current.configuration.path('Seoul').exists()
    assert 'entity=NATRule' in caplog.text and f"{'http_status' if kind=='http' else 'api_code'}={expected}" in caplog.text
    assert marker not in caplog.text+json.dumps(status)
    assert marker not in ''.join(path.read_text() for path in current.configuration.directory.glob('*.json'))


def test_unconfigured_devices_are_reported_instead_of_silently_skipped(native,monkeypatch,caplog):
    current,client,calls,state=native
    configs=current.firewalls.configurations()
    configs[0]['configured']=False;configs[0]['password']=''
    monkeypatch.setattr(current.firewalls,'configurations',lambda:configs)
    client.post('/api/firewall/configuration/refresh');status=finished(client)
    missing=status['firewalls'][configs[0]['name']]
    assert missing['error_code']=='configuration_missing'
    assert missing['diagnostics'][0]['missing_fields']==['password']
    assert not any(name==configs[0]['name'] for name,entity in calls)
    assert 'configuration_missing' in caplog.text


def test_index_failure_after_save_rolls_back_previous_snapshot(native,monkeypatch):
    current,client,calls,state=native
    client.post('/api/firewall/configuration/refresh');finished(client)
    before={name:current.configuration.path(name).read_bytes() for name in NAMES}
    previous=dict(current.configuration.snapshots)
    import backend.services.firewall_configuration as module
    monkeypatch.setattr(module,'ConfigurationIndex',lambda *args:(_ for _ in ()).throw(ValueError('index_version_mismatch')))
    client.post('/api/firewall/configuration/refresh');status=finished(client)
    for name in NAMES:
        assert current.configuration.get(name) is previous[name]
        assert current.configuration.path(name).read_bytes()==before[name]
        assert status['firewalls'][name]['diagnostics'][0]['stage']=='index_build'


def test_click_latest_information_bootstraps_without_any_snapshot_files(native):
    current,client,calls,state=native
    from test_firewall_path_layout_browser import path_browser
    from playwright.sync_api import expect
    entered=threading.Event();release=threading.Event()
    def hold(name,entity):
        if not entered.is_set():entered.set();assert release.wait(5)
    state['hook']=hold
    initial=current.check('10.0.0.10','203.0.113.10','TCP',443)
    assert calls==[] and not current.configuration.directory.exists()
    try:
        with path_browser(initial) as page:
            def bridge(route):
                from urllib.parse import urlsplit
                request=route.request
                response=client.request(request.method,urlsplit(request.url).path,json=request.post_data_json if request.post_data else None)
                route.fulfill(status=response.status_code,json=response.json())
            page.route('**/api/firewall/**',bridge)
            page.get_by_role('button',name='최신 정보 다시 조회',exact=True).click()
            assert entered.wait(2)
            expect(page.get_by_role('button',name='최신 정보 조회 중...',exact=True)).to_be_disabled()
            assert client.get('/api/firewall/configuration/status').json()['data']['running'] is True
            assert not any(current.configuration.path(name).exists() for name in NAMES)
            release.set()
            expect(page.get_by_role('button',name='최신 정보 다시 조회',exact=True)).to_be_enabled(timeout=10000)
            expect(page.locator('.topbar')).not_to_contain_text('저장된 Snapshot 없음')
            assert all(current.configuration.path(name).exists() for name in NAMES)
            assert Counter(calls)==Counter((name,entity) for name in NAMES for entity in ENTITY_NAMES)
    finally:release.set()


def test_configuration_load_failure_is_reported_for_each_device(native,monkeypatch,caplog):
    current,client,calls,state=native
    def unreadable():raise PermissionError('DO_NOT_LOG_PRIVATE_PATH_OR_CREDENTIAL')
    monkeypatch.setattr(current.firewalls,'configurations',unreadable)
    client.post('/api/firewall/configuration/refresh');status=finished(client)
    assert calls==[]
    for name in NAMES:
        failure=status['firewalls'][name]
        assert failure['refresh_status']=='failed'
        assert failure['diagnostics'][0]['stage']=='configuration_load'
        assert failure['diagnostics'][0]['reason']=='permission_denied'
    assert 'DO_NOT_LOG' not in caplog.text+json.dumps(status)
