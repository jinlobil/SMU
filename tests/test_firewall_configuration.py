import copy
import ipaddress
import json
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from backend.services.firewall_configuration import ConfigurationIndex, FirewallConfigurationStore, normalize_objects, validate_response
from backend.services.firewall_path_check import FirewallPathCheckService
from backend.services.firewall import FirewallClient
from test_firewall_path_analysis import snapshot, rule, interface, nat, service


def cached(tmp_path,monkeypatch,data=None,names=('Cloud',)):
    current=FirewallPathCheckService(tmp_path)
    monkeypatch.setattr(current.firewalls,'configurations',lambda:[{'name':name,'configured':True} for name in names])
    calls=[]
    def collect(config,refresh):calls.append(config['name']);return copy.deepcopy(data or snapshot())
    current.configuration.collector=collect
    current.configuration.refresh()
    return current,calls


def test_snapshot_persisted_reloaded_and_index_version_consistent(tmp_path,monkeypatch):
    current,calls=cached(tmp_path,monkeypatch)
    path=tmp_path/'cache/firewall_config/cloud.json'
    assert path.exists() and calls==['Cloud']
    second=FirewallPathCheckService(tmp_path)
    snapshot=second.configuration.get('Cloud')
    assert snapshot['metadata']['snapshot_id']==current.configuration.index('Cloud').snapshot_id
    assert second.configuration.index('Cloud').snapshot_id==snapshot['metadata']['snapshot_id']
    monkeypatch.setattr(FirewallClient,'get',lambda *args:pytest.fail('normal analysis called API'))
    result=second.check('100.1.1.10','203.0.113.10','TCP',443)
    assert result['configuration']['refreshedAt']==snapshot['metadata']['refreshed_at']


def test_first_run_without_snapshot_returns_precise_unknown_without_api(tmp_path,monkeypatch):
    current=FirewallPathCheckService(tmp_path)
    monkeypatch.setattr(FirewallClient,'get',lambda *args:pytest.fail('normal analysis called API'))
    result=current.check('100.1.1.10','203.0.113.10','TCP',443)
    assert result['summary']['status']=='UNKNOWN'
    assert result['configuration']['refreshedAt'] is None


@pytest.mark.parametrize('query',[('100.1.1.10','203.0.113.10'),('100.1.1.10',''),('','203.0.113.10')])
def test_all_modes_call_zero_configuration_api_with_normal_snapshot(tmp_path,monkeypatch,query):
    data=snapshot();data['rules']=[rule(destination='203.0.113.0/24')]
    current,calls=cached(tmp_path,monkeypatch,data)
    monkeypatch.setattr(FirewallClient,'get',lambda *args:pytest.fail('normal analysis called API'))
    index=current.configuration.index('Cloud')
    for _ in range(3):
        result=current.check(*query,'TCP',443)
        assert result['configuration']['snapshots']['Cloud']==index.snapshot_id
        assert result['metrics']['total_ms']>=0
    assert calls==['Cloud']
    assert current.configuration.index('Cloud') is index


@pytest.mark.parametrize('failure',['exception','partial','empty','save'])
def test_failure_keeps_previous_disk_snapshot_and_memory_index(tmp_path,monkeypatch,failure):
    current,_=cached(tmp_path,monkeypatch)
    store=current.configuration;old=store.get('Cloud');index=store.index('Cloud')
    path=store.path('Cloud');before=path.read_bytes()
    def collect(*args):
        if failure=='exception':raise RuntimeError('private credential must not be reported')
        value=snapshot()
        if failure=='partial':value['configurationErrors']={'NATRule':'partial'}
        if failure=='empty':value['rules']=[]
        return value
    store.collector=collect
    if failure=='save':
        from backend.services.refresh import RefreshService
        monkeypatch.setattr(RefreshService,'save_json_atomic',lambda *args:(_ for _ in ()).throw(OSError('secret')))
    status=store.refresh()
    assert store.get('Cloud') is old and store.index('Cloud') is index
    assert path.read_bytes()==before
    assert status['firewalls']['Cloud']['refresh_status']=='failed'
    assert 'secret' not in json.dumps(status) and 'credential' not in json.dumps(status)


def test_per_firewall_partial_failure_preserves_failed_site(tmp_path,monkeypatch):
    current,_=cached(tmp_path,monkeypatch,names=('Cloud','Seoul'))
    store=current.configuration;old=dict(store.snapshots)
    def collect(config,*args):
        if config['name']=='Seoul':raise TimeoutError()
        return snapshot()
    store.collector=collect;store.refresh()
    assert store.get('Seoul') is old['Seoul'] and store.get('Cloud') is not old['Cloud']


def test_search_during_refresh_and_atomic_generation_swap(tmp_path,monkeypatch):
    current,_=cached(tmp_path,monkeypatch)
    store=current.configuration;before=store.get('Cloud');entered=threading.Event();release=threading.Event();calls=[]
    def collect(*args):
        calls.append(1);entered.set();assert release.wait(5)
        value=snapshot();value['rules']=[rule('new Rule')];return value
    store.collector=collect
    store.start_refresh();assert entered.wait(2)
    store.start_refresh();store.start_refresh()
    analysis=current.check('100.1.1.10','203.0.113.10','TCP',443)
    assert analysis['configuration']['snapshots']['Cloud']==before['metadata']['snapshot_id']
    assert store.get('Cloud') is before
    release.set()
    deadline=time.monotonic()+5
    while store.info()['running'] and time.monotonic()<deadline:time.sleep(.005)
    assert len(calls)==1 and store.get('Cloud') is not before
    assert store.index('Cloud').snapshot_id==store.get('Cloud')['metadata']['snapshot_id']
    assert not store.path('Cloud').with_suffix('.json.tmp').exists()


@pytest.mark.parametrize('raw',['<Response totalrecords="3"><IPHost><Name>a</Name></IPHost></Response>', '<Response hasmore="true"/>','<Response><NextToken>next</NextToken></Response>','<Response>'])
def test_truncated_or_partial_response_is_rejected(raw):
    with pytest.raises((ValueError,ET.ParseError)):validate_response(raw,'IPHost')


def test_nested_groups_services_and_cycle_protection_use_export_helpers():
    value=snapshot()
    payloads={
        'IPHost':'<Response><IPHost><Name>host</Name><HostType>IP</HostType><IPAddress>192.0.2.10</IPAddress></IPHost><IPHost><Name>network</Name><HostType>Network</HostType><IPAddress>192.0.2.0</IPAddress><Subnet>255.255.255.0</Subnet></IPHost></Response>',
        'IPHostGroup':'<Response><IPHostGroup><Name>inner</Name><HostList><Host>host</Host><Host>network</Host></HostList></IPHostGroup><IPHostGroup><Name>outer</Name><HostList><Host>inner</Host></HostList></IPHostGroup><IPHostGroup><Name>cycle-a</Name><HostList><Host>cycle-b</Host></HostList></IPHostGroup><IPHostGroup><Name>cycle-b</Name><HostList><Host>cycle-a</Host></HostList></IPHostGroup></Response>',
        'Services':'<Response><Services><Name>https</Name><ServiceDetails><ServiceDetail><Protocol>TCP</Protocol><DestinationPort>443</DestinationPort></ServiceDetail></ServiceDetails></Services></Response>',
        'ServiceGroup':'<Response><ServiceGroup><Name>web</Name><ServiceList><Service>https</Service></ServiceList></ServiceGroup><ServiceGroup><Name>all-web</Name><ServiceList><Service>web</Service></ServiceList></ServiceGroup></Response>'}
    value['rules']=[rule(source='outer',destination='Any')]
    value['rules'][0]['Service']='all-web'
    normalize_objects(payloads,value)
    assert value['expandedObjectGroups']['outer']==['host','network']
    assert '192.0.2.10' in value['rules'][0]['Source Resolved']
    assert '443' in value['rules'][0]['Service Resolved / Protocol / Port']
    assert value['normalizationWarnings']==['group_cycle']
    index=ConfigurationIndex(value)
    assert index.rules('Source',ipaddress.ip_network('192.0.2.10'))=={0}
    assert 'outer' in index.hostObjects.find(ipaddress.ip_network('192.0.2.10'))
    assert 'outer' in index.objectParents['host']
    assert index.services['all-web']=={0} and index.serviceParents['https']=={'web','all-web'}
    assert index.rules('Destination',ipaddress.ip_network('198.51.100.10'))=={0}


@pytest.mark.parametrize('field',['Original Source','Original Destination','Translated Source','Translated Destination'])
def test_all_nat_address_directions_indexed(field):
    value=snapshot();record=nat();record[field]='192.0.2.0/24';value['natRules']=[record]
    index=ConfigurationIndex(value)
    assert index.nat[field].find(ipaddress.ip_network('192.0.2.10'))=={0}


def test_refresh_endpoints_and_normal_analysis_api(tmp_path,monkeypatch):
    from fastapi.testclient import TestClient
    import backend.app as app
    current,calls=cached(tmp_path,monkeypatch)
    monkeypatch.setattr(app,'firewall_path_check_service',current)
    client=TestClient(app.app)
    assert client.get('/api/firewall/configuration').status_code==200
    assert client.post('/api/firewall/path-check',json={'source':'100.1.1.10','destination':'203.0.113.10','protocol':'TCP','port':443}).status_code==200
    assert calls==['Cloud']
    assert client.post('/api/firewall/configuration/refresh').status_code==202
    deadline=time.monotonic()+5
    while current.configuration.info()['running'] and time.monotonic()<deadline:time.sleep(.005)
    assert calls==['Cloud','Cloud']


@pytest.mark.parametrize('bad',[{'metadata':[]},{'objects':{'bad':[]}}, {'rules':[{'Rule Name':'bad','Source Object':[]}]},{'fqdnObjects':{'bad':'string-not-array'}}])
def test_corrupt_snapshot_does_not_break_backend_startup(tmp_path,monkeypatch,bad):
    current,_=cached(tmp_path,monkeypatch)
    data=json.loads(current.configuration.path('Cloud').read_text())
    data.update(bad);current.configuration.path('Cloud').write_text(json.dumps(data))
    restored=FirewallPathCheckService(tmp_path)
    assert restored.configuration.get('Cloud') is None


def test_input_fqdn_and_objects_use_collected_dns_without_query_dns_calls(tmp_path,monkeypatch):
    import backend.services.firewall_path_check as module
    data=snapshot();data['resolvedFqdnAddresses']={'cached.example.test':['203.0.113.10']}
    current,_=cached(tmp_path,monkeypatch,data)
    monkeypatch.setattr(module,'resolve_fqdn',lambda *args:pytest.fail('DNS repeated for cached FQDN'))
    result=current.check('100.1.1.10','cached.example.test','TCP',443)
    assert result['destination']['resolvedIps']==['203.0.113.10']


@pytest.mark.parametrize('query',[('100.1.1.10','203.0.113.10'),('100.1.1.10',''),('','203.0.113.10')])
def test_search_never_rebuilds_a_normal_memory_index(tmp_path,monkeypatch,query):
    data=snapshot();data['rules']=[rule(destination='203.0.113.0/24')]
    current,_=cached(tmp_path,monkeypatch,data)
    import backend.services.firewall_configuration as module
    monkeypatch.setattr(module,'ConfigurationIndex',lambda *args:pytest.fail('Index rebuilt in search'))
    current.check(*query,'TCP',443)


def test_multi_site_refresh_publishes_memory_only_when_whole_batch_finishes(tmp_path,monkeypatch):
    current,_=cached(tmp_path,monkeypatch,names=('Cloud','Seoul'))
    store=current.configuration;old=dict(store.snapshots);entered=threading.Event();release=threading.Event()
    def collect(config,*args):
        if config['name']=='Seoul':entered.set();assert release.wait(5)
        data=snapshot();data['rules']=[rule('new '+config['name'])];return data
    store.collector=collect;store.start_refresh();assert entered.wait(2)
    assert store.get('Cloud') is old['Cloud'] and store.get('Seoul') is old['Seoul']
    release.set();deadline=time.monotonic()+5
    while store.info()['running'] and time.monotonic()<deadline:time.sleep(.005)
    assert all(store.get(name) is not old[name] for name in old)
    assert all(store.index(name).snapshot_id==store.get(name)['metadata']['snapshot_id'] for name in old)
