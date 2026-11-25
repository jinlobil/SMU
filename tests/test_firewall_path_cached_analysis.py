import copy
import ipaddress
import json
import time

import pytest

from test_firewall_path_analysis import service,snapshot,rule,nat,interface
from test_firewall_configuration import cached
from backend.services.firewall_path_check import FirewallPathCheckService


def test_reported_office_vpn_flow_never_matches_default_wan_snat(tmp_path,monkeypatch):
    seoul=snapshot();cloud=snapshot()
    seoul['interfaces']=[interface('PortA','101.1.0.1','101.1.0.1/22','LAN'),interface('PortB','192.0.2.1','192.0.2.1/24','WAN')]
    cloud['interfaces']=[interface('PortA','100.1.0.1','100.1.0.1/16','LAN')]
    seoul['routes']=[{'destination':'100.1.0.0','netmask':'16','interface':'xfrm3','gateway':''}]
    cloud['routes']=[{'destination':'101.1.0.0','netmask':'22','interface':'xfrm9','gateway':''}]
    seoul['rules']=[rule('Office VPN Allow',source='Any')]
    cloud['rules']=[rule('VPN LAN Drop',source='Any',action='Drop')]
    record=nat('SNAT');record.update({'Rule Name':'Default SNAT IPv4','Outbound Interface':'PortB'})
    seoul['natRules']=[record]
    current,_=service(tmp_path,monkeypatch,{'Seoul':seoul,'Cloud':cloud})
    result=current.check('101.1.3.50','100.1.2.131','TCP',None)
    assert result['summary']['status']=='BLOCK' and result['summary']['blockedAt']=='Cloud'
    assert result['firewalls'][0]['analysis']['status']=='PASS'
    route=result['firewalls'][0]['routing']['destination']
    assert route['network']=='100.1.0.0/16' and route['interface']=='xfrm3' and route['zone']=='VPN'
    assert not any(step['type'] in {'snat','dnat'} for step in result['analysisPath'])
    assert 'Default SNAT IPv4' not in json.dumps(result['analysisPath'])


@pytest.mark.parametrize('field,value',[('Original Source','198.51.100.0/24'),('Original Destination','198.51.100.10'),('Original Service','other-service'),('Inbound Interface','wrong-port'),('Outbound Interface','wrong-port')])
def test_snat_requires_every_current_flow_selector(tmp_path,monkeypatch,field,value):
    data=snapshot();record=nat('SNAT');record[field]=value;data['natRules']=[record]
    data['services']={'other-service':'Protocol: TCP | Destination: 8443'}
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check('100.1.1.10','203.0.113.10','TCP',443)
    assert not any(step['type']=='snat' for step in result['analysisPath'])
    assert result['summary']['status']=='PASS'
    assert result['analysisPath'][0]['natDecision']=='NAT_NO_MATCH'


def test_wan_masq_applied_and_internal_no_nat_step(tmp_path,monkeypatch):
    data=snapshot();record=nat('SNAT');record['Outbound Interface']='PortB';data['natRules']=[record]
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    wan=current.check('100.1.1.10','203.0.113.10','TCP',443)
    snat=next(step for step in wan['analysisPath'] if step['type']=='snat')
    assert snat['translation']['translated']=='192.0.2.1/32' and snat['status']=='PASS'
    internal=current.check('100.1.1.10','100.1.1.20','TCP',443)
    assert not any(step['type']=='snat' for step in internal['analysisPath'])
    assert internal['summary']['status']=='PASS'
    assert internal['analysisPath'][0]['natDecision']=='NAT_NOT_REQUIRED'


@pytest.mark.parametrize('field,value',[('Original Source','198.51.100.0/24'),('Original Destination','198.51.100.10'),('Original Service','other-service'),('Inbound Interface','wrong-port'),('Outbound Interface','wrong-port')])
def test_dnat_requires_both_interfaces_and_all_address_service_selectors(tmp_path,monkeypatch,field,value):
    data=snapshot();record=nat();record[field]=value;data['natRules']=[record]
    data['objects']={'published':'192.0.2.20','internal':'100.1.1.20'}
    data['services']={'other-service':'Protocol: TCP | Destination: 8443'}
    data['aliases']=[{'Name':'PortB:10','Parent Interface':'PortB','IP Address':'192.0.2.20','CIDR':'192.0.2.20/24','Zone':'WAN'}]
    data['rules']=[rule(source='Any')]
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check('203.0.113.10','192.0.2.20','TCP',443)
    assert not any(step['type']=='dnat' for step in result['analysisPath'])


def test_policy_discovery_preserves_all_matching_rule_provenance_and_actual_priority(tmp_path,monkeypatch):
    data=snapshot();data['objects']={'server':'203.0.113.10','network':'203.0.113.0/24','group':'203.0.113.10\n203.0.113.0/24'}
    data['rules']=[rule('direct',destination='203.0.113.10'),rule('host',destination='server',order=2),rule('network',destination='network',order=3),rule('group',destination='group',order=4),rule('any drop',destination='Any',action='Drop',order=5)]
    for row in data['rules']:row['Destination Resolved']=data['objects'].get(row['Destination Object'],row['Destination Object'])
    current,_=cached(tmp_path,monkeypatch,data)
    result=current.check('','203.0.113.10','TCP',None)
    assert result['policyCount']==5
    assert {ref['rule'] for ref in result['relatedPolicies']}=={'direct','host','network','group','any drop'}
    assert sum(group['policyCount'] for group in result['groups'])>=5
    assert all(group['relatedPolicies'] and group['miniPath']['nodes'] for group in result['groups'])


def test_grouping_never_loses_duplicate_scope_rule_names(tmp_path,monkeypatch):
    data=snapshot();data['rules']=[rule('first',destination='203.0.113.0/24'),rule('second',destination='203.0.113.0/24',order=2)]
    current,_=cached(tmp_path,monkeypatch,data)
    result=current.check('100.1.1.10','','TCP',443)
    assert len(result['groups'])==1
    assert result['groups'][0]['policyCount']==2
    assert {item['rule'] for item in result['groups'][0]['relatedPolicies']}=={'first','second'}


@pytest.mark.parametrize('mode,source,destination',[('PATH','100.1.1.10','203.0.113.10'),('SOURCE_ONLY','100.1.1.10',''),('DESTINATION_ONLY','','203.0.113.10')])
def test_cached_search_benchmark_no_api_or_group_resolution(tmp_path,monkeypatch,record_property,mode,source,destination):
    data=snapshot();data['rules']=[rule('wanted',destination='203.0.113.0/24')]
    data['rules'] += [rule(f'other-{i}',source=f'198.18.{i//256}.{i%256}',destination=f'198.19.{i//256}.{i%256}',order=i+2) for i in range(1000)]
    start=time.perf_counter();current,calls=cached(tmp_path,monkeypatch,data);refresh_ms=(time.perf_counter()-start)*1000
    import backend.services.firewall_configuration as module
    monkeypatch.setattr(module,'normalize_objects',lambda *args:pytest.fail('Object resolution repeated in search'))
    current.configuration.collector=lambda *args:pytest.fail('API collection in search')
    start=time.perf_counter()
    for _ in range(5):result=current.check(source,destination,'TCP',443)
    elapsed=(time.perf_counter()-start)*1000/5
    record_property('mode',mode);record_property('mean_search_ms',round(elapsed,3));record_property('refresh_build_ms',round(refresh_ms,3));record_property('search_api_calls',0)
    assert calls==['Cloud'] and result['metrics']['policy_lookup_ms']>=0


def test_scheduler_uses_configured_interval_and_dedicated_configuration_target(tmp_path,monkeypatch):
    from backend.services.settings import SchedulerService
    from backend.services.refresh import RefreshService
    current,calls=cached(tmp_path,monkeypatch)
    scheduler=SchedulerService(tmp_path,RefreshService(tmp_path));scheduler.firewall_configuration_refresh=current.configuration.refresh
    with scheduler.lock:
        scheduler.state.update(targets=['firewall_configuration'],interval=120)
    scheduler._run_cycle()
    assert calls==['Cloud','Cloud']
    assert scheduler.get()['interval']==120
    assert scheduler.get()['targetStatus']['firewall_configuration']['status']=='SUCCESS'


def test_unresolved_masq_never_displays_identity_translation_as_applied_nat(tmp_path,monkeypatch):
    data=snapshot();data['routes']=[{'destination':'203.0.113.0','netmask':'24','interface':'xfrm3','gateway':''}]
    data['natRules']=[nat('SNAT')]
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check('100.1.1.10','203.0.113.10','TCP',443)
    assert not any(step['type']=='snat' for step in result['analysisPath'])
    assert result['summary']['status']=='UNKNOWN' and 'NAT_UNKNOWN' in result['summary']['primaryReason']
    assert result['progress']['nodes'][-1]['status']=='UNKNOWN'


@pytest.mark.parametrize('query',[('100.1.1.10',''),('','203.0.113.10')])
def test_complete_snapshot_no_policy_is_default_drop_not_unknown(tmp_path,monkeypatch,query):
    data=snapshot();data['rules']=[]
    current,_=cached(tmp_path,monkeypatch,data)
    result=current.check(*query,'TCP',443)
    assert result['groups']==[] and result['summary']['status']=='BLOCK'
    assert '기본 Drop' in result['summary']['primaryReason']


@pytest.mark.parametrize('with_nat',[False,True])
def test_collected_and_persisted_snapshot_have_identical_path_decisions(tmp_path,monkeypatch,with_nat):
    data=snapshot()
    if with_nat:
        data['natRules']=[nat('SNAT')];data['natRules'][0]['Outbound Interface']='PortB'
    direct,_=service(tmp_path,monkeypatch,{'Cloud':data})
    persisted,_=cached(tmp_path,monkeypatch,data)
    a=direct.check('100.1.1.10','203.0.113.10','TCP',443)
    b=persisted.check('100.1.1.10','203.0.113.10','TCP',443)
    def signature(result):return [(step['type'],step['status'],(step.get('matchedRule') or {}).get('rule'),step.get('translation')) for step in result['analysisPath']]
    assert a['summary']['status']==b['summary']['status'] and signature(a)==signature(b)


def test_failed_refresh_preserves_basis_and_reports_stale_without_raw_exception(tmp_path,monkeypatch):
    from backend.services.aws_security_group_path import AwsSecurityGroupPathService
    monkeypatch.setattr(AwsSecurityGroupPathService,'check',lambda *args,**kwargs:{'outbound':{'state':'N/A'},'inbound':{'state':'N/A'}})
    current,_=cached(tmp_path,monkeypatch)
    old=current.configuration.get('Cloud')['checkedAt']
    current.configuration.collector=lambda *args:(_ for _ in ()).throw(TimeoutError('credential SECRET'))
    current.configuration.refresh()
    result=current.check('100.1.1.10','203.0.113.10','TCP',443)
    assert result['configuration']['refreshedAt']==old
    assert result['summary']['status']=='WARNING'
    assert any('이전 정상 Snapshot' in text for text in result['summary']['warnings'])
    assert 'SECRET' not in json.dumps(result)
    restored=FirewallPathCheckService(tmp_path)
    assert restored.configuration.info()['firewalls']['Cloud']['refresh_status']=='failed'
