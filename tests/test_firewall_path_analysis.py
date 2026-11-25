import copy
import ipaddress
from collections import Counter

import pytest

from backend.services.firewall_path_check import FirewallPathCheckService
from backend.services.aws_security_group_path import AwsSecurityGroupPathService


def rule(name='allow', source='100.1.0.0/22', destination='Any', action='Allow', order=1):
    return {'Rule Name':name,'Status':'Enable','Action':action,'Source Object':source,'Source Resolved':source,
            'Destination Object':destination,'Destination Resolved':destination,'Source Zone':'Any','Destination Zone':'Any',
            'Service':'Any','Service Resolved / Protocol / Port':'Any','_Rule Position':str(order)}


def interface(name, address, cidr, zone, gateway=''):
    return {'Name':name,'Hardware':name,'IP Address':address,'CIDR':cidr,'Zone':zone,'Type':'Physical',
            'Gateway Name':gateway,'Gateway IP':'192.0.2.254' if gateway else ''}


def snapshot():
    return {'rules':[rule()], 'routes':[{'destination':'0.0.0.0','netmask':'0','interface':'PortB','gateway':'192.0.2.254'}],
        'routeError':'','checkedAt':'now','configurationErrors':{},'natRules':[],
        'interfaces':[interface('PortA','100.1.0.1','100.1.0.1/22','LAN'),interface('PortB','192.0.2.1','192.0.2.1/24','WAN','GW')],
        'aliases':[], 'zones':[], 'gateways':[{'Name':'GW','Gateway IP':'192.0.2.254','Type':'Active','Weight':'1'}],
        'objects':{},'services':{},'fqdnObjects':{}}


def service(tmp_path, monkeypatch, snapshots=None, aws=True):
    import backend.services.firewall_path_check as module
    original_mapping = module.resolve_input_network
    def mapping(value):
        result = original_mapping(value)
        if str(value).startswith(('192.0.2.', '198.51.100.', '203.0.113.')):
            result = {**result, 'category':'WAN'}
        return result
    monkeypatch.setattr(module, 'resolve_input_network', mapping)
    snapshots = snapshots or {'Cloud':snapshot()}
    result=FirewallPathCheckService(tmp_path);calls=[]
    monkeypatch.setattr(result.firewalls,'configurations',lambda:[{'name':name,'configured':True} for name in snapshots])
    monkeypatch.setattr(result,'_snapshot',lambda config,refresh:calls.append((config['name'],refresh)) or snapshots[config['name']])
    if aws:
        monkeypatch.setattr(AwsSecurityGroupPathService,'check',lambda *a,**k:{
            'outbound':{'kind':'aws_sg','label':'AWS SG Outbound','state':'N/A','reason':'fixture non-AWS'},
            'inbound':{'kind':'aws_sg','label':'AWS SG Inbound','state':'N/A','reason':'fixture non-AWS'}})
    return result,calls


def test_exact_path_pass_configuration_summary_and_legacy_schema(tmp_path,monkeypatch):
    current,calls=service(tmp_path,monkeypatch)
    result=current.check('100.1.1.10','203.0.113.10','TCP',443)
    assert result['mode']=='PATH' and result['summary']['status']=='PASS'
    assert result['summary']['confidence']=='CONFIRMED'
    assert result['analysisPath'][0]['matchedRule']['rule']=='allow'
    assert [step['type'] for step in result['analysisPath']]==['firewall','route','gateway']
    assert 'Status' not in result['analysisPath'][-1]['gateway']
    assert {'source','destination','path','steps','firewalls','policySummary','awsSecurityGroups','checkedAt'}<=result.keys()
    assert result['firewalls'][0]['routing']['returnStatus']=='PASS'
    assert Counter(name for name,refresh in calls)=={'Cloud':1}


@pytest.mark.parametrize('rows,expected,matched',[([rule(action='Drop')],'BLOCK','allow'),([], 'BLOCK',None),
    ([rule('drop',action='Drop',order=1),rule('later',order=2)],'BLOCK','drop'),
    ([rule('first',order=1),rule('later drop',action='Drop',order=2)],'PASS','first')])
def test_drop_priority_default_drop_and_matched_rule_are_distinct(tmp_path,monkeypatch,rows,expected,matched):
    data=snapshot();data['rules']=rows
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check('100.1.1.10','203.0.113.10','TCP',443)
    assert result['summary']['status']==expected
    firewall=next(step for step in result['analysisPath'] if step['type']=='firewall')
    assert (firewall['matchedRule'] or {}).get('rule')==matched
    if expected=='BLOCK':assert result['summary']['blockedAt']=='Cloud'
    assert len(firewall['candidateRules'])==len(rows)


def test_return_route_unknown_and_blackhole_conflict(tmp_path,monkeypatch):
    data=snapshot();data['interfaces'][0]['CIDR']='100.1.0.1/32'
    data['routes'][0]['destination']='203.0.113.0';data['routes'][0]['netmask']='24'
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check('100.1.1.10','203.0.113.10','TCP',443)
    assert result['summary']['status']=='WARNING'
    assert result['firewalls'][0]['routing']['returnStatus']=='UNKNOWN'
    data['routes'].append({'destination':'100.1.0.0','netmask':'22','interface':'PortA','blackhole':'Enable'})
    result=current.check('100.1.1.10','203.0.113.10','TCP',443)
    assert result['summary']['status']=='BLOCK' and result['firewalls'][0]['routing']['returnStatus']=='FAIL'


def nat(kind='DNAT'):
    return {'Rule Name':kind,'Status':'Enable','Position':'Top','After Rule':'','Original Source':'Any',
        'Original Destination':'published' if kind=='DNAT' else 'Any','Original Service':'Any',
        'Translated Destination':'internal' if kind=='DNAT' else 'Original',
        'Translated Source':'Original' if kind=='DNAT' else 'MASQ','Translated Service':'Original',
        'Inbound Interface':'Any','Outbound Interface':'Any','Linked Firewall Rule':''}


def test_dnat_alias_route_policy_and_gateway_use_translated_packet(tmp_path,monkeypatch):
    data=snapshot();data['rules']=[rule(source='Any',destination='100.1.1.20')]
    data['aliases']=[{'Name':'PortB:0','Parent Interface':'PortB','Zone':'WAN','IP Address':'192.0.2.20','CIDR':'192.0.2.20/24','Type':'Alias'}]
    data['natRules']=[nat()];data['objects']={'published':'192.0.2.20','internal':'100.1.1.20'}
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check('203.0.113.9','192.0.2.20','TCP',443)
    steps=result['analysisPath'];dnat=next(step for step in steps if step['type']=='dnat')
    fw=next(step for step in steps if step['type']=='firewall')
    assert dnat['status']=='PASS' and '100.1.1.20/32' in dnat['reason']
    assert fw['matchedRule']['rule']=='allow' and fw['egressZone']=='LAN'
    assert fw['route']['network']=='100.1.0.0/22'
    assert result['details']['destinationOwners'][0]['Parent Interface']=='PortB'


def test_snat_masq_is_a_separate_step_and_records_original_rule(tmp_path,monkeypatch):
    data=snapshot();data['natRules']=[nat('SNAT')]
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check('100.1.1.10','203.0.113.10','TCP',443)
    snat=next(step for step in result['analysisPath'] if step['type']=='snat')
    assert snat['rule']=='SNAT' and snat['reason']=='100.1.1.10/32 → MASQ' and snat['status']=='PASS'


def test_missing_nat_configuration_isolated_and_unsafe_drop_not_asserted(tmp_path,monkeypatch):
    data=snapshot();data['configurationErrors']['NATRule']='Firewall API 500'
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check('100.1.1.10','203.0.113.10','TCP',443)
    assert result['summary']['status']=='WARNING'
    assert result['firewalls'][0]['analysis']['status']=='UNKNOWN'
    assert any('NATRule' in warning for warning in result['summary']['warnings'])


def test_route_blackhole_and_ambiguous_routes_never_pass(tmp_path,monkeypatch):
    data=snapshot();data['routes'][0]['blackhole']='Enable'
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    assert current.check('100.1.1.10','203.0.113.10','TCP',443)['summary']['status']=='BLOCK'
    data['routes'].append({'destination':'0.0.0.0','netmask':'0','interface':'PortA','gateway':'100.1.0.2'})
    result=current.check('100.1.1.10','203.0.113.10','TCP',443)
    assert result['summary']['status']=='WARNING'
    assert result['firewalls'][0]['routing']['destination']['ambiguous'] is True


@pytest.mark.parametrize('source,destination,mode',[('100.1.1.10','','SOURCE_REACHABILITY'),('', '203.0.113.10','DESTINATION_EXPOSURE')])
def test_one_sided_modes_group_networks_without_enumeration(tmp_path,monkeypatch,source,destination,mode):
    data=snapshot();data['rules']=[rule(destination='203.0.113.0/24'),rule('duplicate scope',destination='203.0.113.0/24',order=2)]
    current,calls=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check(source,destination,'TCP',443)
    assert result['mode']==mode and len(result['groups'])==1
    assert result['groups'][0]['networks']==(['203.0.113.0/24'] if source else ['100.1.0.0/22'])
    assert result['groups'][0]['results']
    assert Counter(name for name,refresh in calls)=={'Cloud':1}


def test_any_scope_is_not_expanded_or_asserted_as_internet_wide_pass(tmp_path,monkeypatch):
    current,_=service(tmp_path,monkeypatch)
    result=current.check('100.1.1.10','','TCP',443)
    assert len(result['groups'])==1 and result['groups'][0]['wildcard'] is True
    assert result['groups'][0]['status']=='WARNING' and result['groups'][0]['results']==[]


def test_source_cidr_partial_rule_is_warning_not_global_block(tmp_path,monkeypatch):
    data=snapshot();data['rules']=[rule(source='100.1.1.0/25',destination='203.0.113.0/24')]
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check('100.1.1.0/24','','TCP',443)
    assert result['groups'][0]['status']=='WARNING'
    result=current.check('100.1.1.0/24','203.0.113.10','TCP',443)
    assert result['summary']['status'] in {'WARNING','UNKNOWN'}


def test_destination_exposure_published_dnat_and_internal_reverse_link(tmp_path,monkeypatch):
    data=snapshot();data['rules']=[rule(source='203.0.113.0/24',destination='100.1.1.20')]
    data['natRules']=[nat()];data['objects']={'published':'192.0.2.20','internal':'100.1.1.20'}
    data['aliases']=[{'Name':'PortB:0','Parent Interface':'PortB','Zone':'WAN','IP Address':'192.0.2.20','CIDR':'192.0.2.20/24','Type':'Alias'}]
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    published=current.check('','192.0.2.20','TCP',443)
    assert published['groups'] and any(step['type']=='dnat' for step in published['groups'][0]['results'][0]['analysisPath'])
    internal=current.check('','100.1.1.20','TCP',443)
    assert internal['details']['publishedServices'][0]['publishedVia']=='published'


@pytest.mark.parametrize('addresses,expected',[(['203.0.113.10'],'PASS'),(['203.0.113.10','203.0.113.11'],'PASS'),([], 'UNKNOWN'),(['203.0.113.10','198.51.100.10'],'WARNING')])
def test_fqdn_all_addresses_and_mixed_results(tmp_path,monkeypatch,addresses,expected):
    import backend.services.firewall_path_check as module
    data=snapshot();data['rules']=[rule(destination='203.0.113.0/24')]
    monkeypatch.setattr(module,'resolve_fqdn',lambda _:addresses)
    current,calls=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check('100.1.1.10','fixture.example.test','TCP',443)
    assert result['summary']['status']==expected
    assert result['analyzedPairCount']==len(addresses)
    assert [item['destination'] for item in result['resolvedResults']]==addresses
    assert Counter(name for name,refresh in calls)=={'Cloud':1}


def test_invalid_empty_query_never_collects_and_refresh_memo_is_per_analysis(tmp_path,monkeypatch):
    current,calls=service(tmp_path,monkeypatch)
    with pytest.raises(ValueError):current.check('','')
    assert calls==[]
    current.check('100.1.1.10','','TCP',443,refresh=True)
    assert calls==[('Cloud',True)]


def test_multi_firewall_first_block_and_downstream_sg_not_reached(tmp_path,monkeypatch):
    seoul=snapshot();cloud=snapshot()
    seoul['interfaces']=[interface('LAN','101.1.0.1','101.1.0.1/22','LAN'),interface('Transit','192.0.2.1','192.0.2.1/30','VPN')]
    cloud['interfaces']=[interface('LAN','100.1.0.1','100.1.0.1/22','LAN'),interface('Transit','192.0.2.2','192.0.2.2/30','VPN')]
    seoul['routes']=[{'destination':'100.1.0.0','netmask':'22','interface':'Transit','gateway':'192.0.2.2'}]
    cloud['routes']=[{'destination':'101.1.0.0','netmask':'22','interface':'Transit','gateway':'192.0.2.1'}]
    seoul['rules']=[rule('Seoul allow',source='Any')];cloud['rules']=[rule('Cloud drop',source='Any',action='Drop')]
    current,calls=service(tmp_path,monkeypatch,{'Seoul':seoul,'Cloud':cloud})
    monkeypatch.setattr(AwsSecurityGroupPathService,'check',lambda *a,**k:{
        'outbound':{'label':'AWS SG Outbound','state':'N/A','reason':'fixture'},
        'inbound':{'label':'AWS SG Inbound','state':'FAIL','reason':'SG no allow'}})
    result=current.check('101.1.0.50','100.1.1.10','TCP',443)
    assert result['summary']['status']=='BLOCK' and result['summary']['blockedAt']=='Cloud'
    assert result['firewalls'][0]['analysis']['status']=='PASS'
    assert result['analysisPath'][-1]['type']=='aws_sg' and result['analysisPath'][-1]['reached'] is False
    assert 'Not reached' in result['analysisPath'][-1]['notReachedReason']
    assert Counter(name for name,refresh in calls)=={'Seoul':1,'Cloud':1}


def test_snat_does_not_erase_original_source_sg_evaluation(tmp_path,monkeypatch):
    data=snapshot();data['natRules']=[nat('SNAT')]
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    observed=[]
    def sg(_self,source,destination,*args,**kwargs):
        observed.append(str(source))
        return {'outbound':{'label':'AWS SG Outbound','state':'PASS' if str(source)=='100.1.1.10/32' else 'N/A','reason':'original source SG'},
                'inbound':{'label':'AWS SG Inbound','state':'PASS','reason':str(source)}}
    monkeypatch.setattr(AwsSecurityGroupPathService,'check',sg)
    result=current.check('100.1.1.10','203.0.113.10','TCP',443)
    assert observed==['100.1.1.10/32','192.0.2.1/32']
    assert result['awsSecurityGroups']['outbound']['state']=='PASS'
    assert result['awsSecurityGroups']['inbound']['reason']=='192.0.2.1/32'


def test_actual_snapshot_reuses_export_parsers_and_refresh_only_once_per_analysis(tmp_path,monkeypatch):
    from backend.services.firewall import FirewallClient
    import backend.services.firewall_path_check as module
    from test_firewall_network_export import PAYLOADS
    client_calls=[]
    xml='<Response><Status code="200">OK</Status><FirewallRule><Name>fixture allow</Name><Status>Enable</Status><NetworkPolicy><Action>Accept</Action></NetworkPolicy></FirewallRule></Response>'
    monkeypatch.setattr(FirewallClient,'get_rules_compatible',lambda self:client_calls.append('Rule') or {'raw':xml,'entity':'FirewallRule','apiVersion':'2000.2'})
    def get(_self,entity):
        client_calls.append(entity)
        if entity=='NATRule':raise RuntimeError('Firewall API 500: PRIVATE secret authorization dump')
        return PAYLOADS[entity]
    monkeypatch.setattr(FirewallClient,'get',get)
    monkeypatch.setattr(module,'resolve_fqdn',lambda _:['203.0.113.10','203.0.113.11'])
    current=FirewallPathCheckService(tmp_path)
    config={'name':'Cloud','configured':True,'host':'example.test','port':'4444','username':'fixture','password':'secret','verify_ssl':False}
    monkeypatch.setattr(current.firewalls,'configurations',lambda:[config])
    result=current.check('100.1.1.10','fixture.example.test','TCP',443,refresh=True)
    assert len(result['resolvedResults'])==2
    assert set(Counter(client_calls).values())=={1}
    assert {'Rule','NATRule','Interface','Alias','Zone','GatewayConfiguration','UnicastRoute'}<=set(client_calls)
    import json
    assert 'PRIVATE' not in json.dumps(result) and 'secret' not in json.dumps(result)


def test_api_supports_three_modes_and_rejects_empty_pair(tmp_path,monkeypatch):
    from fastapi.testclient import TestClient
    import backend.app as app
    current,_=service(tmp_path,monkeypatch)
    monkeypatch.setattr(app,'firewall_path_check_service',current)
    client=TestClient(app.app)
    for source,destination,mode in [('100.1.1.10','203.0.113.10','PATH'),('100.1.1.10','','SOURCE_REACHABILITY'),('','203.0.113.10','DESTINATION_EXPOSURE')]:
        response=client.post('/api/firewall/path-check',json={'source':source,'destination':destination,'protocol':'TCP','port':443})
        assert response.status_code==200 and response.json()['data']['mode']==mode
    assert client.post('/api/firewall/path-check',json={'source':'','destination':''}).status_code==400


def test_unresolved_rule_object_does_not_prove_allow_or_default_drop(tmp_path, monkeypatch):
    data = snapshot()
    unresolved = rule('unresolved drop', source='unresolved-host', action='Drop')
    unresolved['Source Resolved'] = ''
    data['rules'] = [unresolved, rule(order=2)]
    current, _ = service(tmp_path, monkeypatch, {'Cloud': data})
    result = current.check('100.1.1.10', '203.0.113.10', 'TCP', 443)
    assert result['analysisPath'][0]['status'] == 'UNKNOWN'
    assert result['summary']['status'] != 'PASS'
    assert 'resolvedObjects' in result['details']


def test_inferred_zone_mismatch_is_not_a_definitive_firewall_block(tmp_path, monkeypatch):
    data = snapshot()
    data['interfaces'] = []
    data['rules'] = []
    current, _ = service(tmp_path, monkeypatch, {'Cloud': data})
    result = current.check('100.1.1.10', '203.0.113.10', 'TCP', 443)
    assert result['summary']['status'] != 'BLOCK'
    assert result['analysisPath'][0]['confidence'] == 'INFERRED'
