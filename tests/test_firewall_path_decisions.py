"""Configuration-backed scenarios; no calls to operating firewalls."""
import copy
import ipaddress

import pytest

from test_firewall_path_analysis import service, snapshot, rule, nat, interface
from backend.services.firewall_path_decisions import decide_policy


def svc(row, port, protocol='TCP'):
    row.update(Service=f'{protocol}-{port}', **{'Service Resolved / Protocol / Port':f'Protocol: {protocol} | Source: 1:65535 | Destination: {port}'})
    return row


def check(tmp_path, monkeypatch, data=None, port=443):
    current,_=service(tmp_path,monkeypatch,{'Cloud':data or snapshot()})
    return current.check('100.1.1.10','203.0.113.10','TCP',port)


@pytest.mark.parametrize('port',[None,'ANY'])
def test_any_service_drop_is_block_without_port_and_all_following_not_reached(tmp_path,monkeypatch,port):
    data=snapshot();data['rules']=[rule('first Drop',action='Drop'),svc(rule('later allow',order=2),443)]
    result=check(tmp_path,monkeypatch,data,port)
    assert result['summary']['status']=='BLOCK'
    assert result['summary']['matchedRule']=='first Drop'
    assert result['serviceResults'][0]['fromPort']==1 and result['serviceResults'][0]['toPort']==65535
    assert all(step['status']=='NOT_REACHED' for step in result['analysisPath'][1:])
    assert result['progress']['nodes'][-1]['status']=='NOT_REACHED'
    assert all(not link['active'] for link in result['progress']['links'][1:])


def test_tcp_any_partitions_priority_and_mixed_results(tmp_path,monkeypatch):
    data=snapshot();data['rules']=[svc(rule('HTTPS'),443),rule('Drop rest',action='Drop',order=2)]
    result=check(tmp_path,monkeypatch,data,None)
    assert result['summary']['status']=='WARNING'
    assert '서비스별 결과 상이' in result['summary']['primaryReason']
    cases=result['serviceResults']
    assert [(case['fromPort'],case['toPort'],case['summary']['status']) for case in cases]==[(1,442,'BLOCK'),(443,443,'PASS'),(444,65535,'BLOCK')]
    assert cases[1]['analysisPath'][0]['matchedRule']['rule']=='HTTPS'


def test_service_group_does_not_cross_protocol_port_members(tmp_path,monkeypatch):
    data=snapshot();data['rules']=[svc(rule('group'),443)]
    data['rules'][0]['Service Resolved / Protocol / Port']+='\nProtocol: UDP | Destination: 53'
    assert check(tmp_path,monkeypatch,data,53)['summary']['status']=='BLOCK'
    assert check(tmp_path,monkeypatch,data,443)['summary']['status']=='PASS'


def test_all_protocols_any_drop_covers_tcp_udp_and_other_ip(tmp_path,monkeypatch):
    data=snapshot();data['rules']=[rule(action='Drop')]
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check('100.1.1.10','203.0.113.10','ANY')
    assert result['summary']['status']=='BLOCK'
    assert {item['protocol'] for item in result['serviceResults']}=={'TCP','UDP','ICMP','ICMPV6','IP'}
    numbers=[number for item in result['serviceResults'] for number in item.get('protocolNumbers',[])]
    assert set(numbers)==set(range(256))-{1,6,17,58}


def test_top_after_chain_chooses_rule_not_xml_order(tmp_path,monkeypatch):
    data=snapshot()
    first=rule('first Drop',action='Drop');first.update(_Rule_Position='unused')
    first['_Rule Position']='Top'
    later=rule('later Allow');later.update({'_Rule Position':'After','_Rule After':'first Drop'})
    data['rules']=[later,first]
    result=check(tmp_path,monkeypatch,data)
    assert result['summary']['status']=='BLOCK' and result['summary']['matchedRule']=='first Drop'


def test_missing_object_below_selected_rule_cannot_make_unknown(tmp_path,monkeypatch):
    data=snapshot();missing=rule('missing later',source='missing-object',order=2)
    missing['Source Resolved']=''
    data['rules'].append(missing)
    assert check(tmp_path,monkeypatch,data)['summary']['status']=='PASS'


def test_connected_network_from_ip_netmask_without_cidr_or_static(tmp_path,monkeypatch):
    data=snapshot();data['routes']=[]
    data['interfaces']=[{'Name':'LAN','IP Address':'100.1.0.1','Netmask':'255.255.252.0','Zone':'LAN'}]
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check('100.1.1.10','100.1.1.20','TCP',443)
    fw=result['analysisPath'][0]
    assert result['summary']['status']=='PASS'
    assert fw['route']['routeType']=='Connected' and fw['route']['zone']=='LAN'
    assert fw['returnRoute']['route']['routeType']=='Connected'
    assert fw['natStatus']=='NOT_REQUIRED'


def test_lpm_route_then_gateway_config_without_live_health_claim(tmp_path,monkeypatch):
    data=snapshot();data['routes'] += [
        {'destination':'203.0.0.0','netmask':'16','interface':'PortA'},
        {'destination':'203.0.113.0','netmask':'24','interface':'PortB','gateway':'192.0.2.254'}]
    result=check(tmp_path,monkeypatch,data)
    route=next(step for step in result['analysisPath'] if step['type']=='route')
    gateway=next(step for step in result['analysisPath'] if step['type']=='gateway')
    assert route['route']['network']=='203.0.113.0/24' and route['route']['routeType']=='Static'
    assert gateway['configurationOnly'] is True and '설정 기준' in gateway['reason']


def test_static_distance_breaks_equal_prefix_tie(tmp_path,monkeypatch):
    data=snapshot();data['routes'][0]['distance']='10'
    data['routes'].append({'destination':'0.0.0.0','netmask':'0','interface':'PortA','distance':'20'})
    result=check(tmp_path,monkeypatch,data)
    assert result['summary']['status']=='PASS'
    assert not result['analysisPath'][0]['route'].get('ambiguous')


def test_xfrm_without_gateway_is_valid_static_vpn_route(tmp_path,monkeypatch):
    data=snapshot();data['routes']=[{'destination':'203.0.113.0','netmask':'24','interface':'xfrm10','gateway':''}]
    result=check(tmp_path,monkeypatch,data)
    assert result['analysisPath'][0]['egressZone']=='VPN'
    assert result['summary']['status'] in {'PASS','WARNING'}
    assert not any(step['type']=='gateway' for step in result['analysisPath'])


def test_missing_dynamic_forward_route_has_precise_unknown_reason(tmp_path,monkeypatch):
    data=snapshot();data['routes']=[]
    result=check(tmp_path,monkeypatch,data)
    assert result['summary']['status']=='UNKNOWN'
    assert 'BGP / OSPF / SD-WAN' in result['summary']['primaryReason']
    assert result['analysisPath'][0]['status']=='PASS'


def test_block_does_not_get_overridden_by_missing_return_and_route(tmp_path,monkeypatch):
    data=snapshot();data['routes']=[];data['interfaces']=[];data['rules']=[rule(action='Drop')]
    result=check(tmp_path,monkeypatch,data)
    assert result['summary']['status']=='BLOCK'
    assert all(step['status']=='NOT_REACHED' for step in result['analysisPath'][1:])
    assert any(step['configurationStatus']=='UNKNOWN' for step in result['analysisPath'][1:])


def test_alias_dnat_and_combined_snat_use_configured_names_and_packet(tmp_path,monkeypatch):
    data=snapshot();data['aliases']=[{'Name':'WAN:10','Parent Interface':'PortB','IP Address':'192.0.2.20','CIDR':'192.0.2.20/24','Zone':'WAN'}]
    data['rules']=[rule('WAN to LAN Drop',source='Any',destination='100.1.1.20',action='Drop')]
    data['rules'][0].update({'Source Zone':'WAN','Destination Zone':'LAN'})
    data['objects']={'published':'192.0.2.20','internal':'100.1.1.20'}
    data['natRules']=[nat()]
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check('203.0.113.10','192.0.2.20','TCP',None)
    assert result['summary']['status']=='BLOCK'
    assert result['summary']['ingressZone']=='WAN' and result['summary']['egressZone']=='LAN'
    assert result['summary']['matchedRule']=='WAN to LAN Drop'
    assert result['analysisPath'][0]['type']=='dnat' and result['analysisPath'][0]['status']=='PASS'
    assert result['details']['destinationOwners'][0]['Parent Interface']=='PortB'


def test_return_static_appears_after_forward_checks(tmp_path,monkeypatch):
    data=snapshot();data['interfaces'][0]['CIDR']='100.1.0.1/32'
    data['routes'].append({'destination':'100.1.0.0','netmask':'22','interface':'PortA'})
    result=check(tmp_path,monkeypatch,data)
    assert result['summary']['status']=='PASS'
    assert result['analysisPath'][-1]['type']=='return_route'
    assert result['analysisPath'][-1]['route']['routeType']=='Static'


def test_snat_separate_and_nat_not_required_not_unknown(tmp_path,monkeypatch):
    data=snapshot();data['natRules']=[nat('SNAT')]
    result=check(tmp_path,monkeypatch,data)
    assert result['summary']['status']=='PASS'
    assert next(step for step in result['analysisPath'] if step['type']=='snat')['translation']['translated']=='192.0.2.1/32'
    plain=check(tmp_path,monkeypatch,snapshot())
    assert plain['analysisPath'][0]['natStatus']=='NOT_REQUIRED'


def test_compatible_fields_still_present_without_changing_export_parsers(tmp_path,monkeypatch):
    result=check(tmp_path,monkeypatch)
    assert {'path','steps','firewalls','awsSecurityGroups','policySummary','summary','progress','pathSteps','findings'}<=result.keys()
    assert result['summary']['status']=='PASS'


def test_network_union_of_allow_rules_is_pass_not_unnecessary_unknown(tmp_path,monkeypatch):
    data=snapshot();data['rules']=[rule('first half',source='100.1.1.0/25'),rule('second half',source='100.1.1.128/25',order=2)]
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check('100.1.1.0/24','203.0.113.10','TCP',443)
    assert result['summary']['status']=='PASS'
    assert len(result['networkResults'])==2
    assert {case['analysisPath'][0]['matchedRule']['rule'] for case in result['networkResults']}=={'first half','second half'}


def test_network_partial_allow_exposes_blocked_subscope_not_unknown(tmp_path,monkeypatch):
    data=snapshot();data['rules']=[rule('first half',source='100.1.1.0/25')]
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check('100.1.1.0/24','203.0.113.10','TCP',443)
    assert result['summary']['status']=='WARNING'
    assert {case['summary']['status'] for case in result['networkResults']}=={'PASS','BLOCK'}


def test_original_service_and_input_fields_preserved_for_any_analysis(tmp_path,monkeypatch):
    current,_=service(tmp_path,monkeypatch)
    result=current.check('100.1.1.10/255.255.255.255','203.0.113.10','ANY')
    assert result['protocol']=='ANY' and result['port'] is None
    assert result['source']['input']=='100.1.1.10/255.255.255.255'
    assert result['summary']['source']==result['source']['input']


def test_tcp_any_internet_zone_scope_is_verified_instead_of_symbolic_warning(tmp_path,monkeypatch):
    data=snapshot();data['rules'][0]['Destination Zone']='WAN'
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check('100.1.1.10','','TCP',None)
    assert result['groups'][0]['status']=='PASS'
    assert result['groups'][0]['results']
    assert all(case['summary']['status']=='PASS' for case in result['groups'][0]['results'])


def test_numeric_nat_priority_is_decided_without_guessing(tmp_path,monkeypatch):
    data=snapshot();data['objects']={'published':'192.0.2.20','internal':'100.1.1.20','other':'100.1.1.30'}
    later=nat();later.update({'Position':'2','Rule Name':'later','Translated Destination':'other'})
    first=nat();first.update({'Position':'1','Rule Name':'first'})
    data['natRules']=[later,first];data['rules']=[rule(source='Any')]
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check('203.0.113.10','192.0.2.20','TCP',443)
    assert result['summary']['status']=='PASS'
    assert result['analysisPath'][0]['rule']=='first'
    assert result['analysisPath'][0]['translation']['translated']=='100.1.1.20/32'


def test_broad_cidr_overlap_does_not_invent_an_unconfigured_site_firewall(tmp_path,monkeypatch):
    result=check(tmp_path,monkeypatch)
    current,_=service(tmp_path,monkeypatch)
    result=current.check('100.1.1.10','101.0.0.0/8','TCP',443)
    assert result['summary']['status']=='PASS'
    assert 'Seoul' not in result['path']


def test_numeric_path_resolves_existing_fqdn_object_without_raw_dump(tmp_path,monkeypatch):
    import backend.services.firewall_path_check as module
    data=snapshot();data['rules'][0].update({'Destination Object':'fqdn-object','Destination Resolved':'object.example.test\n203.0.113.10','_Destination FQDNs':['object.example.test']})
    calls=[]
    monkeypatch.setattr(module,'resolve_fqdn',lambda value:calls.append(value) or ['203.0.113.10'])
    assert check(tmp_path,monkeypatch,data)['summary']['status']=='PASS'
    assert calls==[]  # Existing Snapshot already resolved the Object during refresh.


def test_dns_object_failure_has_specific_reason(tmp_path,monkeypatch):
    import backend.services.firewall_path_check as module
    data=snapshot();data['rules'][0].update({'Destination Object':'fqdn-object','Destination Resolved':'object.example.test','_Destination FQDNs':['object.example.test']})
    data['rules'][0]['_Object Resolution Errors']=['Destination FQDN DNS Resolve 실패']
    monkeypatch.setattr(module,'resolve_fqdn',lambda value:[])
    result=check(tmp_path,monkeypatch,data)
    assert result['summary']['status']=='UNKNOWN'
    assert 'DNS Resolve 실패' in result['summary']['primaryReason']


def test_ip_protocol_6_uses_tcp_service_ranges_and_preserves_input_protocol(tmp_path,monkeypatch):
    data=snapshot();data['rules']=[svc(rule('HTTPS'),443),rule('drop rest',action='Drop',order=2)]
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check('100.1.1.10','203.0.113.10','IP',None,protocol_number=6)
    assert result['protocol']=='IP' and result['protocolNumber']==6
    assert result['summary']['status']=='WARNING'
    assert any(case['fromPort']==443 and case['summary']['status']=='PASS' for case in result['serviceResults'])


def test_ip_encoded_tcp_service_and_any_port_are_not_default_dropped(tmp_path,monkeypatch):
    data=snapshot();data['rules'][0].update({'Service':'ip6','Service Resolved / Protocol / Port':'Protocol: IP | Protocol Number: 6'})
    assert check(tmp_path,monkeypatch,data)['summary']['status']=='PASS'
    data['rules'][0].update({'Service':'tcpAny','Service Resolved / Protocol / Port':'Protocol: TCP | Destination: Any'})
    assert check(tmp_path,monkeypatch,data)['summary']['status']=='PASS'


def test_source_only_network_union_uses_complete_path_coverage(tmp_path,monkeypatch):
    data=snapshot();data['rules']=[rule('first half',source='100.1.1.0/25',destination='203.0.113.0/24'),rule('second half',source='100.1.1.128/25',destination='203.0.113.0/24',order=2)]
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check('100.1.1.0/24','','TCP',443)
    assert result['groups'][0]['status']=='PASS'
    assert len(result['groups'][0]['results'][0]['networkResults'])==2


def test_destination_exposure_validates_reverse_dnat_publication_path(tmp_path,monkeypatch):
    data=snapshot();data['rules']=[rule(source='203.0.113.0/24',destination='100.1.1.20')]
    data['natRules']=[nat()];data['objects']={'published':'192.0.2.20','internal':'100.1.1.20'}
    current,_=service(tmp_path,monkeypatch,{'Cloud':data})
    result=current.check('','100.1.1.20','TCP',443)
    published=[group for group in result['groups'] if group.get('publication')]
    assert published and published[0]['status']=='PASS'
    assert any(step['type']=='dnat' and step['status']=='PASS' for step in published[0]['results'][0]['analysisPath'])
