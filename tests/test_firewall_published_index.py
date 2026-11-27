import copy
import ipaddress
import time

import pytest

from backend.services.firewall_configuration import ConfigurationIndex
from backend.services.firewall_topology import network
from test_firewall_dynamic_packet import topology,policy,nat,service,check,aws_data


def published():
    snapshots=topology();hub=snapshots['Hub']
    hub['rules']=[policy('Published rule',source='9.9.9.9',destination='#uplink:10')]
    hub['rules'][0].update({'Destination Resolved':'','Source Zone':'WAN','Destination Zone':'LAN',
        'Service':'published group','Service Resolved / Protocol / Port':'Protocol: TCP | Destination: 44300\nProtocol: TCP | Destination: 50000'})
    hub['services']={'published group':'Protocol: TCP | Destination: 44300\nProtocol: TCP | Destination: 50000'}
    hub['natRules']=[nat('Published NAT','#uplink:10','10.42.0.25',inbound='uplink',service='published group')]
    hub['localServices']=[{'zone':'WAN','protocol':'TCP','port':8444,'service':'HTTPS','enabled':True}]
    return snapshots


def test_alias_reverse_index_normalizes_both_policy_and_nat_references(tmp_path):
    current=service(tmp_path,published());index=current.configuration.indexes['Hub']
    assert index.interface_by_address['10.43.0.12'][0]['Name']=='uplink:10'
    assert index.interface_refs['#uplink:10']['IP Address']=='10.43.0.12'
    assert index.aliases['uplink:10']['Parent Interface']=='uplink'
    assert index.aliases['uplink:10']['Zone']==index.interfaces['uplink']['Zone']
    assert index.interface_rules['uplink:10']=={0}
    assert index.interface_nat['uplink:10']=={0}
    assert 0 in index.rules('Destination',network('10.43.0.12'))
    assert 0 not in index.unresolved['Destination']


def test_published_dnat_policy_keeps_original_reference_and_translated_route(tmp_path):
    current=service(tmp_path,published())
    result=check(current,'10.43.0.12','9.9.9.9',50000)
    assert result['summary']['status']=='PASS'
    assert result['endpoints']['destination']['usage']=='PUBLISHED_ADDRESS'
    steps=result['analysisPath'];fw=next(step for step in steps if step['type']=='firewall')
    assert fw['matchedRule']['rule']=='Published rule'
    assert fw['matchedRule']['destinationMatchBasis']=='published_interface_reference'
    assert fw['ingressZone']=='WAN' and fw['egressZone']=='LAN'
    assert fw['route']['network']=='10.42.0.0/24'
    assert not any(step['type']=='firewall_local' for step in steps)
    assert next(step for step in steps if step['type']=='dnat')['translation']['translated']=='10.42.0.25/32'


def test_published_rule_without_translation_is_not_mislabeled_local(tmp_path):
    snapshots=published();snapshots['Hub']['natRules']=[]
    result=check(service(tmp_path,snapshots),'10.43.0.12','9.9.9.9',50000)
    assert result['endpoints']['destination']['usage']=='PUBLISHED_ADDRESS'
    assert result['summary']['status']=='UNKNOWN'
    assert result['analysisPath'][-1]['label']=='Published Next Hop'
    assert any(step['type']=='firewall' and step['status']=='PASS' for step in result['analysisPath'])
    assert not any(step['type']=='firewall_local' for step in result['analysisPath'])


def test_local_service_is_checked_after_all_transit_matches(tmp_path):
    snapshots=published();snapshots['Hub']['localServices'].append({'zone':'WAN','protocol':'TCP','port':50000,'service':'API'})
    current=service(tmp_path,snapshots)
    assert check(current,'10.43.0.12','9.9.9.9',50000)['endpoints']['destination']['usage']=='PUBLISHED_ADDRESS'
    result=check(current,'10.43.0.12','9.9.9.9',8444)
    assert result['analysisPath'][-1]['type']=='firewall_local'
    assert result['forwardPath']['status']=='REACHED'
    assert result['endpoints']['destination']['usage']=='FIREWALL_LOCAL_ENDPOINT'


def test_no_transit_and_no_local_configuration_is_unclassified(tmp_path):
    result=check(service(tmp_path,published()),'10.43.0.12','9.9.9.9',12345)
    assert result['analysisPath'][-1]['type']=='firewall_endpoint'
    assert result['forwardPath']['status']=='UNKNOWN'


def test_alias_transit_does_not_match_another_source(tmp_path):
    snapshots=published();snapshots['Hub']['natRules']=[]
    result=check(service(tmp_path,snapshots),'10.43.0.12','8.8.8.8',50000)
    assert not any(step['type']=='published_address' for step in result['analysisPath'])
    assert result['summary']['status']!='PASS'


def test_alias_transit_drop_is_not_local_endpoint(tmp_path):
    snapshots=published();snapshots['Hub']['natRules']=[]
    snapshots['Hub']['rules'][0]['Action']='Drop'
    result=check(service(tmp_path,snapshots),'10.43.0.12','9.9.9.9',50000)
    assert result['summary']['status']=='BLOCK'
    assert not any(step['type']=='firewall_local' for step in result['analysisPath'])


def test_result_cache_is_limited_to_memory_generation(tmp_path):
    current=service(tmp_path,published())
    first=check(current,'10.43.0.12','9.9.9.9',50000)
    second=check(current,'10.43.0.12','9.9.9.9',50000)
    assert not first['metrics']['cache_hit'] and second['metrics']['cache_hit']
    second['summary']['status']='modified by caller'
    assert check(current,'10.43.0.12','9.9.9.9',50000)['summary']['status']=='PASS'
    from backend.services.firewall_topology import TopologyIndex
    store=current.configuration
    store.topology=TopologyIndex(store.snapshots,store.indexes,store.aws_data)
    assert not check(current,'10.43.0.12','9.9.9.9',50000)['metrics']['cache_hit']


def test_any_port_preserves_allowed_ranges_and_different_outcomes(tmp_path):
    result=check(service(tmp_path,published()),'10.43.0.12','9.9.9.9',None)
    assert result['summary']['status']=='WARNING'
    for port in [44300,50000]:
        scope=next(scope for scope in result['serviceResults'] if scope['fromPort']<=port<=scope['toPort'])
        assert scope['summary']['status']=='PASS'
    assert any(scope['summary']['status']!='PASS' for scope in result['serviceResults'])


class IndexedOnly(list):
    def __iter__(self):raise AssertionError('runtime full table scan')


@pytest.mark.parametrize('mode',['PATH','SOURCE_ONLY','DESTINATION_ONLY'])
def test_all_modes_use_prepared_candidates_without_scanning_raw_tables(tmp_path,monkeypatch,mode):
    snapshots=published()
    for i in range(1000):
        row=policy('noise-'+str(i),source=str(ipaddress.IPv4Address(int(ipaddress.IPv4Address('198.18.0.1'))+i)),destination='198.19.0.1',order=i+2)
        row['Service']='unrelated';row['Service Resolved / Protocol / Port']='Protocol: TCP | Destination: 22'
        snapshots['Hub']['rules'].append(row)
    current=service(tmp_path,snapshots)
    for snapshot in snapshots.values():
        for table in ('rules','natRules','routes'):snapshot[table]=IndexedOnly(snapshot[table])
    from backend.services.firewall import FirewallClient
    import socket
    monkeypatch.setattr(FirewallClient,'get',lambda *a,**k:pytest.fail('query performed an API call'))
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:pytest.fail('query performed a DNS call'))
    src='' if mode=='DESTINATION_ONLY' else '9.9.9.9'
    dst='' if mode=='SOURCE_ONLY' else '10.43.0.12'
    result=current.check(src,dst,'TCP',50000)
    assert result['metrics']['total_rule_count']>1000
    assert result['metrics']['candidate_rule_count']<15
    required={'endpoint_lookup_ms','object_index_lookup_ms','group_lookup_ms','service_index_lookup_ms','nat_index_lookup_ms','candidate_rule_count','candidate_nat_count','policy_validation_ms','dynamic_path_ms','total_ms'}
    assert required<=result['metrics'].keys()


def test_managed_eni_without_instance_keeps_explicit_empty_sg_information(tmp_path):
    snapshots=published();data={'instances':[],'network_interfaces':[{'NetworkInterfaceId':'eni-managed','PrivateIpAddress':'10.42.0.25','PrivateIpAddresses':[{'PrivateIpAddress':'10.42.0.25'}],'Groups':[],'VpcId':'vpc-fixture','InterfaceType':'network_load_balancer'}],
        'security_groups':[],'security_group_rules':[]}
    result=check(service(tmp_path,snapshots,data),'10.43.0.12','9.9.9.9',50000)
    assert result['summary']['status']=='PASS'
    assert result['awsSecurityGroups']['inbound']['state']=='N/A'
    assert result['awsSecurityGroups']['inbound']['endpoint']['eniId']=='eni-managed'


def test_empty_snapshot_responds_immediately_without_refresh(tmp_path,monkeypatch):
    current=service(tmp_path,{})
    current.configuration.collector=lambda *args:pytest.fail('implicit refresh')
    start=time.perf_counter();result=current.check('9.9.9.9','8.8.8.8','TCP',None)
    assert 'Configuration Snapshot이 없습니다' in result['summary']['primaryReason']
    assert time.perf_counter()-start<1
