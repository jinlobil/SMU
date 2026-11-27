"""Packet flow tests: synthetic topology; no production addresses, names, or API calls."""
import copy
import ipaddress
import json

import pytest

from backend.services.firewall_configuration import ConfigurationIndex
from backend.services.firewall_path_check import FirewallPathCheckService
from backend.services.firewall_topology import TopologyIndex, network


def interface(name, ip, zone, gateway=''):
    return {'Name': name, 'Hardware': name, 'Type': 'Physical', 'IP Address': ip,
        'Netmask': '255.255.255.0', 'CIDR': ip + '/24', 'Zone': zone, 'Gateway IP': gateway}


def policy(name='permit', action='Accept', source='Any', destination='Any', order=1):
    return {'Rule Name': name, 'Status': 'Enable', 'Action': action, 'Source Object': source,
        'Source Resolved': source, 'Destination Object': destination, 'Destination Resolved': destination,
        'Source Zone': 'Any', 'Destination Zone': 'Any', 'Service': 'Any', 'Service Resolved / Protocol / Port': 'Any',
        '_Rule Position': str(order)}


def route(cidr, port, gateway=''):
    return {'destination': cidr.split('/')[0], 'netmask': cidr.split('/')[1], 'interface': port, 'gateway': gateway, 'status': 'ON'}


def config(name, interfaces, routes=()):
    return {'metadata': {'snapshot_id': name + '-generation'}, 'checkedAt': 'fixture',
        'rules': [policy()], 'natRules': [], 'interfaces': interfaces, 'aliases': [], 'routes': list(routes),
        'zones': [], 'gateways': [], 'objects': {}, 'services': {}, 'fqdnObjects': {}, 'configurationErrors': {}}


def topology():
    branch = config('Edge', [interface('inside', '10.41.0.1', 'LAN'), interface('uplink', '198.51.100.2', 'WAN', '198.51.100.1')],
        [route('10.42.0.0/24', 'xfrm42')])
    cloud = config('Hub', [interface('inside', '10.42.0.1', 'LAN'), interface('uplink', '10.43.0.2', 'WAN', '10.43.0.1')],
        [route('10.41.0.0/24', 'xfrm17')])
    cloud['aliases'] = [{'Name': 'uplink:10', 'Type': 'Alias', 'Parent Interface': 'uplink',
        'IP Address': '10.43.0.12', 'Netmask': '255.255.255.0'}]
    branch['natRules'] = [nat('egress', snat='MASQ', outbound='uplink')]
    return {'Edge': branch, 'Hub': cloud}


def nat(name, dest='', dnat='Original', snat='Original', inbound='', outbound='', service=''):
    return {'Rule Name': name, 'Status': 'Enable', 'Position': '1', 'Original Source': '',
        'Original Destination': dest, 'Original Service': service, 'Translated Source': snat,
        'Translated Destination': dnat, 'Translated Service': 'Original',
        'Inbound Interface': inbound, 'Outbound Interface': outbound, 'Linked Firewall Rule': ''}


def aws_data():
    eni = {'NetworkInterfaceId': 'eni-fixture', 'PrivateIpAddress': '10.43.0.2', 'VpcId': 'vpc-fixture',
        'Groups': [{'GroupId': 'sg-fixture'}], 'PrivateIpAddresses': [
            {'PrivateIpAddress': '10.43.0.2', 'Association': {'PublicIp': '8.8.4.4'}},
            {'PrivateIpAddress': '10.43.0.12', 'Association': {'PublicIp': '8.8.4.5'}}]}
    return {'instances': [{'InstanceId': 'i-fixture', 'NetworkInterfaces': [eni]}], 'network_interfaces': [eni],
        'addresses': [], 'security_groups': [{'GroupId': 'sg-fixture', 'GroupName': 'fixture'}],
        'security_group_rules': [{'GroupId': 'sg-fixture', 'IsEgress': False, 'IpProtocol': '-1', 'CidrIpv4': '0.0.0.0/0'},
            {'GroupId': 'sg-fixture', 'IsEgress': True, 'IpProtocol': '-1', 'CidrIpv4': '0.0.0.0/0'}]}


def service(tmp_path, snapshots=None, aws=None):
    current = FirewallPathCheckService(tmp_path)
    snapshots = snapshots if snapshots is not None else topology()
    current.configuration.snapshots = snapshots
    current.configuration.indexes = {name: ConfigurationIndex(row) for name, row in snapshots.items()}
    current.configuration.aws_data = aws or {}
    current.configuration.topology = TopologyIndex(snapshots, current.configuration.indexes, aws)
    current.firewalls.configurations = lambda: [{'name': name, 'configured': True} for name in snapshots]
    return current


def check(current, destination='8.8.8.8', source='10.41.0.25', port=443):
    return current.check(source, destination, 'TCP', port)


def test_vpn_hops_from_reciprocal_routes_no_wan_nat_or_gateway(tmp_path):
    result = check(service(tmp_path), '10.42.0.25')
    assert result['summary']['status'] == 'PASS'
    assert result['path'] == ['Edge', 'Hub']
    assert not any(row['type'] in {'snat', 'dnat', 'gateway', 'aws_sg', 'return_route'} for row in result['analysisPath'])
    assert result['returnPath']['status'] == 'PASS'
    assert result['forwardPath']['status'] == 'REACHED'


def test_default_wan_route_shares_egress_with_nat_and_no_cloud(tmp_path):
    result = check(service(tmp_path))
    assert result['summary']['status'] == 'PASS' and result['path'] == ['Edge']
    types = [row['type'] for row in result['analysisPath']]
    assert types.index('firewall') < types.index('route') < types.index('snat') < types.index('gateway')
    assert next(row for row in result['analysisPath'] if row['type'] == 'snat')['translation']['translated'] == '198.51.100.2/32'
    assert not any(row['type'] in {'aws_sg', 'return_route'} for row in result['analysisPath'])


@pytest.mark.parametrize('public,private,interface_name,kind', [('8.8.4.4', '10.43.0.2', 'uplink', 'physical'), ('8.8.4.5', '10.43.0.12', 'uplink:10', 'alias')])
def test_primary_and_alias_eip_join_and_firewall_local_no_transit(tmp_path, public, private, interface_name, kind):
    current = service(tmp_path, aws=aws_data())
    entry = current.configuration.topology.public_addresses[public]
    assert (entry['private_ip'], entry['interface'], entry['interface_type'], entry['zone'], entry['parent_interface']) == (private, interface_name, kind, 'WAN', 'uplink')
    result = check(current, public, port=9876)
    assert result['endpoints']['destination']['type'] == 'FIREWALL_PUBLIC_IP'
    assert result['path'] == ['Edge', 'Hub']
    assert not any(row['type'] == 'firewall' and row['firewall'] == 'Hub' for row in result['analysisPath'])
    assert result['analysisPath'][-1]['type'] == 'firewall_local'
    assert result['forwardPath']['status'] == 'REACHED'
    assert result['summary']['status'] == 'UNKNOWN'  # Local port / ACL is not collected.
    assert any(row['type'] == 'aws_sg' for row in result['analysisPath'])


def test_alias_reference_dnat_uses_translated_route_and_policy(tmp_path):
    snapshots = topology()
    snapshots['Hub']['natRules'] = [nat('publish', '#uplink:10', '10.42.0.25', inbound='uplink')]
    snapshots['Hub']['rules'] = [policy('translated target', destination='10.42.0.25')]
    current = service(tmp_path, snapshots, aws_data())
    result = check(current, '8.8.4.5', source='9.9.9.9')
    assert result['summary']['status'] == 'PASS'
    dnat = next(row for row in result['analysisPath'] if row['type'] == 'dnat')
    fw = next(row for row in result['analysisPath'] if row['type'] == 'firewall')
    assert dnat['translation']['translated'] == '10.42.0.25/32'
    assert fw['egressZone'] == 'LAN' and fw['matchedRule']['rule'] == 'translated target'
    assert not any(row['type'] == 'firewall_local' for row in result['analysisPath'])


def test_block_stops_processing_before_route_nat_sg_or_return(tmp_path, monkeypatch):
    snapshots = topology(); snapshots['Edge']['rules'] = [policy('deny', 'Drop')]
    current = service(tmp_path, snapshots, aws_data())
    from backend.services.firewall_packet import ReturnPathAnalyzer
    monkeypatch.setattr(ReturnPathAnalyzer, 'analyze', lambda *args: pytest.fail('return evaluated after block'))
    result = check(current, '8.8.4.4')
    assert result['summary']['status'] == 'BLOCK'
    assert result['path'] == ['Edge']
    assert [row['type'] for row in result['analysisPath']] == ['firewall']
    assert result['progress']['nodes'][-1]['status'] == 'NOT_REACHED'


def test_literal_ip_or_match_ignores_unrelated_fqdn_error(tmp_path):
    snapshots = topology(); row = snapshots['Edge']['rules'][0]
    row.update({'Destination Object': 'exact\nmissing.example', 'Destination Resolved': '8.8.8.8',
        '_Destination Missing Objects': ['missing.example'], '_Object Resolution Errors': ['Destination FQDN DNS Resolve 실패']})
    result = check(service(tmp_path, snapshots))
    assert result['summary']['status'] == 'PASS'


def test_route_priority_connected_specific_default_and_disabled(tmp_path):
    current = service(tmp_path); routes = current.configuration.topology.routes
    edge = current.configuration.snapshots['Edge']
    assert routes.select('Edge', network('10.41.0.5'))['routeType'] == 'Connected'
    edge['routes'].extend([route('8.8.0.0/16', 'uplink'), {**route('8.8.8.0/24', 'inside'), 'status': 'Disable'}])
    current = service(tmp_path, current.configuration.snapshots)
    assert current.configuration.topology.routes.select('Edge', network('8.8.8.8'))['network'] == '8.8.0.0/16'
    assert current.configuration.topology.routes.select('Edge', network('9.9.9.9'))['source'] == 'interface_gateway'


def test_unknown_next_hop_does_not_manufacture_remaining_steps(tmp_path):
    snapshots = topology(); snapshots.pop('Hub')
    result = check(service(tmp_path, snapshots), '10.42.0.25')
    assert result['summary']['status'] == 'UNKNOWN'
    assert result['analysisPath'][-1]['label'] == 'VPN Next Hop'
    assert result['returnPath']['status'] == 'NOT_REACHED'


def test_loop_detection_stops_at_repeated_packet_state(tmp_path):
    snapshots = topology()
    # Explicit route gateways are exact peer Interface addresses.
    snapshots['Edge']['routes'] = [route('10.99.0.0/24', 'uplink', '10.43.0.2')]
    snapshots['Hub']['routes'] = [route('10.99.0.0/24', 'uplink', '10.41.0.1')]
    result = check(service(tmp_path, snapshots), '10.99.0.25')
    assert result['summary']['status'] == 'UNKNOWN'
    assert result['analysisPath'][-1]['reasonCode'] == 'ROUTING_LOOP_DETECTED'
    assert result['forwardPath']['hopCount'] < 10


def test_analysis_uses_pinned_memory_without_file_reads_apis_or_dns(tmp_path, monkeypatch):
    current = service(tmp_path, aws=aws_data())
    from pathlib import Path
    import socket
    from backend.services.firewall import FirewallClient
    monkeypatch.setattr(Path, 'read_text', lambda *a, **k: pytest.fail('analysis file read'))
    monkeypatch.setattr(FirewallClient, 'get', lambda *a, **k: pytest.fail('analysis API'))
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: pytest.fail('analysis DNS'))
    assert check(current, '8.8.4.4')['forwardPath']['status'] == 'REACHED'


def test_blank_port_partitions_services_without_arbitrary_choice(tmp_path):
    snapshots = topology()
    row = policy('https', destination='Any')
    row.update({'Service': 'https', 'Service Resolved / Protocol / Port': 'Protocol: TCP | Destination: 443'})
    snapshots['Edge']['rules'] = [row, policy('deny other', 'Drop', order=2)]
    result = check(service(tmp_path, snapshots), port=None)
    assert result['summary']['status'] == 'WARNING'
    assert {case['summary']['status'] for case in result['serviceResults']} == {'PASS', 'BLOCK'}


def test_source_and_destination_discovery_use_dynamic_builder(tmp_path):
    snapshots = topology(); snapshots['Edge']['rules'] = [policy(source='10.41.0.25', destination='8.8.8.8')]
    current = service(tmp_path, snapshots)
    for source, destination in [('10.41.0.25', ''), ('', '8.8.8.8')]:
        result = current.check(source, destination, 'TCP', 443)
        assert result['groups']
        cases = [case for group in result['groups'] for case in group['results']]
        assert any(case['summary']['status'] == 'PASS' for case in cases)
        assert not any(step['type'] == 'return_route' for case in cases for step in case['analysisPath'])


def test_same_vpc_uses_exact_eni_groups_and_bypasses_firewall_seed(tmp_path):
    data = aws_data()
    for i, ip in enumerate(('10.41.0.25', '10.42.0.25')):
        data['instances'].append({'InstanceId': 'i-host-' + str(i), 'NetworkInterfaces': [
            {'NetworkInterfaceId': 'eni-host-' + str(i), 'VpcId': 'vpc-direct', 'PrivateIpAddress': ip,
             'Groups': [{'GroupId': 'sg-host-' + str(i)}]}]})
        data['security_groups'].append({'GroupId': 'sg-host-' + str(i)})
        for egress in (False, True):
            data['security_group_rules'].append({'GroupId': 'sg-host-' + str(i), 'IsEgress': egress, 'IpProtocol': '-1', 'CidrIpv4': '0.0.0.0/0'})
    result = check(service(tmp_path, aws=data), '10.42.0.25')
    assert result['summary']['status'] == 'PASS'
    assert not any(step['type'] == 'firewall' for step in result['analysisPath'])
    assert all(step['awsSg']['endpoint']['eniId'].startswith('eni-host-') for step in result['analysisPath'])


def test_fqdn_uses_only_resolved_snapshot_values(tmp_path, monkeypatch):
    snapshots = topology(); snapshots['Edge']['resolvedFqdnAddresses'] = {'service.example': ['8.8.8.8']}
    import backend.services.firewall_path_check as module
    monkeypatch.setattr(module, 'resolve_fqdn', lambda *args: pytest.fail('live DNS lookup'))
    result = check(service(tmp_path, snapshots), 'service.example')
    assert result['summary']['status'] == 'PASS'
    assert result['resolvedResults'][0]['destination'] == '8.8.8.8'


def test_refresh_pins_aws_topology_and_rebuilds_join_only_on_refresh(tmp_path, monkeypatch):
    from backend.services.aws_assets import AwsCollector
    from backend.services.firewall_path_analysis import PathAnalysis
    snapshots = topology(); current = service(tmp_path, snapshots, aws_data())
    (tmp_path / 'env').mkdir(); (tmp_path / 'env/aws_env.txt').write_text('AWS_ACCESS_KEY_ID=fixture\nAWS_SECRET_ACCESS_KEY=fixture\nAWS_REGION=fixture')
    calls = []
    fresh = aws_data(); fresh['instances'][0]['NetworkInterfaces'][0]['PrivateIpAddresses'][0]['Association']['PublicIp'] = '8.8.4.6'
    fresh['network_interfaces'] = fresh['instances'][0]['NetworkInterfaces']
    monkeypatch.setattr(AwsCollector, 'collect_network', lambda self: calls.append('network') or fresh)
    current.configuration.collector = lambda config, refresh: copy.deepcopy(snapshots[config['name']])
    pinned = PathAnalysis(current)
    status = current.configuration.refresh()
    assert all(row['refresh_status'] == 'success' for row in status['firewalls'].values())
    assert calls == ['network']
    assert '8.8.4.6' in current.configuration.topology.public_addresses
    assert '8.8.4.6' not in pinned.topology.public_addresses
    manifest = json.loads((tmp_path / 'cache/firewall_config/topology.json').read_text())
    assert manifest['snapshot_ids'] == current.configuration.topology.snapshot_ids
    assert manifest['aws'] == fresh
    check(current)
    assert calls == ['network']


def test_topology_build_failure_keeps_previous_generation_and_files(tmp_path, monkeypatch):
    import backend.services.firewall_topology as module
    snapshots = topology(); current = service(tmp_path, snapshots, aws_data())
    current.configuration.collector = lambda config, refresh: copy.deepcopy(snapshots[config['name']])
    current.configuration.refresh()
    store = current.configuration
    previous = store.topology
    paths = {name: store.path(name).read_bytes() for name in snapshots}
    monkeypatch.setattr(module, 'TopologyIndex', lambda *args: (_ for _ in ()).throw(ValueError('private secret')))
    status = store.refresh()
    assert store.topology is previous
    assert all(store.path(name).read_bytes() == value for name, value in paths.items())
    assert all(row['refresh_status'] == 'failed' for row in status['firewalls'].values())
    assert 'private secret' not in json.dumps(status)


def test_missing_configuration_does_not_guess_cloud_from_site_name(tmp_path):
    result = check(service(tmp_path, {}), '8.8.8.8')
    assert result['summary']['status'] == 'UNKNOWN'
    assert not result['path']
    assert not any(step['type'] in {'aws_sg', 'snat', 'return_route'} for step in result['analysisPath'])


def test_duplicate_private_ip_in_other_vpc_does_not_join_public_to_wrong_firewall(tmp_path):
    data=aws_data()
    duplicate=copy.deepcopy(data['instances'][0]);duplicate['InstanceId']='i-other'
    duplicate['NetworkInterfaces'][0].update(NetworkInterfaceId='eni-other',VpcId='vpc-other')
    duplicate['NetworkInterfaces'][0]['PrivateIpAddresses'][0]['Association']['PublicIp']='8.8.4.7'
    data['instances'].append(duplicate)
    current=service(tmp_path,aws=data)
    for public in ('8.8.4.4','8.8.4.7'):
        endpoint=current.configuration.topology.resolve(network(public))
        assert endpoint.kind=='UNKNOWN_ENDPOINT'
        assert endpoint.owner is None


def test_same_connected_subnet_bypasses_gateway_policy_nat_and_return(tmp_path):
    snapshots=topology();snapshots['Edge']['rules']=[policy('not traversed','Drop')]
    result=check(service(tmp_path,snapshots),'10.41.0.35')
    assert result['summary']['status']=='PASS'
    assert result['path']==[]
    assert [step['type'] for step in result['analysisPath']]==['network']
    assert result['returnPath']['required'] is False


def test_mixed_address_family_dns_records_do_not_crash_or_choose_one(tmp_path):
    snapshots=topology();snapshots['Edge']['resolvedFqdnAddresses']={'mixed.example':['2001:db8::5','8.8.8.8']}
    result=check(service(tmp_path,snapshots),'mixed.example')
    assert result['summary']['status']=='WARNING'
    assert len(result['resolvedResults'])==2
    assert {case['summary']['status'] for case in result['resolvedResults']}=={'UNKNOWN','PASS'}


def test_aws_failure_still_collects_firewalls_and_preserves_generation(tmp_path,monkeypatch):
    snapshots=topology();current=service(tmp_path,snapshots,aws_data())
    calls=[]
    current.configuration.collector=lambda config,refresh:calls.append(config['name']) or copy.deepcopy(snapshots[config['name']])
    old=current.configuration.topology
    monkeypatch.setattr(current.configuration,'collect_aws_topology',lambda:(_ for _ in ()).throw(PermissionError('private credential dump')))
    status=current.configuration.refresh()
    assert calls==list(snapshots)
    assert current.configuration.topology is old
    assert all(row['diagnostics'][0]['stage']=='aws_topology_collection' for row in status['firewalls'].values())
    assert 'private credential dump' not in json.dumps(status)


def test_missing_aws_credentials_still_creates_first_firewall_generation(tmp_path):
    snapshots=topology();current=service(tmp_path,snapshots)
    (tmp_path/'env').mkdir();(tmp_path/'env/aws_env.txt').write_text('')
    current.configuration.collector=lambda config,refresh:copy.deepcopy(snapshots[config['name']])
    status=current.configuration.refresh()
    assert all(row['refresh_status']=='success' for row in status['firewalls'].values())
    assert all(current.configuration.path(name).exists() for name in snapshots)


def test_topology_manifest_mismatch_does_not_mix_new_aws_with_old_firewall(tmp_path):
    current=service(tmp_path,aws=aws_data())
    directory=tmp_path/'cache/firewall_config';directory.mkdir(parents=True)
    (directory/'topology.json').write_text(json.dumps({'snapshot_ids':{'different':'generation'},'aws':aws_data()}))
    (tmp_path/'cache/aws.json').write_text(json.dumps(aws_data()))
    current.configuration.load_topology()
    assert current.configuration.topology.aws_data=={}
    assert current.configuration.topology.public_addresses=={}


def test_unknown_fqdn_is_only_relevant_when_no_numeric_or_member_matches(tmp_path):
    snapshots=topology();row=snapshots['Edge']['rules'][0]
    row.update({'Destination Object':'missing.example','Destination Resolved':'',
        '_Destination FQDNs':['missing.example'],'_Object Resolution Errors':['Destination FQDN DNS Resolve 실패']})
    result=check(service(tmp_path,snapshots))
    assert result['summary']['status']=='UNKNOWN'
    assert 'DNS Resolve 실패' in result['summary']['primaryReason']


def test_hop_limit_is_bounded_even_if_translations_change_loop_state(tmp_path,monkeypatch):
    from backend.services.firewall_packet import DynamicPathBuilder
    monkeypatch.setattr(DynamicPathBuilder,'MAX_HOPS',1)
    result=check(service(tmp_path),'10.42.0.25')
    assert result['analysisPath'][-1]['reasonCode']=='MAX_HOP_COUNT_EXCEEDED'
    assert result['returnPath']['status']=='NOT_REACHED'


def test_network_refresh_uses_only_existing_ec2_network_operations(tmp_path,monkeypatch):
    from backend.services.aws_assets import AwsCollector
    directory=tmp_path/'env';directory.mkdir()
    (directory/'aws_env.txt').write_text('AWS_ACCESS_KEY_ID=fixture\nAWS_SECRET_ACCESS_KEY=fixture\nAWS_REGION=fixture')
    collector=AwsCollector(tmp_path);calls=[]
    monkeypatch.setattr(collector,'_client',lambda credentials:object())
    monkeypatch.setattr(collector,'_pages',lambda client,operation,key:calls.append(operation) or [])
    result=collector.collect_network()
    assert set(calls)=={'describe_instances','describe_network_interfaces','describe_addresses','describe_security_groups','describe_security_group_rules','describe_subnets','describe_vpcs'}
    assert 'ssm_inventory' not in result and 'volumes' not in result


def test_browser_renders_only_emitted_wan_path_and_separate_return(tmp_path):
    from test_firewall_path_layout_browser import path_browser
    result=check(service(tmp_path))
    with path_browser(result) as page:
        assert page.locator('.path-progress li').count()==len(result['progress']['nodes'])
        assert page.get_by_text('Hub Firewall',exact=True).count()==0
        assert page.get_by_label('Return Path',exact=True).is_visible()
        assert not any('Return Route' in value for value in page.locator('.path-progress li b').all_text_contents())


def test_browser_local_firewall_endpoint_has_no_transit_policy_card(tmp_path):
    from test_firewall_path_layout_browser import path_browser
    result=check(service(tmp_path,aws=aws_data()),'8.8.4.4',port=9876)
    with path_browser(result) as page:
        assert page.get_by_role('heading',name='Hub Local Endpoint',exact=True).is_visible()
        assert page.get_by_role('heading',name='Hub Firewall',exact=True).count()==0
        assert page.locator('.path-progress li').count()==len(result['progress']['nodes'])


def test_browser_mini_path_preserves_backend_route_nat_and_gateway_nodes(tmp_path):
    from test_firewall_path_layout_browser import path_browser
    snapshots=topology();snapshots['Edge']['rules']=[policy(source='10.41.0.25',destination='8.8.8.8')]
    result=service(tmp_path,snapshots).check('10.41.0.25','','TCP',443)
    group=next(group for group in result['groups'] if group['object']=='8.8.8.8')
    with path_browser(result) as page:
        labels=page.locator('.mini-path').first.locator('small').all_text_contents()
        assert 'SNAT' in labels
        assert any('Default Route' in label for label in labels)
        assert any(row['type']=='gateway' for row in group['miniPath']['nodes'])
        assert len(labels)==len(group['miniPath']['nodes'])


def test_normal_queries_do_not_reload_env_or_firewall_configuration(tmp_path,monkeypatch):
    current=service(tmp_path)
    monkeypatch.setattr(current.firewalls,'configurations',lambda:pytest.fail('normal analysis reloaded configuration'))
    for source,destination in [('10.41.0.25','8.8.8.8'),('10.41.0.25',''),('','8.8.8.8')]:
        result=current.check(source,destination,'TCP',443)
        assert result['summary']
