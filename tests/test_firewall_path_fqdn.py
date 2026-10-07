import ipaddress

import pytest

from backend.services.fqdn import fqdn_matches, normalize_fqdn, resolve_fqdn
from backend.services.firewall_path_check import match_rules
from backend.services.firewall_rule_export import parse_firewall_rules
from backend.services.aws_security_group_path import AwsSecurityGroupPathService
from test_aws_security_group_path import payload, save, path_service


def fqdn_rules(object_name='api-host', action='Allow'):
    return parse_firewall_rules({
        'Rule': f'''<Response><FirewallRule><Name>fqdn-policy</Name><Status>Enable</Status><NetworkPolicy>
            <SourceZones><Zone>Any</Zone></SourceZones><DestinationZones><Zone>Any</Zone></DestinationZones>
            <SourceNetworks><Network>Any</Network></SourceNetworks>
            <DestinationNetworks><Network>{object_name}</Network></DestinationNetworks>
            <Services><Service>https</Service></Services><Action>{action}</Action>
            </NetworkPolicy></FirewallRule></Response>''',
        'FQDNHost': '''<Response><FQDNHost><Name>api-host</Name><FQDN>api.example.com</FQDN></FQDNHost>
            <FQDNHost><Name>wild-host</Name><FQDN>*.example.net</FQDN></FQDNHost></Response>''',
        'FQDNHostGroup': '''<Response><FQDNHostGroup><Name>web-group</Name><FQDNHostList>
            <FQDNHost>api-host</FQDNHost><FQDNHost>wild-host</FQDNHost></FQDNHostList></FQDNHostGroup></Response>''',
        'Services': '''<Response><Services><Name>https</Name><ServiceDetails><ServiceDetail><Protocol>TCP</Protocol>
            <DestinationPort>443</DestinationPort></ServiceDetail></ServiceDetails></Services></Response>''',
    })[0]


@pytest.mark.parametrize('object_name,query,expected', [
    ('api-host', 'api.example.com', 'allow'), ('api-host', 'other.example.com', 'no_matching_rule'),
    ('web-group', 'api.example.com', 'allow'), ('web-group', 'a.example.net', 'allow'),
    ('wild-host', 'api.example.net', 'allow'), ('wild-host', 'a.b.example.net', 'allow'),
    ('wild-host', 'example.net', 'no_matching_rule'), ('wild-host', 'badexample.net', 'no_matching_rule'),
    ('wild-host', 'api.example.net.attacker.test', 'no_matching_rule'),
])
def test_policy_matches_registered_typed_fqdn_objects(object_name, query, expected):
    result = match_rules(fqdn_rules(object_name), ipaddress.ip_network('192.0.2.1'), None, 'TCP', 443, destination_fqdn=query)
    assert result['state'] == expected


@pytest.mark.parametrize('protocol,port,state', [('TCP', 443, 'allow'), ('TCP', 80, 'no_matching_rule'), ('UDP', 443, 'no_matching_rule')])
def test_fqdn_policy_uses_existing_service_check(protocol, port, state):
    assert match_rules(fqdn_rules(), ipaddress.ip_network('192.0.2.1'), None, protocol, port, destination_fqdn='api.example.com')['state'] == state


def test_fqdn_does_not_match_ip_rule_or_an_object_display_name():
    rows = [{'Rule Name': 'ip-only', 'Status': 'Enable', 'Action': 'Allow', 'Source Object': 'Any',
             'Destination Object': 'api.example.com', 'Destination Resolved': '100.1.2.10', 'Service': 'Any'}]
    assert match_rules(rows, ipaddress.ip_network('192.0.2.1'), ipaddress.ip_network('100.1.2.10'), 'TCP', 443,
                       destination_fqdn='api.example.com')['state'] == 'no_matching_rule'


@pytest.mark.parametrize('resolved', [[], ['198.51.100.1'], ['100.1.2.10']])
def test_path_dns_does_not_replace_fqdn_policy_query(tmp_path, monkeypatch, resolved):
    import backend.services.firewall_path_check as module
    save(tmp_path, payload())
    monkeypatch.setattr(module, 'resolve_fqdn', lambda _: resolved)
    service = path_service(tmp_path, monkeypatch)
    monkeypatch.setattr(service, '_snapshot', lambda *_: {'rules': fqdn_rules(action='Reject'), 'routes': [], 'routeError': '', 'checkedAt': 'now'})
    result = service.check('101.1.0.50', 'API.Example.Com.', 'TCP', 443)
    assert result['destination']['input'] == 'api.example.com'
    assert result['destination']['resolvedIps'] == resolved
    assert result['firewalls'][0]['policy']['state'] == 'deny'
    assert result['firewalls'][0]['policy']['matchedRule']['rule'] == 'fqdn-policy'
    assert result['policySummary']['state'] == 'FAIL'


@pytest.mark.parametrize('rule_protocol,start,end,expected', [('tcp', 443, 443, 'UNKNOWN'), ('tcp', 400, 500, 'UNKNOWN'),
    ('-1', None, None, 'UNKNOWN'), ('tcp', 80, 80, 'FAIL'), ('udp', 443, 443, 'FAIL')])
def test_fqdn_sg_checks_direction_protocol_port_never_exact_address(tmp_path, rule_protocol, start, end, expected):
    data = payload()
    data['security_group_rules'][1].update(IpProtocol=rule_protocol, FromPort=start, ToPort=end, CidrIpv4='192.0.2.123/32')
    # Reverse direction does not make Inbound pass.
    data['security_group_rules'].append({'GroupId': 'sg-b', 'SecurityGroupRuleId': 'wrong-direction', 'IsEgress': True, 'IpProtocol': '-1', 'CidrIpv4': '0.0.0.0/0'})
    save(tmp_path, data)
    result = AwsSecurityGroupPathService(tmp_path).check(ipaddress.ip_network('10.10.0.10'), ipaddress.ip_network('100.1.2.10'),
        'TCP', 443, None, [], False, fqdn=True, destination_queries=[ipaddress.ip_network('100.1.2.10')])
    inbound = result['inbound']
    assert inbound['state'] == expected
    assert result['outbound']['state'] == 'UNKNOWN'
    assert inbound['queryMode'] == 'fqdn'
    assert [rule['ruleId'] for rule in inbound['matches']] == (['in-b'] if expected == 'UNKNOWN' else [])
    if expected == 'UNKNOWN': assert 'Source/Destination 조건은 FQDN 기준으로 판정하지 않음' in inbound['reason']
    else: assert inbound['reason'] == '해당 포트 허용 Rule 없음'


@pytest.mark.parametrize('addresses,state', [(['198.51.100.1'], 'N/A'), ([], 'UNKNOWN'), (['100.1.2.10', '198.51.100.1'], 'UNKNOWN')])
def test_fqdn_destination_aws_identification_is_conservative(tmp_path, addresses, state):
    save(tmp_path, payload())
    result = AwsSecurityGroupPathService(tmp_path).check(ipaddress.ip_network('10.10.0.10'), None,
        'TCP', 443, None, [], True, fqdn=True, destination_queries=[ipaddress.ip_network(ip) for ip in addresses])
    assert result['inbound']['state'] == state


@pytest.mark.parametrize('value', ['https://api.example.com', 'bad name', 'api..example.com', '*.example.com', '999.1.1.1', '-api.example.com'])
def test_invalid_fqdn_is_rejected(value):
    with pytest.raises(ValueError): normalize_fqdn(value)


def test_dns_failure_is_only_missing_auxiliary_information(monkeypatch):
    import socket
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *_args, **_kwargs: (_ for _ in ()).throw(socket.gaierror()))
    assert resolve_fqdn('api.example.com') == []
    assert fqdn_matches('API.example.com.', '*.example.com')


def test_existing_api_accepts_destination_fqdn(tmp_path, monkeypatch):
    import backend.app as app_module
    import backend.services.firewall_path_check as module
    from fastapi.testclient import TestClient
    save(tmp_path, payload())
    service = path_service(tmp_path, monkeypatch)
    monkeypatch.setattr(module, 'resolve_fqdn', lambda _: ['100.1.2.10'])
    monkeypatch.setattr(app_module, 'firewall_path_check_service', service)
    response = TestClient(app_module.app).post('/api/firewall/path-check', json={
        'source': '10.10.0.10', 'destination': 'api.example.com', 'protocol': 'TCP', 'port': 443})
    assert response.status_code == 200
    result = response.json()['data']
    assert result['destination']['fqdn'] == 'api.example.com'
    assert result['path'] == []
    assert all(step['state'] == 'UNKNOWN' for step in result['steps'])


def test_fqdn_group_nested_names_and_cycles_are_resolved_safely():
    from backend.services.firewall_rule_export import _fqdn_object_patterns
    patterns = _fqdn_object_patterns({
        'FQDNHost': '<Response><FQDNHost><Name>host</Name><FQDN>api.example.com</FQDN></FQDNHost></Response>',
        'FQDNHostGroup': '''<Response><FQDNHostGroup><Name>outer</Name><FQDNHostList>
            <FQDNHostGroup><Name>inner</Name></FQDNHostGroup></FQDNHostList></FQDNHostGroup>
            <FQDNHostGroup><Name>inner</Name><FQDNHostList><FQDNHost><Name>host</Name></FQDNHost>
            <FQDNHostGroup>outer</FQDNHostGroup></FQDNHostList></FQDNHostGroup></Response>''',
    })
    assert patterns['outer'] == patterns['inner'] == ['api.example.com']


def test_fqdn_sg_complete_empty_rules_fail_but_missing_rules_are_unknown(tmp_path):
    data = payload()
    data['security_group_rules'] = []
    save(tmp_path, data)
    service = AwsSecurityGroupPathService(tmp_path)
    args = (ipaddress.ip_network('10.10.0.10'), None, 'TCP', 443, None, [], True)
    kwargs = {'fqdn': True, 'destination_queries': [ipaddress.ip_network('100.1.2.10')]}
    assert service.check(*args, **kwargs)['inbound']['state'] == 'FAIL'
    data.pop('security_group_rules')
    save(tmp_path, data)
    assert service.check(*args, **kwargs)['inbound']['state'] == 'UNKNOWN'
