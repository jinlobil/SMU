import ipaddress

import pytest
from fastapi.testclient import TestClient

from backend.services.firewall_path_check import match_rules
from backend.services.firewall_rule_export import parse_firewall_rules
from backend.services.aws_security_group_path import AwsSecurityGroupPathService
from test_aws_security_group_path import payload, save, path_service


def source_rules(name='source-group'):
    return parse_firewall_rules({
        'Rule': f'''<Response><FirewallRule><Name>source-fqdn-rule</Name><Status>Enable</Status><NetworkPolicy>
          <SourceZones><Zone>Any</Zone></SourceZones><DestinationZones><Zone>Any</Zone></DestinationZones>
          <SourceNetworks><Network>{name}</Network></SourceNetworks><DestinationNetworks><Network>Any</Network></DestinationNetworks>
          <Services><Service>Any</Service></Services><Action>Allow</Action></NetworkPolicy></FirewallRule></Response>''',
        'FQDNHost': '<Response><FQDNHost><Name>source-host</Name><FQDN>host.example.com</FQDN></FQDNHost><FQDNHost><Name>wild-host</Name><FQDN>*.example.net</FQDN></FQDNHost></Response>',
        'FQDNHostGroup': '<Response><FQDNHostGroup><Name>source-group</Name><FQDNHostList><FQDNHost>source-host</FQDNHost><FQDNHost>wild-host</FQDNHost></FQDNHostList></FQDNHostGroup></Response>',
    })[0]


@pytest.mark.parametrize('name,query,expected', [('source-host', 'host.example.com', 'allow'),
    ('source-group', 'host.example.com', 'allow'), ('source-group', 'sub.example.net', 'allow'),
    ('wild-host', 'example.net', 'no_matching_rule'), ('wild-host', 'badexample.net', 'no_matching_rule'),
    ('source-host', 'other.example.com', 'no_matching_rule')])
def test_source_typed_fqdn_object_group_and_wildcard(name, query, expected):
    result = match_rules(source_rules(name), None, ipaddress.ip_network('192.0.2.1'), 'TCP', 443, source_fqdn=query)
    assert result['state'] == expected


@pytest.mark.parametrize('addresses', [[], ['101.1.0.50'], ['101.1.0.50', '101.3.0.10']])
def test_source_dns_is_topology_only_no_arbitrary_record(tmp_path, monkeypatch, addresses):
    import backend.services.firewall_path_check as module
    save(tmp_path, payload())
    monkeypatch.setattr(module, 'resolve_fqdn', lambda _: addresses)
    service = path_service(tmp_path, monkeypatch)
    monkeypatch.setattr(service, '_snapshot', lambda *_: {'rules': source_rules(), 'routes': [], 'routeError': '', 'checkedAt': 'now'})
    result = service.check('HOST.Example.COM.', '100.1.2.10', 'TCP', 443)
    assert result['source']['input'] == 'host.example.com'
    assert result['source']['resolvedIps'] == addresses
    assert result['source']['network'] == ('101.1.0.50/32' if len(addresses) == 1 else '')
    assert result['firewalls'] and all(item['policy']['state'] == 'allow' for item in result['firewalls'])
    if len(addresses) != 1:
        assert result['partialPath'] is True
        assert all(item['routing']['return'] is None for item in result['firewalls'])


@pytest.mark.parametrize('value', ['https://host.example.com', '*.example.com', 'bad name', 'host..example.com', '999.1.1.1', 'host/example.com'])
def test_bad_source_fqdn_rejected(tmp_path, value):
    from backend.services.firewall_path_check import FirewallPathCheckService
    with pytest.raises(ValueError): FirewallPathCheckService(tmp_path).check(value, '192.0.2.1')


@pytest.mark.parametrize('value,network', [('101.1.0.50', '101.1.0.50/32'), ('101.1.0.0/24', '101.1.0.0/24')])
def test_original_source_ip_and_cidr_unchanged(tmp_path, monkeypatch, value, network):
    result = path_service(tmp_path, monkeypatch).check(value, '100.1.2.10', 'TCP', 443)
    assert result['source']['network'] == network and 'fqdn' not in result['source']


def test_source_fqdn_api_and_simultaneous_destination_fqdn(tmp_path, monkeypatch):
    import backend.app as app_module
    import backend.services.firewall_path_check as module
    service = path_service(tmp_path, monkeypatch)
    monkeypatch.setattr(service, '_snapshot', lambda *_: {'rules': source_rules(), 'routes': [], 'routeError': '', 'checkedAt': 'now'})
    monkeypatch.setattr(module, 'resolve_fqdn', lambda query: ['101.1.0.50'] if query == 'host.example.com' else ['100.1.2.10'])
    monkeypatch.setattr(app_module, 'firewall_path_check_service', service)
    response = TestClient(app_module.app).post('/api/firewall/path-check', json={'source': 'host.example.com', 'destination': 'dest.example.com', 'protocol': 'TCP', 'port': 443})
    assert response.status_code == 200
    assert response.json()['data']['source']['fqdn'] == 'host.example.com'
    assert response.json()['data']['destination']['fqdn'] == 'dest.example.com'


def test_source_aws_dns_multiple_endpoints_remain_unknown_and_port_only(tmp_path):
    save(tmp_path, payload())
    result = AwsSecurityGroupPathService(tmp_path).check(None, ipaddress.ip_network('100.1.2.10'), 'TCP', 443, None, [], True,
        source_fqdn=True, source_queries=[ipaddress.ip_network(value) for value in ['10.10.0.10', '198.51.100.1']])
    assert result['outbound']['endpoint']['state'] == 'UNKNOWN'
    assert result['inbound']['queryMode'] == 'fqdn'
    assert result['inbound']['state'] != 'PASS'


def test_source_fqdn_form_submits_unchanged_with_existing_ui(tmp_path, monkeypatch):
    from test_firewall_path_layout_browser import path_browser
    import backend.services.firewall_path_check as module
    monkeypatch.setattr(module, 'resolve_fqdn', lambda _: ['101.1.0.50'])
    result = path_service(tmp_path, monkeypatch).check('host.example.com', '100.1.2.10', 'TCP', 443)
    with path_browser(result) as page:
        page.get_by_label('Source IP / CIDR / FQDN', exact=True).fill('host.example.com')
        with page.expect_request('**/api/firewall/path-check') as sent:
            page.get_by_role('button', name='Path Check', exact=True).click()
        assert sent.value.post_data_json['source'] == 'host.example.com'
        assert page.get_by_label('Destination IP / CIDR / FQDN', exact=True).count() == 1
