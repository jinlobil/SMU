from collections import Counter
from pathlib import Path
from xml.etree import ElementTree as ET
from zipfile import ZipFile

import pytest

from backend.services.firewall import FirewallClient
from backend.services.firewall_nat import NAT_COLUMNS, parse_nat_rules
from backend.services.firewall_rule_export import FirewallRuleExportService, ROUTE_COLUMNS, _route_export_rows
from backend.services.spreadsheet import write_xlsx_workbook
from test_firewall_rule_export import XML, env

NS = {'m': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}

NAT = '''<Response APIVersion="2000.2"><Status code="200">OK</Status>
<NATRule><Name>fixture SNAT</Name><Status>Enable</Status><IPFamily>IPv4</IPFamily><Position>Top</Position>
<OriginalSourceNetworks><Network>Host A</Network><Network>Network B</Network></OriginalSourceNetworks>
<TranslatedSource>MASQ</TranslatedSource><TranslatedDestination>Original</TranslatedDestination><TranslatedService>Original</TranslatedService>
<OutboundInterfaces><Interface>PortA</Interface><Interface>PortB</Interface></OutboundInterfaces>
<LinkedFirewallrule>None</LinkedFirewallrule><Description>first line
second line</Description><NATMethod>fixture-method</NATMethod><HealthCheck>Enable</HealthCheck><OverrideInterfaceNATPolicy>Disable</OverrideInterfaceNATPolicy></NATRule>
<NATRule><Name>NAT_37</Name><Status>Disable</Status><Position>After</Position><After><Name>fixture SNAT</Name></After>
<OriginalDestinationNetworks><Network>Public A</Network><Network>Public B</Network></OriginalDestinationNetworks>
<OriginalServices><Service>HTTPS</Service><Service>TCP fixture</Service></OriginalServices>
<TranslatedSource>Original</TranslatedSource><TranslatedDestination>Fixture Destination</TranslatedDestination><TranslatedService>Original</TranslatedService>
<InboundInterfaces><Interface>PortB</Interface><Interface>PortC</Interface></InboundInterfaces><LinkedFirewallrule>None</LinkedFirewallrule><Description/>
</NATRule></Response>'''
ROUTE = '''<Response APIVersion="2000.2"><Status code="200">OK</Status><UnicastRoute><IPFamily>IPv4</IPFamily>
<DestinationIP>10.10.0.0</DestinationIP><Netmask>255.255.0.0</Netmask><Gateway/><Interface>xfrm1</Interface>
<Distance>4</Distance><AdministrativeDistance>9</AdministrativeDistance><Status>ON</Status><Blackhole>Disable</Blackhole><Description/>
</UnicastRoute></Response>'''


def test_nat_multiple_snat_dnat_and_linked_firewall_priority():
    rules = [{'Rule Name': 'Allow one', 'Linked NAT': 'NAT_37'}, {'Rule Name': 'Allow two', 'Linked NAT': 'NAT_37'},
             {'Rule Name': 'Allow one', 'Linked NAT': 'NAT_37'}, {'Rule Name': 'Not a substring', 'Linked NAT': 'NAT_37-extra'}]
    snat, dnat = parse_nat_rules(NAT, rules)
    assert list(snat) == list(dnat) == NAT_COLUMNS
    assert snat['Rule Name'] == 'fixture SNAT' and dnat['Rule Name'] == 'NAT_37'
    assert snat['Original Source'] == 'Host A\nNetwork B'
    assert snat['Original Destination'] == snat['Original Service'] == snat['Inbound Interface'] == ''
    assert snat['Translated Source'] == 'MASQ' and snat['Translated Destination'] == snat['Translated Service'] == 'Original'
    assert snat['Outbound Interface'] == 'PortA\nPortB'
    assert snat['Description'] == 'first line\nsecond line'
    assert (snat['Status'], snat['IP Family'], snat['Position'], snat['After Rule']) == ('Enable', 'IPv4', 'Top', '')
    assert snat['NAT Method'] == 'fixture-method' and snat['Health Check'] == 'Enable' and snat['Override Interface NAT'] == 'Disable'
    assert dnat['Original Destination'] == 'Public A\nPublic B' and dnat['Original Service'] == 'HTTPS\nTCP fixture'
    assert dnat['Original Source'] == dnat['Outbound Interface'] == dnat['Description'] == ''
    assert dnat['Inbound Interface'] == 'PortB\nPortC'
    assert (dnat['Status'], dnat['Position'], dnat['After Rule']) == ('Disable', 'After', 'fixture SNAT')
    assert dnat['Linked Firewall Rule'] == 'Allow one\nAllow two'
    primary = NAT.replace('<LinkedFirewallrule>None</LinkedFirewallrule>', '<LinkedFirewallrule>Primary rule</LinkedFirewallrule>')
    assert parse_nat_rules(primary, rules)[1]['Linked Firewall Rule'] == 'Primary rule'


@pytest.mark.parametrize('linked', ['', '<LinkedFirewallrule/>', '<LinkedFirewallrule>None</LinkedFirewallrule>'])
def test_nat_empty_link_uses_reverse_mapping(linked):
    xml = f'<Response><NATRule><Name>fixture</Name>{linked}</NATRule></Response>'
    assert parse_nat_rules(xml, [{'Rule Name': 'A', 'Linked NAT': 'fixture'}])[0]['Linked Firewall Rule'] == 'A'
    assert parse_nat_rules(xml)[0]['Linked Firewall Rule'] == ''


@pytest.mark.parametrize('tag', ['OriginalSourceNetworks', 'OriginalDestinationNetworks', 'OriginalServices', 'InboundInterfaces',
                                    'OutboundInterfaces', 'Description', 'NATMethod', 'HealthCheck', 'OverrideInterfaceNATPolicy'])
def test_nat_fields_are_optional_without_any_or_other_inferred_values(tag):
    root = ET.fromstring(NAT)
    for node in root.findall('NATRule'):
        for child in list(node):
            if child.tag == tag: node.remove(child)
    rows = parse_nat_rules(ET.tostring(root, encoding='unicode'))
    assert len(rows) == 2
    column = {'OriginalSourceNetworks': 'Original Source', 'OriginalDestinationNetworks': 'Original Destination',
              'OriginalServices': 'Original Service', 'InboundInterfaces': 'Inbound Interface', 'OutboundInterfaces': 'Outbound Interface',
              'Description': 'Description', 'NATMethod': 'NAT Method', 'HealthCheck': 'Health Check',
              'OverrideInterfaceNATPolicy': 'Override Interface NAT'}[tag]
    assert all(row[column] == '' for row in rows)


@pytest.mark.parametrize('translated', ['MASQ', 'Original', 'Fixture Alias'])
def test_snat_translated_source_is_not_resolved_or_rewritten(translated):
    assert parse_nat_rules(NAT.replace('<TranslatedSource>MASQ</TranslatedSource>', f'<TranslatedSource>{translated}</TranslatedSource>'))[0]['Translated Source'] == translated


def test_source_restricted_dnat_and_missing_every_optional_tag():
    xml = NAT.replace('<Name>NAT_37</Name>', '<Name>NAT_37</Name><OriginalSourceNetworks><Network>Restricted Source</Network></OriginalSourceNetworks>')
    assert parse_nat_rules(xml)[1]['Original Source'] == 'Restricted Source'
    minimal = parse_nat_rules('<Response><NATRule><Name>minimal</Name></NATRule></Response>')[0]
    assert minimal == {column: 'minimal' if column == 'Rule Name' else '' for column in NAT_COLUMNS}
    assert parse_nat_rules('<Response><Status code="200">OK</Status></Response>') == []


@pytest.mark.parametrize('mask,prefix', [('255.240.0.0', 12), ('255.255.0.0', 16), ('255.255.252.0', 22),
                                       ('255.255.254.0', 23), ('255.255.255.0', 24), ('255.255.255.240', 28), ('255.255.255.255', 32)])
def test_actual_destination_ip_and_cidr_masks(mask, prefix):
    from ipaddress import IPv4Network
    row = _route_export_rows(ROUTE.replace('255.255.0.0', mask))[0]
    assert list(row) == ROUTE_COLUMNS
    assert row['Destination'] == '10.10.0.0' and row['Netmask'] == mask
    assert row['CIDR'] == str(IPv4Network(f'10.10.0.0/{prefix}', strict=False))
    assert row['Gateway'] == row['Description'] == ''
    assert row['Distance'] == '4' and row['Administrative Distance'] == '9'
    assert row['Status'] == 'ON' and row['Blackhole'] == 'Disable'


@pytest.mark.parametrize('interface', ['PortA', 'xfrm1', 'xfrm2', 'xfrm3'])
def test_empty_gateway_is_valid_for_interfaces(interface):
    row = _route_export_rows(ROUTE.replace('xfrm1', interface))[0]
    assert row['Interface'] == interface and row['Gateway'] == ''
    assert _route_export_rows(ROUTE.replace('<Gateway/>', '<Gateway>192.0.2.1</Gateway>'))[0]['Gateway'] == '192.0.2.1'


def test_route_invalid_netmask_preserves_original_fields_and_multiple_routes():
    root = ET.fromstring(ROUTE); root.append(ET.fromstring(ROUTE).find('UnicastRoute'))
    root[1].find('Netmask').text = 'bad-mask'
    rows = _route_export_rows(ET.tostring(root, encoding='unicode'))
    assert len(rows) == 2
    assert rows[0]['Destination'] == '10.10.0.0' and rows[0]['Netmask'] == 'bad-mask' and rows[0]['CIDR'] == ''
    assert rows[1]['CIDR'] == '10.10.0.0/16'


def text(row):
    return [cell.findtext('m:is/m:t', default='', namespaces=NS) for cell in row]


def mock_api(monkeypatch, overrides=None):
    seen = []
    def get(client, entity):
        seen.append((client.name, entity))
        value = (overrides or {}).get((client.name, entity), NAT if entity == 'NATRule' else ROUTE if entity == 'UnicastRoute' else XML[entity])
        if isinstance(value, Exception): raise value
        return value
    monkeypatch.setattr(FirewallClient, 'get', get)
    return seen


def test_real_workbook_all_four_devices_new_tables_and_existing_sheets_unchanged(tmp_path, monkeypatch):
    env(tmp_path); seen = mock_api(monkeypatch)
    import backend.services.firewall_rule_export as module
    specs = []
    def capture(path, sheets):
        specs.extend(sheets)
        return write_xlsx_workbook(path, sheets)
    monkeypatch.setattr(module, 'write_xlsx_workbook', capture)
    messages = []
    result = FirewallRuleExportService(tmp_path).build(['Cloud', 'Seoul', 'Icheon', 'Anseong'], messages.append)
    assert result['sheets'] == ['Cloud', 'Seoul', 'Icheon', 'Anseong', 'LAN ↔ OFFICE', 'LAN ↔ WAN', 'ETC', 'NAT', 'Route']
    assert result['errors'] == []
    assert result['counts'] == {name: 1 for name in ('Cloud', 'Seoul', 'Icheon', 'Anseong')}
    assert result['natCounts'] == {name: 2 for name in result['counts']}
    assert result['routeCounts'] == {name: 1 for name in result['counts']}
    for device in result['counts']:
        assert Counter(entity for name, entity in seen if name == device) == {entity: 1 for entity in ('FirewallRule', 'IPHost', 'IPHostGroup', 'FQDNHost', 'FQDNHostGroup', 'Services', 'ServiceGroup', 'NATRule', 'UnicastRoute')}
    assert any('Cloud NAT Rules' in message for message in messages) and messages[-1] == 'Excel 생성 중'
    before = tmp_path / 'before.xlsx'; write_xlsx_workbook(before, specs[:7])
    with ZipFile(result['path']) as archive, ZipFile(before) as baseline:
        assert archive.testzip() is None
        for filename in archive.namelist():
            if filename.endswith(('.xml', '.rels')): ET.fromstring(archive.read(filename))
        for i in range(1, 8): assert archive.read(f'xl/worksheets/sheet{i}.xml') == baseline.read(f'xl/worksheets/sheet{i}.xml')
        assert len([filename for filename in archive.namelist() if filename.startswith('xl/tables/table')]) == 8
        for number, suffix, step in [(8, 'NAT Rules', 5), (9, 'Static Routes', 4)]:
            sheet = ET.fromstring(archive.read(f'xl/worksheets/sheet{number}.xml'))
            rows = sheet.findall('m:sheetData/m:row', NS)
            assert [text(row)[0] for row in rows if text(row) and text(row)[0].endswith(suffix)] == [f'{name} {suffix}' for name in result['counts']]
            assert [int(row.get('r')) for row in rows if not len(row)] == [step, step*2, step*3]
        nat_rows = ET.fromstring(archive.read('xl/worksheets/sheet8.xml')).findall('m:sheetData/m:row', NS)
        assert text(nat_rows[3])[NAT_COLUMNS.index('Linked Firewall Rule')] == 'FW_IN_SEOUL_VPN_PDA_TO_AWS_WMS'


def test_errors_and_empty_sections_are_isolated_and_secrets_never_exported(tmp_path, monkeypatch, caplog):
    env(tmp_path)
    empty = '<Response><Status code="200">OK</Status></Response>'
    seen = mock_api(monkeypatch, {('Icheon', 'NATRule'): RuntimeError('Firewall API 500: secret <Password>secret</Password> request dump'),
                                ('Seoul', 'UnicastRoute'): TimeoutError('secret request dump'),
                                ('Anseong', 'NATRule'): empty, ('Anseong', 'UnicastRoute'): empty})
    result = FirewallRuleExportService(tmp_path).build(['Cloud', 'Seoul', 'Icheon', 'Anseong'])
    assert result['sheets'][-3:] == ['Export Errors', 'NAT', 'Route']
    assert result['natCounts'] == {'Cloud': 2, 'Seoul': 2, 'Anseong': 0}
    assert result['routeCounts'] == {'Cloud': 1, 'Icheon': 1, 'Anseong': 0}
    assert len(result['errors']) == 2 and {row['Firewall'] for row in result['errors']} == {'Icheon', 'Seoul'}
    with ZipFile(result['path']) as archive:
        xml = '\n'.join(archive.read(name).decode() for name in archive.namelist() if name.endswith('.xml'))
        assert 'No data' in xml and '조회 실패' in xml and 'NATRule' in xml and 'UnicastRoute' in xml
        assert 'secret' not in xml + caplog.text + str(result)
    assert len([1 for name, entity in seen if name == 'Anseong' and entity == 'UnicastRoute']) == 1


def test_selected_device_sections_are_sorted_without_querying_unselected_devices(tmp_path, monkeypatch):
    env(tmp_path); seen = mock_api(monkeypatch)
    result = FirewallRuleExportService(tmp_path).build(['Anseong', 'Cloud'])
    assert result['sheets'][:2] == ['Anseong', 'Cloud']  # Existing caller-selected order remains unchanged.
    assert {name for name, entity in seen} == {'Cloud', 'Anseong'}
    with ZipFile(result['path']) as archive:
        nat = ET.fromstring(archive.read('xl/worksheets/sheet6.xml'))
        titles = [text(row)[0] for row in nat.findall('m:sheetData/m:row', NS) if text(row) and text(row)[0].endswith('NAT Rules')]
        assert titles == ['Cloud NAT Rules', 'Anseong NAT Rules']


def test_nat_get_uses_existing_authenticated_read_transport(monkeypatch):
    client = FirewallClient({'name': 'Cloud', 'username': 'fixture', 'password': 'fixture', 'host': 'example.test', 'port': '4444', 'verify_ssl': False})
    calls = []
    monkeypatch.setattr(client, '_post_xml', lambda request: calls.append(request) or NAT)
    assert client.get('NATRule') == NAT
    assert '<Get><NATRule/></Get>' in calls[0] and '<Set' not in calls[0]
