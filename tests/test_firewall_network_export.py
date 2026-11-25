from collections import Counter
from xml.etree import ElementTree as ET
from zipfile import ZipFile

import pytest

from backend.services.firewall import FirewallClient
from backend.services.firewall_network_export import (
    INTERFACE_COLUMNS, ZONE_COLUMNS, GATEWAY_COLUMNS, parse_interfaces, parse_aliases, parse_zones, parse_gateways, interface_cidr,
)
from backend.services.firewall_rule_export import FirewallRuleExportService
from backend.services.spreadsheet import write_xlsx_workbook
from test_firewall_rule_export import XML, env
from test_firewall_nat_route_export import NAT, ROUTE

NS = {'m': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
INTERFACE = '''<Response><Status code="200">OK</Status>
<Interface><IPv4Configuration>Enable</IPv4Configuration><IPv6Configuration>Disable</IPv6Configuration><Hardware>PortA</Hardware><Name>PortA</Name>
<InterfaceStatus>ON</InterfaceStatus><NetworkZone>LAN</NetworkZone><IPv4Assignment>DHCP</IPv4Assignment><IPAddress>192.0.2.11</IPAddress><Netmask>255.255.255.0</Netmask>
<InterfaceSpeed>Auto Negotiate</InterfaceSpeed><AutoNegotiation>Enable</AutoNegotiation><MTU>1500</MTU><MACAddress>02:00:00:00:00:01</MACAddress>
<MSS><OverrideMSS>Enable</OverrideMSS><MSSValue>1460</MSSValue></MSS><Status>Connected, FEC off</Status><BreakoutMembers><Interface>Not a record</Interface></BreakoutMembers></Interface>
<Interface><Hardware>PortB</Hardware><Name>PortB</Name><InterfaceStatus>ON</InterfaceStatus><NetworkZone>WAN</NetworkZone><IPv4Assignment>Static</IPv4Assignment>
<IPAddress>198.51.100.201</IPAddress><Netmask>255.255.255.0</Netmask><GatewayName>PortB_GW</GatewayName><GatewayIP>198.51.100.1</GatewayIP></Interface></Response>'''
ALIAS = '''<Response><Status code="200">OK</Status><Alias><Interface>PortB</Interface><Name>PortB:0</Name><IPFamily>IPv4</IPFamily><IPAddress>198.51.100.202</IPAddress><Netmask>255.255.255.0</Netmask></Alias>
<Alias><Interface>PortB</Interface><Name>PortB:1</Name><IPFamily>IPv4</IPFamily><IPAddress>198.51.100.203</IPAddress><Netmask>255.255.255.0</Netmask></Alias>
<Alias><Interface>UnknownParent</Interface><Name>UnknownParent:0</Name><IPFamily>IPv4</IPFamily><IPAddress>203.0.113.5</IPAddress><Netmask>255.255.255.240</Netmask></Alias></Response>'''
ZONE = '''<Response><Status code="200">OK</Status><Zone><Name>LAN</Name><Type>System</Type><Description/><ApplianceAccess>
<AdminServices><HTTPS>Enable</HTTPS><SSH>Disable</SSH></AdminServices>
<AuthenticationServices><ClientAuthentication>Enable</ClientAuthentication><CaptivePortal>Disable</CaptivePortal><RadiusSSO>Enable</RadiusSSO><ChromebookSSO>Disable</ChromebookSSO></AuthenticationServices>
<NetworkServices><DNS>Enable</DNS><Ping>Enable</Ping></NetworkServices>
<OtherServices><WebProxy>Disable</WebProxy><UserPortal>Enable</UserPortal><WirelessProtection>Disable</WirelessProtection><SMTPRelay>Disable</SMTPRelay><SNMP>Enable</SNMP></OtherServices>
<VPNServices><VPNPortal>Enable</VPNPortal><SSLVPN>Disable</SSLVPN></VPNServices></ApplianceAccess></Zone>'''+''.join(f'<Zone><Name>{name}</Name><Type>System</Type><Description/></Zone>' for name in ('WAN','DMZ','LOCAL','VPN','Discover','WiFi'))+'</Response>'
GATEWAY = '''<Response><Status code="200">OK</Status><GatewayConfiguration><GatewayFailoverTimeout>60</GatewayFailoverTimeout>
<Gateway><Name>PortB_GW</Name><IPFamily>IPv4</IPFamily><IPAddress>198.51.100.1</IPAddress><Type>Active</Type><Weight>1</Weight>
<FailOverRules><Rule><Protocol>PING</Protocol><IPAddress>198.51.100.1</IPAddress><Port>*</Port><Condition/></Rule>
<Rule><Protocol>TCP</Protocol><IPAddress>203.0.113.8</IPAddress><Port>443</Port><Condition>AND</Condition></Rule></FailOverRules></Gateway>
<Gateway><Name>Other_GW</Name><IPFamily>IPv4</IPFamily><IPAddress>192.0.2.1</IPAddress><Type>Backup</Type><Weight>2</Weight></Gateway>
</GatewayConfiguration></Response>'''
PAYLOADS = {**XML, 'NATRule': NAT, 'UnicastRoute': ROUTE, 'Interface': INTERFACE, 'Alias': ALIAS, 'Zone': ZONE, 'GatewayConfiguration': GATEWAY}


def test_physical_interfaces_fields_host_cidr_and_optional_mss():
    rows = parse_interfaces(INTERFACE)
    assert len(rows) == 2 and list(rows[0]) == INTERFACE_COLUMNS
    nested = INTERFACE.replace('<Interface>Not a record</Interface>', '<Interface><Name>Nested reference</Name><NetworkZone>WAN</NetworkZone></Interface>')
    assert parse_interfaces(nested) == rows
    a, b = rows
    assert a['Name'] == a['Hardware'] == 'PortA' and a['Type'] == 'Physical'
    assert a['Zone'] == 'LAN' and a['IPv4 Assignment'] == 'DHCP'
    assert a['IP Address'] == '192.0.2.11' and a['Netmask'] == '255.255.255.0'
    assert a['CIDR'] == '192.0.2.11/24' and a['IP Family'] == 'IPv4'
    assert a['Interface Status'] == 'ON' and a['Status'] == 'Connected, FEC off'
    assert a['Interface Speed'] == 'Auto Negotiate' and a['Auto Negotiation'] == 'Enable'
    assert a['MTU'] == '1500' and a['MAC Address'] == '02:00:00:00:00:01'
    assert a['Gateway Name'] == a['Gateway IP'] == a['Parent Interface'] == ''
    assert b['IPv4 Assignment'] == 'Static' and b['Gateway Name'] == 'PortB_GW' and b['Gateway IP'] == '198.51.100.1'
    assert b['CIDR'] == '198.51.100.201/24'
    root = ET.fromstring(INTERFACE); root.find('Interface').remove(root.find('Interface/MSS'))
    assert parse_interfaces(ET.tostring(root, encoding='unicode')) == rows


@pytest.mark.parametrize('address,mask,cidr', [('192.0.2.201','255.255.255.0','192.0.2.201/24'),
    ('192.0.2.201','bad',''), ('192.0.2.201','255.0.255.0',''), ('bad','24',''), ('192.0.2.201','','')])
def test_interface_cidr_does_not_replace_host_with_network(address, mask, cidr):
    assert interface_cidr(address, mask) == cidr


def test_alias_parent_zone_inheritance_and_blank_physical_only_fields():
    physical = parse_interfaces(INTERFACE)
    aliases = parse_aliases(ALIAS, physical)
    assert [row['Name'] for row in aliases] == ['PortB:0', 'PortB:1', 'UnknownParent:0']
    assert [row['Zone'] for row in aliases] == ['WAN', 'WAN', '']
    assert aliases[0]['Parent Interface'] == 'PortB' and aliases[0]['Type'] == 'Alias'
    assert aliases[0]['IP Family'] == 'IPv4' and aliases[0]['CIDR'] == '198.51.100.202/24'
    for row in aliases:
        assert all(row[column] == '' for column in ('Hardware','IPv4 Assignment','Gateway Name','Gateway IP','Interface Status','Status','Interface Speed','Auto Negotiation','MTU','MAC Address'))
    assert all(row['Zone'] == '' for row in parse_aliases(ALIAS))
    assert parse_aliases(ALIAS.replace('255.255.255.0','bad'), physical)[0]['CIDR'] == ''


def test_all_zones_members_exclude_aliases_and_device_access_enabled_only():
    physical = parse_interfaces(INTERFACE)
    zones = parse_zones(ZONE, physical + parse_aliases(ALIAS, physical))
    assert [row['Name'] for row in zones] == ['LAN','WAN','DMZ','LOCAL','VPN','Discover','WiFi']
    assert list(zones[0]) == ZONE_COLUMNS and zones[0]['Type'] == 'System' and zones[0]['Description'] == ''
    assert zones[0]['Members'] == 'PortA' and zones[1]['Members'] == 'PortB'
    assert all(row['Members'] == '' for row in zones[2:])
    assert zones[0]['Device Access'] == 'HTTPS\nClient Authentication\nRadius SSO\nDNS\nPing\nUser Portal\nSNMP\nVPN Portal'
    assert all(row['Device Access'] == '' for row in zones[1:])
    assert 'PortB:0' not in zones[1]['Members']


@pytest.mark.parametrize('category,field,label', [
    ('AdminServices','HTTPS','HTTPS'), ('AdminServices','SSH','SSH'),
    ('AuthenticationServices','ClientAuthentication','Client Authentication'), ('AuthenticationServices','CaptivePortal','Captive Portal'),
    ('AuthenticationServices','RadiusSSO','Radius SSO'), ('AuthenticationServices','ChromebookSSO','Chromebook SSO'),
    ('NetworkServices','DNS','DNS'), ('NetworkServices','Ping','Ping'),
    ('OtherServices','WebProxy','Web Proxy'), ('OtherServices','UserPortal','User Portal'),
    ('OtherServices','WirelessProtection','Wireless Protection'), ('OtherServices','SMTPRelay','SMTP Relay'), ('OtherServices','SNMP','SNMP'),
    ('VPNServices','VPNPortal','VPN Portal'), ('VPNServices','SSLVPN','SSL VPN'),
])
def test_device_access_service_labels(category, field, label):
    xml = f'<Response><Zone><Name>fixture</Name><ApplianceAccess><{category}><{field}>Enable</{field}></{category}></ApplianceAccess></Zone></Response>'
    assert parse_zones(xml)[0]['Device Access'] == label
    assert parse_zones(xml.replace('Enable', 'Disable'))[0]['Device Access'] == ''


def test_gateway_timeout_is_global_and_failover_columns_preserve_rule_slots():
    rows, timeouts = parse_gateways(GATEWAY)
    assert timeouts == ['60'] and len(rows) == 2 and list(rows[0]) == GATEWAY_COLUMNS
    assert rows[0] == {'Name':'PortB_GW','IP Family':'IPv4','Gateway IP':'198.51.100.1','Type':'Active','Weight':'1',
        'Failover Protocol':'PING\nTCP','Failover Target':'198.51.100.1\n203.0.113.8','Failover Port':'*\n443','Failover Condition':'\nAND'}
    assert all(rows[1][column] == '' for column in GATEWAY_COLUMNS if column.startswith('Failover '))
    assert 'Timeout' not in str(list(rows[0]))
    assert not any(column in rows[0] for column in ('Status', 'Usage', 'RTT', 'Loss'))
    root=ET.fromstring(GATEWAY); rules=root.find('GatewayConfiguration/Gateway/FailOverRules'); rules.remove(rules[-1])
    row=parse_gateways(ET.tostring(root, encoding='unicode'))[0][0]
    assert row['Failover Protocol']=='PING' and row['Failover Condition']==''


@pytest.mark.parametrize('entity,parser', [('Interface',parse_interfaces),('Alias',parse_aliases),('Zone',parse_zones)])
def test_empty_and_optional_entity_fields(entity, parser):
    assert parser('<Response><Status code="200">OK</Status></Response>') == []
    rows=parser(f'<Response><{entity}><Name>minimal</Name></{entity}></Response>')
    assert len(rows)==1 and rows[0]['Name']=='minimal'
    with pytest.raises(RuntimeError): parser('<Response><Status code="500">failed</Status></Response>')


def test_empty_gateway_configuration_does_not_invent_timeout():
    assert parse_gateways('<Response><Status code="200">OK</Status></Response>') == ([],[])
    assert parse_gateways('<Response><GatewayConfiguration><GatewayFailoverTimeout>0</GatewayFailoverTimeout></GatewayConfiguration></Response>') == ([],['0'])


def mock_network(monkeypatch, overrides=None):
    calls=[]
    def get(client,entity):
        calls.append((client.name,entity))
        value=(overrides or {}).get((client.name,entity),PAYLOADS[entity])
        if isinstance(value,Exception):raise value
        return value
    monkeypatch.setattr(FirewallClient,'get',get)
    return calls


def text(row):return [cell.findtext('m:is/m:t',default='',namespaces=NS) for cell in row]


def test_complete_workbook_12_sheets_20_tables_and_old_nine_sheets_unchanged(tmp_path,monkeypatch):
    env(tmp_path); calls=mock_network(monkeypatch)
    import backend.services.firewall_rule_export as module
    specs=[]
    def capture(path,sheets):specs.extend(sheets);return write_xlsx_workbook(path,sheets)
    monkeypatch.setattr(module,'write_xlsx_workbook',capture)
    messages=[];result=FirewallRuleExportService(tmp_path).build(['Cloud','Seoul','Icheon','Anseong'],messages.append)
    assert result['sheets']==['Cloud','Seoul','Icheon','Anseong','LAN ↔ OFFICE','LAN ↔ WAN','ETC','NAT','Route','Interface','Zone','Gateway']
    assert result['errors']==[] and result['interfaceCounts']=={name:5 for name in ('Cloud','Seoul','Icheon','Anseong')}
    assert result['aliasCounts']=={name:3 for name in result['interfaceCounts']}
    assert result['zoneCounts']=={name:7 for name in result['interfaceCounts']}
    assert result['gatewayCounts']=={name:2 for name in result['interfaceCounts']}
    expected={'FirewallRule','IPHost','IPHostGroup','FQDNHost','FQDNHostGroup','Services','ServiceGroup','NATRule','UnicastRoute','Interface','Alias','Zone','GatewayConfiguration'}
    for name in result['interfaceCounts']:
        assert Counter(entity for device,entity in calls if name==device)=={entity:1 for entity in expected}
    assert any('GatewayConfiguration' in message for message in messages)
    baseline=tmp_path/'baseline.xlsx';write_xlsx_workbook(baseline,specs[:9])
    with ZipFile(result['path']) as archive,ZipFile(baseline) as old:
        assert archive.testzip() is None
        for filename in archive.namelist():
            if filename.endswith(('.xml','.rels')):ET.fromstring(archive.read(filename))
        for i in range(1,10):assert archive.read(f'xl/worksheets/sheet{i}.xml')==old.read(f'xl/worksheets/sheet{i}.xml')
        assert archive.read('xl/styles.xml')==old.read('xl/styles.xml')
        tables=[ET.fromstring(archive.read(filename)) for filename in archive.namelist() if filename.startswith('xl/tables/table')]
        assert len(tables)==20 and len({table.get('name') for table in tables})==20
        for number,kind,suffix in [(10,'interface','Interfaces'),(11,'zone','Zones'),(12,'gateway','Gateways')]:
            sheet=ET.fromstring(archive.read(f'xl/worksheets/sheet{number}.xml'))
            rows=sheet.findall('m:sheetData/m:row',NS)
            titles=[row for row in rows if text(row) and text(row)[0].endswith(suffix)]
            assert [text(row)[0] for row in titles]==[f'{name} {suffix}' for name in ('Cloud','Seoul','Icheon','Anseong')]
            own=[table for table in tables if table.get('name').startswith(f'tbl_{kind}_')]
            ends=[int(table.get('ref').split(':')[1][1:]) for table in own]
            for title,end in zip(titles[1:],ends):
                assert int(title.get('r'))==end+2
                assert not list(next(row for row in rows if int(row.get('r'))==end+1))
            assert sheet.find('m:sheetViews/m:sheetView/m:pane',NS).get('topLeftCell')==('A4' if kind=='gateway' else 'A3')
            assert sheet.find('m:autoFilter',NS) is None
            assert len(sheet.findall('m:tableParts/m:tablePart',NS))==4
            assert all(float(col.get('width'))<=60 for col in sheet.findall('m:cols/m:col',NS))
        gateway=archive.read('xl/worksheets/sheet12.xml').decode()
        assert gateway.count('Gateway Failover Timeout : 60 sec')==4
        assert 'xml:space="preserve"' in gateway
        assert all(table.find('m:autoFilter',NS).get('ref')==table.get('ref') for table in tables)


@pytest.mark.parametrize('entity',['Interface','Alias','Zone','GatewayConfiguration'])
def test_each_entity_error_isolated_and_partial_data_kept(tmp_path,monkeypatch,caplog,entity):
    env(tmp_path)
    calls=mock_network(monkeypatch,{('Cloud',entity):RuntimeError('Firewall API 500: secret credential request dump')})
    import backend.services.firewall_rule_export as module
    specs=[]
    def capture(path,sheets):specs.extend(sheets);return write_xlsx_workbook(path,sheets)
    monkeypatch.setattr(module,'write_xlsx_workbook',capture)
    result=FirewallRuleExportService(tmp_path).build(['Cloud','Seoul','Icheon','Anseong'])
    assert len(result['errors'])==1 and entity in result['errors'][0]['Error Type']
    assert result['interfaceCounts']['Seoul']==5 and result['gatewayCounts']['Seoul']==2
    by_name={spec['name']:spec for spec in specs}
    interface=by_name['Interface']['sections'][0]; zone=by_name['Zone']['sections'][0]
    if entity=='Interface':
        assert len(interface['rows'])==3 and all(row['Zone']=='' for row in interface['rows'])
        assert all(row['Members']=='' for row in zone['rows']) and 'Members 확인 불가' in zone['notes'][0]
    if entity=='Alias':assert len(interface['rows'])==2 and 'Alias' in interface['notes'][0]
    if entity=='Zone':assert len(interface['rows'])==5 and zone['message'].startswith('조회 실패')
    if entity=='GatewayConfiguration':assert by_name['Gateway']['sections'][0]['message'].startswith('조회 실패')
    assert Counter((name,e) for name,e in calls)[('Cloud',entity)]==1
    with ZipFile(result['path']) as archive:
        xml='\n'.join(archive.read(name).decode() for name in archive.namelist() if name.endswith('.xml'))
        assert '조회 실패' in xml and 'secret' not in xml+str(result)+caplog.text


def test_successful_empty_entities_have_no_data_and_keep_sections(tmp_path,monkeypatch):
    env(tmp_path)
    empty='<Response><Status code="200">OK</Status></Response>'
    mock_network(monkeypatch,{('Cloud',entity):empty for entity in ('Interface','Alias','Zone','GatewayConfiguration')})
    result=FirewallRuleExportService(tmp_path).build(['Cloud'])
    assert result['errors']==[] and all(result[key]=={'Cloud':0} for key in ('interfaceCounts','aliasCounts','zoneCounts','gatewayCounts'))
    with ZipFile(result['path']) as archive:
        for index in (7,8,9):
            xml=archive.read(f'xl/worksheets/sheet{index}.xml').decode()
            assert 'No data' in xml and '조회 실패' not in xml


@pytest.mark.parametrize('entity',['Interface','Alias','Zone','GatewayConfiguration'])
def test_new_entities_use_existing_authenticated_get_only(monkeypatch,entity):
    client=FirewallClient({'name':'Cloud','host':'example.test','port':'4444','username':'fixture','password':'fixture','verify_ssl':False})
    calls=[]
    monkeypatch.setattr(client,'_post_xml',lambda request:calls.append(request) or PAYLOADS[entity])
    client.get(entity)
    assert len(calls)==1 and f'<Get><{entity}/></Get>' in calls[0] and '<Set' not in calls[0]
