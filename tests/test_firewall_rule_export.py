from pathlib import Path
from zipfile import ZipFile

import pytest

from backend.services.firewall import FirewallClient
from backend.services.firewall_rule_export import ENTITIES, FirewallRuleExportService, classify_parsed_rule, parse_firewall_rules
from backend.services.spreadsheet import safe_sheet_name


XML = {
    "FirewallRule": '''<Response APIVersion="2000.2"><Status code="200">OK</Status><FirewallRule><Name>FW_IN_SEOUL_VPN_PDA_TO_AWS_WMS</Name><Status>Enable</Status><PolicyType>Network</PolicyType><Description>Seoul VPN to WMS</Description><NetworkPolicy><PolicyGroup>SSL_PDA &gt; WMS</PolicyGroup><SourceZones><Zone>VPN</Zone></SourceZones><SourceNetworks><Network>Office Hosts</Network></SourceNetworks><DestinationZones><Zone>LAN</Zone></DestinationZones><DestinationNetworks><Network>portal.example.com</Network></DestinationNetworks><Services><Service>Web Ports</Service></Services><Exclusions><SourceNetworks><Network>Excluded Source</Network></SourceNetworks><DestinationNetworks><Network>Excluded Destination</Network></DestinationNetworks><Services><Service>Excluded Service</Service></Services></Exclusions><Action>Accept</Action><Schedule>All The Time</Schedule><IntrusionPrevention>LAN TO WAN</IntrusionPrevention><MalwareScanning>Enable</MalwareScanning><WebFilterPolicy>Default</WebFilterPolicy><ApplicationControlPolicy>Allow Apps</ApplicationControlPolicy><TrafficShapingPolicy>QoS Standard</TrafficShapingPolicy><MinimumSourceHBPermitted>Green</MinimumSourceHBPermitted><LinkedNATRule>NAT_37</LinkedNATRule><ProxyMode>Disable</ProxyMode><LogTraffic>Enable</LogTraffic></NetworkPolicy></FirewallRule></Response>''',
    "IPHost": '''<Response APIVersion="2000.2"><Status code="200">OK</Status><IPHost><Name>PC-1</Name><HostType>IP</HostType><IPAddress>10.0.0.1</IPAddress></IPHost><IPHost><Name>Office Network</Name><HostType>Network</HostType><IPAddress>10.10.0.0</IPAddress><Subnet>255.255.0.0</Subnet></IPHost><IPHost><Name>VPN Range</Name><HostType>IPRange</HostType><StartIPAddress>10.20.0.1</StartIPAddress><EndIPAddress>10.20.0.50</EndIPAddress></IPHost><IPHost><Name>DNS List</Name><HostType>IPList</HostType><ListOfIPAddresses><IPAddress>1.1.1.1</IPAddress><IPAddress>8.8.8.8</IPAddress></ListOfIPAddresses></IPHost></Response>''',
    "IPHostGroup": '''<Response APIVersion="2000.2"><Status code="200">OK</Status><IPHostGroup><Name>Office Hosts</Name><HostList><IPHost>PC-1</IPHost><IPHost>Office Network</IPHost><IPHost>VPN Range</IPHost><IPHost>DNS List</IPHost></HostList></IPHostGroup></Response>''',
    "FQDNHost": '''<Response><Status code="200">OK</Status><FQDNHost><Name>portal.example.com</Name><FQDN>portal.example.com</FQDN></FQDNHost></Response>''',
    "FQDNHostGroup": '''<Response><Status code="200">OK</Status></Response>''',
    "Services": '''<Response APIVersion="2000.2"><Status code="200">OK</Status><Services><Name>Web Ports</Name><Type>TCPorUDP</Type><ServiceDetails><ServiceDetail><Protocol>TCP</Protocol><SourcePort>1:65535</SourcePort><DestinationPort>80</DestinationPort></ServiceDetail><ServiceDetail><Protocol>TCP</Protocol><SourcePort>1024:65535</SourcePort><DestinationPort>443</DestinationPort></ServiceDetail></ServiceDetails></Services></Response>''',
    "ServiceGroup": '''<Response APIVersion="2000.2"><Status code="200">OK</Status></Response>''',
}


def env(root: Path, names=("Cloud", "Seoul", "Icheon", "Anseong")) -> None:
    prefixes = {"Cloud": "", "Seoul": "SEOUL_", "Icheon": "ICHEON_", "Anseong": "ANSEONG_"}
    lines = []
    for name in names:
        stem = f"FW_{prefixes[name]}"
        lines += [f"{stem}HOST={name.lower()}.local", f"{stem}PORT=4444", f"{stem}USERNAME=admin", f"{stem}PASSWORD=secret"]
    path = root / "env/Firewall_env.txt"; path.parent.mkdir(parents=True); path.write_text("\n".join(lines), encoding="utf-8")


def sheet_names(path: Path) -> str:
    with ZipFile(path) as archive:
        return archive.read("xl/workbook.xml").decode()


def test_rule_parser_resolves_hosts_groups_fqdn_services_and_preserves_xml() -> None:
    rows, columns = parse_firewall_rules(XML)
    row = rows[0]
    assert row["Rule Group"] == "SSL_PDA > WMS"
    assert row["Rule Name"] == "FW_IN_SEOUL_VPN_PDA_TO_AWS_WMS"
    assert row["Status"] == "활성"
    assert row["Policy Type"] == "Network"
    assert row["Description"] == "Seoul VPN to WMS"
    assert row["Source Object"] == "Office Hosts"
    assert "PC-1 (10.0.0.1)" in row["Source Resolved"]
    assert row["Destination Resolved"] == "portal.example.com"
    assert "Protocol: TCP | Source: 1:65535 | Destination: 80" in row["Service Resolved / Protocol / Port"]
    assert "Protocol: TCP | Source: 1024:65535 | Destination: 443" in row["Service Resolved / Protocol / Port"]
    assert "Rule ID" not in columns
    assert "Order" not in columns
    assert row["IPS"] == "LAN TO WAN"
    assert row["AV"] == "Enable"
    assert row["Web"] == "Default"
    assert row["Application"] == "Allow Apps"
    assert row["QoS"] == "QoS Standard"
    assert row["Heartbeat"] == "Green"
    assert row["Linked NAT"] == "NAT_37"
    assert row["Proxy"] == "Disable"
    assert row["Log"] == "Enable"
    assert all(not column.startswith("XML:") for column in columns)


def test_selected_firewalls_make_only_selected_sheets(tmp_path: Path, monkeypatch) -> None:
    env(tmp_path)
    monkeypatch.setattr(FirewallClient, "get", lambda _self, entity: XML[entity])
    result = FirewallRuleExportService(tmp_path).build(["Cloud", "Icheon"])
    workbook = sheet_names(Path(result["path"]))
    assert result["sheets"] == ["Cloud", "Icheon", "LAN ↔ OFFICE", "LAN ↔ WAN", "ETC"]
    assert 'name="Seoul"' not in workbook and 'name="Anseong"' not in workbook


def test_all_configured_firewalls_make_one_sheet_each(tmp_path: Path, monkeypatch) -> None:
    env(tmp_path)
    monkeypatch.setattr(FirewallClient, "get", lambda _self, entity: XML[entity])
    result = FirewallRuleExportService(tmp_path).build(["Cloud", "Seoul", "Icheon", "Anseong"])
    assert result["sheets"] == ["Cloud", "Seoul", "Icheon", "Anseong", "LAN ↔ OFFICE", "LAN ↔ WAN", "ETC"]
    assert sum(result["counts"].values()) == sum(result["analysisCounts"].values()) == 4


def test_one_firewall_failure_keeps_successful_sheets_and_error_sheet(tmp_path: Path, monkeypatch) -> None:
    env(tmp_path, ("Cloud", "Seoul"))
    def get(client, entity):
        if client.name == "Seoul":
            raise TimeoutError("timed out")
        return XML[entity]
    monkeypatch.setattr(FirewallClient, "get", get)
    result = FirewallRuleExportService(tmp_path).build(["Cloud", "Seoul"])
    assert result["sheets"] == ["Cloud", "LAN ↔ OFFICE", "LAN ↔ WAN", "ETC", "Export Errors"]
    assert result["errors"] == [{"Firewall": "Seoul", "Error Type": "Connection Timeout", "Message": "timed out"}]


def test_export_queries_all_required_xml_entities(tmp_path: Path, monkeypatch) -> None:
    env(tmp_path, ("Cloud",)); seen = []
    def get(_client, entity):
        seen.append(entity); return XML[entity]
    monkeypatch.setattr(FirewallClient, "get", get)
    FirewallRuleExportService(tmp_path).build(["Cloud"])
    assert seen == ["FirewallRule", *ENTITIES]


def test_malformed_rule_xml_is_reported_without_broken_workbook(tmp_path: Path, monkeypatch) -> None:
    env(tmp_path, ("Cloud",))
    monkeypatch.setattr(FirewallClient, "get", lambda _self, entity: "<broken" if entity == "FirewallRule" else XML[entity])
    result = FirewallRuleExportService(tmp_path).build(["Cloud"])
    assert result["sheets"] == ["LAN ↔ OFFICE", "LAN ↔ WAN", "ETC", "Export Errors"]
    assert result["errors"][0]["Error Type"] == "XML Parse Error"
    assert Path(result["path"]).read_bytes().startswith(b"PK")


def test_sheet_names_are_excel_safe_and_unique() -> None:
    used: set[str] = set()
    first = safe_sheet_name("Seoul/Firewall:Primary*Very-Long-Worksheet-Name", used)
    second = safe_sheet_name("Seoul/Firewall:Primary*Very-Long-Worksheet-Name", used)
    assert len(first) <= 31 and len(second) <= 31
    assert first != second
    assert not set("[]:*?/\\") & set(first + second)


def test_rule_entity_falls_back_only_for_529_invalid_module(monkeypatch) -> None:
    client = FirewallClient({"name": "Cloud", "host": "cloud", "port": "4444", "username": "u", "password": "p", "verify_ssl": False})
    calls: list[str] = []
    responses = iter([
        '<Response APIVersion="1700.1"><Status code="529">Input request module is Invalid</Status></Response>',
        '<Response APIVersion="1700.1"><Status code="200">OK</Status><SecurityPolicy><Name>Legacy Rule</Name></SecurityPolicy></Response>',
    ])
    def post(_request: str) -> str:
        calls.append(_request); return next(responses)
    monkeypatch.setattr(client, "_post_xml", post)
    result = client.get_rules_compatible()
    assert result["entity"] == "SecurityPolicy"
    assert result["apiVersion"] == "1700.1"
    assert "<FirewallRule/>" in calls[0] and "<SecurityPolicy/>" in calls[1]


def test_rule_entity_does_not_fallback_for_other_failures(monkeypatch) -> None:
    client = FirewallClient({"name": "Cloud", "host": "cloud", "port": "4444", "username": "u", "password": "p", "verify_ssl": False})
    calls: list[str] = []
    monkeypatch.setattr(client, "_post_xml", lambda request: calls.append(request) or '<Response APIVersion="2000.2"><Status code="500">Other error</Status></Response>')
    result = client.get_rules_compatible()
    assert result["entity"] == "FirewallRule"
    assert len(calls) == 1


def test_security_policy_is_parsed_into_same_rule_model() -> None:
    payloads = dict(XML)
    payloads["Rule"] = XML["FirewallRule"].replace("FirewallRule", "SecurityPolicy")
    rows, _columns = parse_firewall_rules(payloads, "SecurityPolicy")
    assert rows[0]["Rule Name"] == "FW_IN_SEOUL_VPN_PDA_TO_AWS_WMS"
    assert rows[0]["Action"] == "Accept"


def test_legacy_firewall_fallback_builds_sheet_and_diagnostics(tmp_path: Path, monkeypatch) -> None:
    env(tmp_path, ("Cloud",))
    legacy_rules = XML["FirewallRule"].replace('APIVersion="2000.2"', 'APIVersion="1700.1"').replace("FirewallRule", "SecurityPolicy")
    def post(_client, request: str) -> str:
        if "<FirewallRule/>" in request:
            return '<Response APIVersion="1700.1"><Status code="529">Input request module is Invalid</Status></Response>'
        if "<SecurityPolicy/>" in request:
            return legacy_rules
        return next(XML[entity] for entity in ENTITIES if f"<{entity}/>" in request)
    monkeypatch.setattr(FirewallClient, "_post_xml", post)
    result = FirewallRuleExportService(tmp_path).build(["Cloud"])
    assert result["sheets"] == ["Cloud", "LAN ↔ OFFICE", "LAN ↔ WAN", "ETC"]
    assert result["counts"] == {"Cloud": 1}
    assert result["diagnostics"]["Cloud"] == {"apiVersion": "1700.1", "ruleEntity": "SecurityPolicy", "enrichmentErrors": []}


def test_object_entity_529_is_reported_without_losing_rule_sheet(tmp_path: Path, monkeypatch) -> None:
    env(tmp_path, ("Cloud",))
    def get(_client, entity):
        if entity == "IPHostGroup":
            return '<Response APIVersion="2000.2"><Status code="529">Input request module is Invalid</Status></Response>'
        return XML[entity]
    monkeypatch.setattr(FirewallClient, "get", get)
    result = FirewallRuleExportService(tmp_path).build(["Cloud"])
    assert result["sheets"] == ["Cloud", "LAN ↔ OFFICE", "LAN ↔ WAN", "ETC"]
    assert result["errors"] == []
    assert "entity IPHostGroup 529" in result["diagnostics"]["Cloud"]["enrichmentErrors"][0]


def test_iphost_types_preserve_network_range_and_list_values() -> None:
    rows, _ = parse_firewall_rules(XML)
    resolved = rows[0]["Source Resolved"]
    assert "Office Network (10.10.0.0 / 255.255.0.0)" in resolved
    assert "VPN Range (10.20.0.1 - 10.20.0.50)" in resolved
    assert "DNS List (1.1.1.1\n8.8.8.8)" in resolved


def test_rule_exclusions_do_not_leak_into_management_columns() -> None:
    row = parse_firewall_rules(XML)[0][0]
    assert row["Source Object"] == "Office Hosts"
    assert row["Destination Object"] == "portal.example.com"
    assert row["Service"] == "Web Ports"
    assert "Excluded Source" not in row["Source Object"]
    assert "Excluded Destination" not in row["Destination Object"]
    assert "Excluded Service" not in row["Service"]


def test_services_request_uses_plural_sophos_entity(monkeypatch) -> None:
    client = FirewallClient({"name": "Cloud", "host": "cloud", "port": "4444", "username": "u", "password": "p", "verify_ssl": False})
    requests: list[str] = []
    monkeypatch.setattr(client, "_post_xml", lambda request: requests.append(request) or XML["Services"])
    client.get("Services")
    assert "<Services/>" in requests[0]


def test_services_failure_still_creates_rule_sheet(tmp_path: Path, monkeypatch) -> None:
    env(tmp_path, ("Cloud",))
    def get(_client, entity):
        if entity == "Services":
            raise TimeoutError("services unavailable")
        return XML[entity]
    monkeypatch.setattr(FirewallClient, "get", get)
    result = FirewallRuleExportService(tmp_path).build(["Cloud"])
    assert result["sheets"] == ["Cloud", "LAN ↔ OFFICE", "LAN ↔ WAN", "ETC"]
    assert result["counts"] == {"Cloud": 1}
    assert result["errors"] == []
    assert result["diagnostics"]["Cloud"]["enrichmentErrors"][0].startswith("Services: TimeoutError")


def test_nat_columns_are_not_in_firewall_rule_export() -> None:
    _rows, columns = parse_firewall_rules(XML)
    assert "NAT Policy" not in columns
    assert "Source NAT" not in columns
    assert "Destination NAT" not in columns


def test_network_and_user_policies_are_rows_but_group_header_is_not() -> None:
    payloads = dict(XML)
    payloads["Rule"] = '''<Response APIVersion="2000.2"><Status code="200">OK</Status><FirewallRuleGroup><Name>SSL_PDA &gt; WMS</Name><FirewallRule><Name>Network Rule</Name><Status>Enable</Status><PolicyType>Network</PolicyType><NetworkPolicy/></FirewallRule></FirewallRuleGroup><FirewallRule><Name>User Rule</Name><Status>Disable</Status><PolicyType>User</PolicyType><UserPolicy><PolicyGroup>Identity Rules</PolicyGroup></UserPolicy></FirewallRule></Response>'''
    rows, _columns = parse_firewall_rules(payloads)
    assert [(row["Rule Group"], row["Rule Name"], row["Status"]) for row in rows] == [
        ("SSL_PDA > WMS", "Network Rule", "활성"),
        ("Identity Rules", "User Rule", "비활성"),
    ]


def test_real_root_rule_id_is_first_column_but_is_never_synthesized() -> None:
    payloads = dict(XML)
    payloads["Rule"] = XML["FirewallRule"].replace("<Name>FW_IN", "<RuleID>#43</RuleID><Name>FW_IN")
    rows, columns = parse_firewall_rules(payloads)
    assert columns[0] == "Rule ID"
    assert rows[0]["Rule ID"] == "43"


def test_export_styles_only_the_localized_status_cell(tmp_path: Path, monkeypatch) -> None:
    env(tmp_path, ("Cloud",))
    monkeypatch.setattr(FirewallClient, "get", lambda _self, entity: XML[entity])
    result = FirewallRuleExportService(tmp_path).build(["Cloud"])
    with ZipFile(result["path"]) as workbook:
        sheet = workbook.read("xl/worksheets/sheet1.xml").decode()
        styles = workbook.read("xl/styles.xml").decode()
    assert 'r="B2" t="inlineStr" s="3"' in sheet
    assert 'fgColor rgb="FFC6F6D5"' in styles
    assert 'fgColor rgb="FFFED7D7"' in styles


def test_analysis_sheet_adds_firewall_and_derived_columns_without_changing_master(tmp_path: Path, monkeypatch) -> None:
    env(tmp_path, ("Cloud",))
    monkeypatch.setattr(FirewallClient, "get", lambda _self, entity: XML[entity])
    result = FirewallRuleExportService(tmp_path).build(["Cloud"])
    with ZipFile(result["path"]) as workbook:
        master = workbook.read("xl/worksheets/sheet1.xml").decode()
        etc = workbook.read("xl/worksheets/sheet4.xml").decode()
    assert "Source Category" not in master and "Destination Site" not in master
    assert "Firewall" in etc and "Source Category" in etc and "Destination Site" in etc
    assert "Cloud" in etc
