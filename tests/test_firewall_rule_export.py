from pathlib import Path
from zipfile import ZipFile

import pytest

from backend.services.firewall import FirewallClient
from backend.services.firewall_rule_export import ENTITIES, FirewallRuleExportService, parse_firewall_rules
from backend.services.spreadsheet import safe_sheet_name


XML = {
    "FirewallRule": '''<Response><Status code="200">OK</Status><FirewallRule><Name>Allow Web</Name><Status>Enable</Status><Action>Accept</Action><SourceZones><Zone>LAN</Zone></SourceZones><SourceNetworks><Network>Office Hosts</Network></SourceNetworks><DestinationZones><Zone>WAN</Zone></DestinationZones><DestinationNetworks><Network>portal.example.com</Network></DestinationNetworks><Services><Service>HTTPS</Service></Services><Schedule>All The Time</Schedule><LogTraffic>Enable</LogTraffic><WebFilterPolicy>Default</WebFilterPolicy><ApplicationControlPolicy>Allow Apps</ApplicationControlPolicy><IPSPolicy>LAN TO WAN</IPSPolicy><CustomUsefulField>preserved</CustomUsefulField></FirewallRule></Response>''',
    "IPHost": '''<Response><Status code="200">OK</Status><IPHost><Name>PC-1</Name><IPAddress>10.0.0.1</IPAddress></IPHost></Response>''',
    "IPHostGroup": '''<Response><Status code="200">OK</Status><IPHostGroup><Name>Office Hosts</Name><HostList><IPHost>PC-1</IPHost></HostList></IPHostGroup></Response>''',
    "FQDNHost": '''<Response><Status code="200">OK</Status><FQDNHost><Name>portal.example.com</Name><FQDN>portal.example.com</FQDN></FQDNHost></Response>''',
    "FQDNHostGroup": '''<Response><Status code="200">OK</Status></Response>''',
    "Service": '''<Response><Status code="200">OK</Status><Service><Name>HTTPS</Name><Protocol>TCP</Protocol><DestinationPort>443</DestinationPort></Service></Response>''',
    "ServiceGroup": '''<Response><Status code="200">OK</Status></Response>''',
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
    assert row["Source Object"] == "Office Hosts"
    assert "PC-1 (10.0.0.1)" in row["Source Resolved"]
    assert row["Destination Resolved"] == "portal.example.com"
    assert row["Service Resolved / Protocol / Port"] == "TCP / 443"
    assert row["XML: CustomUsefulField"] == "preserved"
    assert "XML: CustomUsefulField" in columns


def test_selected_firewalls_make_only_selected_sheets(tmp_path: Path, monkeypatch) -> None:
    env(tmp_path)
    monkeypatch.setattr(FirewallClient, "get", lambda _self, entity: XML[entity])
    result = FirewallRuleExportService(tmp_path).build(["Cloud", "Icheon"])
    workbook = sheet_names(Path(result["path"]))
    assert result["sheets"] == ["Cloud", "Icheon"]
    assert 'name="Seoul"' not in workbook and 'name="Anseong"' not in workbook


def test_all_configured_firewalls_make_one_sheet_each(tmp_path: Path, monkeypatch) -> None:
    env(tmp_path)
    monkeypatch.setattr(FirewallClient, "get", lambda _self, entity: XML[entity])
    result = FirewallRuleExportService(tmp_path).build(["Cloud", "Seoul", "Icheon", "Anseong"])
    assert result["sheets"] == ["Cloud", "Seoul", "Icheon", "Anseong"]


def test_one_firewall_failure_keeps_successful_sheets_and_error_sheet(tmp_path: Path, monkeypatch) -> None:
    env(tmp_path, ("Cloud", "Seoul"))
    def get(client, entity):
        if client.name == "Seoul":
            raise TimeoutError("timed out")
        return XML[entity]
    monkeypatch.setattr(FirewallClient, "get", get)
    result = FirewallRuleExportService(tmp_path).build(["Cloud", "Seoul"])
    assert result["sheets"] == ["Cloud", "Export Errors"]
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
    assert result["sheets"] == ["Export Errors"]
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
    assert rows[0]["Rule Name"] == "Allow Web"
    assert rows[0]["Action"] == "Accept"


def test_legacy_firewall_fallback_builds_sheet_and_diagnostics(tmp_path: Path, monkeypatch) -> None:
    env(tmp_path, ("Cloud",))
    legacy_rules = XML["FirewallRule"].replace('<Response>', '<Response APIVersion="1700.1">').replace("FirewallRule", "SecurityPolicy")
    def post(_client, request: str) -> str:
        if "<FirewallRule/>" in request:
            return '<Response APIVersion="1700.1"><Status code="529">Input request module is Invalid</Status></Response>'
        if "<SecurityPolicy/>" in request:
            return legacy_rules
        return next(XML[entity] for entity in ENTITIES if f"<{entity}/>" in request)
    monkeypatch.setattr(FirewallClient, "_post_xml", post)
    result = FirewallRuleExportService(tmp_path).build(["Cloud"])
    assert result["sheets"] == ["Cloud"]
    assert result["counts"] == {"Cloud": 1}
    assert result["diagnostics"]["Cloud"] == {"apiVersion": "1700.1", "ruleEntity": "SecurityPolicy"}


def test_object_entity_529_identifies_the_incompatible_module(tmp_path: Path, monkeypatch) -> None:
    env(tmp_path, ("Cloud",))
    def get(_client, entity):
        if entity == "IPHostGroup":
            return '<Response APIVersion="2000.2"><Status code="529">Input request module is Invalid</Status></Response>'
        return XML[entity]
    monkeypatch.setattr(FirewallClient, "get", get)
    result = FirewallRuleExportService(tmp_path).build(["Cloud"])
    assert result["sheets"] == ["Export Errors"]
    assert "entity IPHostGroup 529" in result["errors"][0]["Message"]
