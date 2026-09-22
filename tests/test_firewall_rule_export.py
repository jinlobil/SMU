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
    assert seen == list(ENTITIES)


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
