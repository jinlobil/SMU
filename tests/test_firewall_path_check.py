import ipaddress
from pathlib import Path

import pytest

from backend.services.firewall import FirewallClient
from backend.services.firewall_network_mapping import determine_firewall_path, resolve_input_network
from backend.services.firewall_path_check import FirewallPathCheckService, address_match, match_rules, match_static_route, parse_unicast_routes, service_match


def rule(name: str, source: str, destination: str, service: str, *, status: str = "활성", action: str = "Allow") -> dict[str, str]:
    return {"Rule Name": name, "Status": status, "Action": action, "Source Object": name, "Source Resolved": source, "Destination Object": name, "Destination Resolved": destination, "Service": "service", "Service Resolved / Protocol / Port": service}


def test_unicast_route_uses_existing_authenticated_firewall_client(monkeypatch) -> None:
    requests: list[str] = []
    client = FirewallClient({"name": "Cloud", "host": "cloud", "port": "4444", "username": "u", "password": "p", "verify_ssl": False})
    monkeypatch.setattr(client, "_post_xml", lambda xml: requests.append(xml) or "<Response/>")
    client.get("UnicastRoute")
    assert "<Login><Username>u</Username><Password>p</Password></Login>" in requests[0]
    assert "<Get><UnicastRoute/></Get>" in requests[0]


@pytest.mark.parametrize(("source", "destination", "expected"), [
    ("101.1.0.50", "100.1.2.10", ["Seoul", "Cloud"]),
    ("101.3.0.10", "100.1.2.10", ["Icheon", "Cloud"]),
    ("100.1.2.10", "101.1.0.50", ["Cloud", "Seoul"]),
])
def test_managed_firewall_paths(source: str, destination: str, expected: list[str]) -> None:
    path, partial = determine_firewall_path(resolve_input_network(source), resolve_input_network(destination))
    assert path == expected and partial is False


def test_unmanaged_office_path_is_explicitly_partial() -> None:
    path, partial = determine_firewall_path(resolve_input_network("102.1.1.1"), resolve_input_network("100.1.2.10"))
    assert path == ["Cloud"] and partial is True


def test_address_matching_supports_ip_cidr_group_and_partial() -> None:
    assert address_match(ipaddress.ip_network("101.1.0.50/32"), "Direct", "101.1.0.50") == "full"
    assert address_match(ipaddress.ip_network("101.1.0.0/22"), "Group", "Member (101.1.0.0/22)") == "full"
    assert address_match(ipaddress.ip_network("101.1.0.0/22"), "Narrow", "101.1.0.0/24") == "partial"
    assert address_match(ipaddress.ip_network("101.1.0.0/22"), "Other", "101.2.0.0/24") == "none"


def test_service_matching_supports_direct_group_range_and_any() -> None:
    assert service_match("TCP", 389, "TCP_389", "Protocol: TCP | Destination: 389")
    assert service_match("TCP", 389, "AD_SERVICE_GROUP", "TCP_389 (Protocol: TCP | Destination: 389)")
    assert service_match("TCP", 389, "Range", "Protocol: TCP | Destination: 300:400")
    assert service_match("UDP", 53, "Any", "")
    assert not service_match("UDP", 389, "TCP", "Protocol: TCP | Destination: 389")


def test_policy_states_allow_disabled_deny_and_order_unknown() -> None:
    source, destination = ipaddress.ip_network("101.1.0.50"), ipaddress.ip_network("100.1.2.10")
    service = "Protocol: TCP | Destination: 389"
    assert match_rules([rule("allow", "101.1.0.0/22", "100.1.0.0/22", service)], source, destination, "TCP", 389)["state"] == "allow"
    assert match_rules([rule("disabled", "101.1.0.0/22", "100.1.0.0/22", service, status="비활성")], source, destination, "TCP", 389)["state"] == "disabled"
    assert match_rules([rule("deny", "101.1.0.0/22", "100.1.0.0/22", service, action="Deny")], source, destination, "TCP", 389)["state"] == "deny"
    result = match_rules([rule("deny first", "101.1.0.0/22", "100.1.0.0/22", service, action="Deny"), rule("allow later", "101.1.0.0/22", "100.1.0.0/22", service)], source, destination, "TCP", 389)
    assert result["state"] == "order_check_required" and result["orderReliable"] is False


def test_static_route_exact_prefix_longest_and_missing() -> None:
    xml = '''<Response><Status code="200">OK</Status><UnicastRoute><Destination>100.1.0.0</Destination><Netmask>255.255.0.0</Netmask><Gateway>1.1.1.1</Gateway><Interface>Port1</Interface></UnicastRoute><UnicastRoute><Destination>100.1.0.0</Destination><Netmask>255.255.252.0</Netmask><Gateway>2.2.2.2</Gateway><Interface>IPsec</Interface><AdministrativeDistance>1</AdministrativeDistance><Status>Enable</Status><Description>AWS</Description></UnicastRoute></Response>'''
    routes = parse_unicast_routes(xml)
    matched = match_static_route(routes, ipaddress.ip_network("100.1.2.10"))
    assert matched["network"] == "100.1.0.0/22" and matched["gateway"] == "2.2.2.2"
    assert match_static_route(routes, ipaddress.ip_network("8.8.8.8")) is None
    assert match_static_route([{"destination": "8.8.8.0", "netmask": "24", "status": "Disable"}], ipaddress.ip_network("8.8.8.8")) is None


def test_snapshot_cache_and_refresh_only_refetch_requested_firewall(tmp_path: Path, monkeypatch) -> None:
    service = FirewallPathCheckService(tmp_path, ttl_seconds=300); calls = []
    rule_xml = '''<Response><Status code="200">OK</Status><FirewallRule><Name>Rule</Name><Status>Enable</Status><NetworkPolicy/></FirewallRule></Response>'''
    monkeypatch.setattr(FirewallClient, "get_rules_compatible", lambda self: calls.append((self.name,"rules")) or {"raw":rule_xml,"entity":"FirewallRule","apiVersion":""})
    monkeypatch.setattr(FirewallClient, "get", lambda self, entity: calls.append((self.name,entity)) or '<Response><Status code="200">OK</Status></Response>')
    config = {"name":"Cloud","host":"cloud","port":"4444","username":"u","password":"p","verify_ssl":False}
    service._snapshot(config, False); first = len(calls)
    service._snapshot(config, False); assert len(calls) == first
    service._snapshot(config, True); assert len(calls) > first


def test_network_mapping_failure_is_not_assigned_a_firewall() -> None:
    unresolved = resolve_input_network("192.168.55.10")
    assert unresolved["category"] == "" and unresolved["managedFirewall"] == ""
