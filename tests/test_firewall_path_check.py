import ipaddress
from pathlib import Path

import pytest

from backend.services.firewall import FirewallClient
from backend.services.firewall_network_mapping import determine_firewall_path, expected_zones_for_path, resolve_input_network
from backend.services.firewall_path_check import FirewallPathCheckService, address_match, address_match_details, match_rules, match_static_route, parse_unicast_routes, service_match, zone_match
from backend.services.firewall_rule_export import is_wildcard_value, parse_firewall_rules


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
    ("101.1.3.50", "52.79.112.47", ["Seoul"]),
    ("101.3.0.10", "52.79.112.47", ["Icheon"]),
    ("101.2.1.10", "52.79.112.47", ["Anseong"]),
])
def test_managed_firewall_paths(source: str, destination: str, expected: list[str]) -> None:
    path, partial = determine_firewall_path(resolve_input_network(source), resolve_input_network(destination))
    assert path == expected and partial is False


def test_unmanaged_office_path_is_explicitly_partial() -> None:
    path, partial = determine_firewall_path(resolve_input_network("102.1.1.1"), resolve_input_network("100.1.2.10"))
    assert path == ["Cloud"] and partial is True


def test_address_matching_supports_ip_cidr_group_and_partial() -> None:
    assert address_match(ipaddress.ip_network("192.0.2.77/32"), "Direct", "192.0.2.0/24") == "full"
    assert address_match(ipaddress.ip_network("192.0.2.0/24"), "Group", "Member (192.0.0.0/16)") == "full"
    assert address_match(ipaddress.ip_network("192.0.2.0/24"), "Narrow", "192.0.2.77/32") == "partial"
    assert address_match(ipaddress.ip_network("192.0.2.0/24"), "Other", "198.51.100.0/24") == "none"


@pytest.mark.parametrize("wildcard", ["Any", "ALL HOSTS", "모두", "모든_호스트", "*"])
def test_common_wildcard_normalization_matches_any_ipv4(wildcard: str) -> None:
    assert is_wildcard_value(wildcard)
    result = address_match_details(ipaddress.ip_network("203.0.113.19"), wildcard, "")
    assert result == {"match": "full", "wildcard": True, "resolverFailed": False}


@pytest.mark.parametrize("wildcard_xml", [
    "",
    "<SourceNetworks/><DestinationNetworks/>",
    "<SourceNetworks>Any</SourceNetworks><DestinationNetworks><Network>All</Network></DestinationNetworks>",
])
def test_parser_preserves_semantic_address_wildcards(wildcard_xml: str) -> None:
    payloads = {"Rule": f'''<Response><Status code="200">OK</Status><FirewallRule><Name>GENERIC_RULE</Name><Status>Enable</Status><NetworkPolicy><Action>Accept</Action><SourceZones><Zone>Any</Zone></SourceZones>{wildcard_xml}<DestinationZones><Zone>Any</Zone></DestinationZones><Services><Service>TCP_443</Service></Services></NetworkPolicy></FirewallRule></Response>''',
                "Services": '''<Response><Status code="200">OK</Status><Services><Name>TCP_443</Name><ServiceDetails><ServiceDetail><Protocol>TCP</Protocol><DestinationPort>443</DestinationPort></ServiceDetail></ServiceDetails></Services></Response>'''}
    rows, _columns = parse_firewall_rules(payloads, "FirewallRule")
    row = rows[0]
    assert row["Source Object"] == row["Destination Object"] == ""
    assert row["source_wildcard"] is row["destination_wildcard"] is True
    broad = match_rules(rows, ipaddress.ip_network("192.0.2.77"), ipaddress.ip_network("198.51.100.44"), "ANY", None)
    exact = match_rules(rows, ipaddress.ip_network("192.0.2.77"), ipaddress.ip_network("198.51.100.44"), "TCP", 443)
    assert broad["matches"][0]["addressCandidate"] is True
    assert exact["state"] == "allow" and exact["matchedRule"]["full_match"] is True


def test_parser_preserves_empty_service_container_as_any_service() -> None:
    payloads = {"Rule": '''<Response><Status code="200">OK</Status><FirewallRule><Name>GENERIC_ANY_SERVICE</Name><Status>Enable</Status><NetworkPolicy><Action>Accept</Action><SourceNetworks/><DestinationNetworks/><Services/></NetworkPolicy></FirewallRule></Response>'''}
    rows, _columns = parse_firewall_rules(payloads, "FirewallRule")
    assert rows[0]["service_wildcard"] is True
    result = match_rules(rows, ipaddress.ip_network("192.0.2.77"), ipaddress.ip_network("198.51.100.44"), "UDP", 65000)
    assert result["state"] == "allow"
    assert result["matchedRule"]["anyService"] is True


def test_omitted_sfos22_policy_lists_are_wildcards_but_other_missing_fields_are_not() -> None:
    payloads = {"Rule": '''<Response APIVersion="2200.1"><Status code="200">OK</Status><FirewallRule><Name>CATCH_ALL</Name><Status>Enable</Status><NetworkPolicy><Action>Accept</Action></NetworkPolicy></FirewallRule></Response>'''}
    rows, _columns = parse_firewall_rules(payloads, "FirewallRule")
    row = rows[0]
    assert row["source_wildcard"] is row["destination_wildcard"] is row["service_wildcard"] is True
    assert row["_Source Semantics"] == row["_Destination Semantics"] == row["_Service Semantics"] == "omitted_container"
    assert row["Source Zone"] == row["Destination Zone"] == ""
    assert not zone_match("LAN", row["Source Zone"])
    result = match_rules(rows, ipaddress.ip_network("192.0.2.77"), ipaddress.ip_network("198.51.100.44"), "TCP", 443)
    assert result["state"] == "allow" and result["matchedRule"]["anyService"] is True


def test_explicit_policy_lists_are_not_wildcards() -> None:
    payloads = {"Rule": '''<Response><Status code="200">OK</Status><FirewallRule><Name>EXPLICIT_RULE</Name><Status>Enable</Status><NetworkPolicy><Action>Accept</Action><SourceNetworks><Network>SRC</Network></SourceNetworks><DestinationNetworks><Network>DST</Network></DestinationNetworks><Services><Service>HTTPS</Service></Services></NetworkPolicy></FirewallRule></Response>'''}
    rows, _columns = parse_firewall_rules(payloads, "FirewallRule")
    assert rows[0]["source_wildcard"] is rows[0]["destination_wildcard"] is rows[0]["service_wildcard"] is False


def test_iphost_group_and_ip_range_use_resolved_network_containment() -> None:
    request = ipaddress.ip_network("192.0.2.77")
    assert address_match(request, "GENERIC_GROUP", "MEMBER_NET (192.0.2.0/24)") == "full"
    assert address_match(request, "GENERIC_RANGE", "192.0.2.64 - 192.0.2.95") == "full"


def test_resolver_failure_is_distinct_from_real_no_match() -> None:
    failed = address_match_details(ipaddress.ip_network("192.0.2.77"), "UNRESOLVED_OBJECT", "UNRESOLVED_OBJECT")
    no_match = address_match_details(ipaddress.ip_network("192.0.2.77"), "OTHER_NET", "198.51.100.0/24")
    assert failed["resolverFailed"] is True and failed["match"] == "none"
    assert no_match["resolverFailed"] is False and no_match["match"] == "none"


def test_zone_matching_uses_expected_zone_membership_and_wildcards() -> None:
    assert zone_match("LAN", "Wireless\nLAN")
    assert zone_match("WAN", "Any Zone")
    assert not zone_match("WAN", "LAN\nVPN")


def test_path_engine_provides_expected_zones_per_firewall_hop() -> None:
    source, destination = resolve_input_network("101.1.3.50"), resolve_input_network("100.1.2.77")
    path, _partial = determine_firewall_path(source, destination)
    assert expected_zones_for_path(source, destination, path) == {"Seoul": ("LAN", "VPN"), "Cloud": ("VPN", "LAN")}


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
    assert match_rules([rule("disabled", "101.1.0.0/22", "100.1.0.0/22", service, status="비활성")], source, destination, "TCP", 389)["state"] == "no_matching_rule"
    assert match_rules([rule("deny", "101.1.0.0/22", "100.1.0.0/22", service, action="Deny")], source, destination, "TCP", 389)["state"] == "deny"
    result = match_rules([rule("deny first", "101.1.0.0/22", "100.1.0.0/22", service, action="Deny"), rule("allow later", "101.1.0.0/22", "100.1.0.0/22", service)], source, destination, "TCP", 389)
    assert result["state"] == "order_check_required" and result["orderReliable"] is False
    assert [candidate["rule"] for candidate in result["matches"]] == ["deny first", "allow later"]
    assert all(candidate["fullMatch"] for candidate in result["matches"])


def test_explicit_position_selects_first_active_rule_without_using_rule_id() -> None:
    source, destination = ipaddress.ip_network("106.1.0.0/16"), ipaddress.ip_network("100.1.2.77")
    service = "Protocol: TCP | Destination: 3389"
    later_allow = {**rule("allow", "106.1.0.0/16", "100.1.2.77", service, action="Accept"), "_Rule Position": "20", "Rule ID": "1"}
    first_deny = {**rule("deny", "106.1.0.0/16", "100.1.2.77", service, action="Reject"), "_Rule Position": "10", "Rule ID": "999"}
    result = match_rules([later_allow, first_deny], source, destination, "TCP", 3389)
    assert result["state"] == "deny"
    assert result["matchedRule"]["rule"] == "deny"
    assert result["orderSource"] == "numeric_position"


def test_sfos_position_after_chain_restores_effective_rule_order() -> None:
    payloads = {"Rule": '''<Response APIVersion="2200.1"><Status code="200">OK</Status><FirewallRule><Name>SECOND_RULE</Name><Status>Enable</Status><Position>After</Position><After><Name>FIRST_RULE</Name></After><NetworkPolicy><Action>Accept</Action></NetworkPolicy></FirewallRule><FirewallRule><Name>FIRST_RULE</Name><Status>Enable</Status><Position>Top</Position><NetworkPolicy><Action>Reject</Action></NetworkPolicy></FirewallRule></Response>'''}
    rows, _columns = parse_firewall_rules(payloads, "FirewallRule")
    assert {row["Rule Name"]: row["_Rule Order"] for row in rows} == {"SECOND_RULE": 2, "FIRST_RULE": 1}
    result = match_rules(rows, ipaddress.ip_network("192.0.2.77"), ipaddress.ip_network("198.51.100.44"), "TCP", 443)
    assert result["state"] == "deny"
    assert result["matchedRule"]["rule"] == "FIRST_RULE"
    assert result["orderSource"] == "position_after_chain"


def test_incomplete_position_after_chain_does_not_guess_order() -> None:
    payloads = {"Rule": '''<Response><Status code="200">OK</Status><FirewallRule><Name>FIRST_RULE</Name><Status>Enable</Status><Position>Top</Position><NetworkPolicy><Action>Reject</Action></NetworkPolicy></FirewallRule><FirewallRule><Name>ORPHAN_RULE</Name><Status>Enable</Status><Position>After</Position><After><Name>MISSING_RULE</Name></After><NetworkPolicy><Action>Accept</Action></NetworkPolicy></FirewallRule></Response>'''}
    rows, _columns = parse_firewall_rules(payloads, "FirewallRule")
    assert all("_Rule Order" not in row for row in rows)
    result = match_rules(rows, ipaddress.ip_network("192.0.2.77"), ipaddress.ip_network("198.51.100.44"), "TCP", 443)
    assert result["state"] == "order_check_required"


def test_user_policy_uses_generalized_resolved_groups() -> None:
    payloads = {
        "Rule": '''<Response><Status code="200">OK</Status><FirewallRule><Name>GENERIC_USER_RULE</Name><Status>Enable</Status><PolicyType>User</PolicyType><UserPolicy><Action>Accept</Action><SourceZones><Zone>VPN</Zone></SourceZones><SourceNetworks><Network>GENERIC_SOURCE_NET</Network></SourceNetworks><DestinationZones><Zone>LAN</Zone></DestinationZones><DestinationNetworks><Network>GENERIC_DEST_GROUP</Network></DestinationNetworks><Services><Service>GENERIC_SERVICE_GROUP</Service></Services></UserPolicy></FirewallRule></Response>''',
        "IPHost": '''<Response><Status code="200">OK</Status><IPHost><Name>GENERIC_SOURCE_NET</Name><HostType>Network</HostType><IPAddress>192.0.2.0</IPAddress><Subnet>255.255.255.0</Subnet></IPHost><IPHost><Name>GENERIC_DEST_A</Name><HostType>IP</HostType><IPAddress>198.51.100.77</IPAddress></IPHost><IPHost><Name>GENERIC_DEST_B</Name><HostType>IP</HostType><IPAddress>198.51.100.78</IPAddress></IPHost></Response>''',
        "IPHostGroup": '''<Response><Status code="200">OK</Status><IPHostGroup><Name>GENERIC_DEST_GROUP</Name><HostList><IPHost>GENERIC_DEST_A</IPHost><IPHost>GENERIC_DEST_B</IPHost></HostList></IPHostGroup></Response>''',
        "Services": '''<Response><Status code="200">OK</Status><Services><Name>TCP_3389</Name><ServiceDetails><ServiceDetail><Protocol>TCP</Protocol><DestinationPort>3389</DestinationPort></ServiceDetail></ServiceDetails></Services></Response>''',
        "ServiceGroup": '''<Response><Status code="200">OK</Status><ServiceGroup><Name>GENERIC_SERVICE_GROUP</Name><ServiceList><Service>TCP_3389</Service></ServiceList></ServiceGroup></Response>''',
    }
    rows, _columns = parse_firewall_rules(payloads, "FirewallRule")
    result = match_rules(rows, ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("198.51.100.77"), "TCP", 3389, "VPN", "LAN")
    candidate = result["matchedRule"]
    assert result["state"] == "allow"
    assert candidate["rule"] == "GENERIC_USER_RULE"
    assert candidate["status"] == "활성" and candidate["action"] == "Accept"
    assert candidate["sourceMatch"] == candidate["destinationMatch"] == "full"
    assert candidate["protocolMatch"] is candidate["portMatch"] is candidate["serviceMatch"] is True
    assert candidate["sourceZone"] == "VPN" and candidate["destinationZone"] == "LAN"
    assert candidate["fullMatch"] is True


def test_general_any_rule_is_an_effective_allow_for_specific_request() -> None:
    any_rule = rule("Office Internet", "Any", "Any", "Any", action="Accept")
    result = match_rules([any_rule], ipaddress.ip_network("101.1.3.50"), ipaddress.ip_network("52.79.112.47"), "TCP", 443)
    assert result["state"] == "allow"
    assert result["matchedRule"]["rule"] == "Office Internet"


def test_no_active_effective_rule_is_default_drop_not_policy_missing() -> None:
    result = match_rules([], ipaddress.ip_network("101.1.3.50"), ipaddress.ip_network("52.79.112.47"), "TCP", 443)
    assert result["state"] == "no_matching_rule"


def test_exact_query_retains_address_candidate_and_service_rejection_reason() -> None:
    candidate = rule("GENERIC_HTTPS", "192.0.2.0/24", "Any", "Protocol: TCP | Destination: 443")
    result = match_rules([candidate], ipaddress.ip_network("192.0.2.77"), ipaddress.ip_network("203.0.113.10"), "TCP", 22)
    assert result["state"] == "no_matching_rule"
    assert result["matches"][0]["addressCandidate"] is True
    assert result["matches"][0]["full_match"] is False
    assert result["matches"][0]["reject_reason"] == "port_no_match"
    assert {
        "source_match", "destination_match", "source_zone_match", "destination_zone_match",
        "protocol_match", "port_match", "source_wildcard", "destination_wildcard",
        "broad_query", "full_match", "reject_reason",
    } <= result["matches"][0].keys()


def test_zone_mismatch_rejects_address_candidate_with_diagnostic() -> None:
    candidate = {**rule("GENERIC_RULE", "192.0.2.0/24", "Any", "Any"), "Source Zone": "VPN", "Destination Zone": "WAN"}
    result = match_rules([candidate], ipaddress.ip_network("192.0.2.77"), ipaddress.ip_network("203.0.113.10"), "TCP", 443, "LAN", "WAN")
    assert result["matches"] == []
    assert result["evaluations"][0]["source_zone_match"] is False
    assert "source_zone_no_match" in result["evaluations"][0]["reject_reason"]


def test_unspecified_service_preserves_address_candidates_without_global_verdict() -> None:
    rows = [
        rule("https allow", "101.1.0.0/22", "Any", "Protocol: TCP | Destination: 443", action="Accept"),
        rule("ssh deny", "101.1.0.0/22", "Any", "Protocol: TCP | Destination: 22", action="Reject"),
        rule("dns allow", "101.1.0.0/22", "Any", "Protocol: UDP | Destination: 53", action="Accept"),
    ]
    result = match_rules(rows, ipaddress.ip_network("101.1.3.50"), ipaddress.ip_network("52.79.112.47"), "ANY", None)
    assert result["state"] == "service_varies"
    assert result["broadQuery"] is True
    assert [candidate["rule"] for candidate in result["matches"]] == ["https allow", "ssh deny", "dns allow"]
    assert result["matches"][0]["serviceProtocols"] == ["TCP"]
    assert result["matches"][0]["servicePorts"] == ["443"]


def test_protocol_without_port_is_broad_and_accepts_parser_protocol_names() -> None:
    icmp = rule("icmp", "Any", "Any", "Protocol: ICMP", action="Accept")
    result = match_rules([icmp], ipaddress.ip_network("101.1.3.50"), ipaddress.ip_network("52.79.112.47"), "ICMP", None)
    assert result["state"] == "service_varies"
    assert result["matches"][0]["protocolMatch"] is True


def test_static_route_exact_prefix_longest_and_missing() -> None:
    xml = '''<Response><Status code="200">OK</Status><UnicastRoute><Destination>100.1.0.0</Destination><Netmask>255.255.0.0</Netmask><Gateway>1.1.1.1</Gateway><Interface>Port1</Interface></UnicastRoute><UnicastRoute><Destination>100.1.0.0</Destination><Netmask>255.255.252.0</Netmask><Gateway>2.2.2.2</Gateway><Interface>IPsec</Interface><AdministrativeDistance>1</AdministrativeDistance><Status>Enable</Status><Description>AWS</Description></UnicastRoute></Response>'''
    routes = parse_unicast_routes(xml)
    matched = match_static_route(routes, ipaddress.ip_network("100.1.2.10"))
    assert matched["network"] == "100.1.0.0/22" and matched["gateway"] == "2.2.2.2"
    assert match_static_route(routes, ipaddress.ip_network("8.8.8.8")) is None
    assert match_static_route([{"destination": "8.8.8.0", "netmask": "24", "status": "Disable"}], ipaddress.ip_network("8.8.8.8")) is None


def test_default_route_participates_in_longest_prefix_match() -> None:
    routes = [
        {"destination": "0.0.0.0", "netmask": "0", "gateway": "52.79.112.1", "status": "Enable"},
        {"destination": "52.79.0.0", "netmask": "16", "gateway": "52.79.0.1", "status": "Enable"},
    ]
    assert match_static_route(routes, ipaddress.ip_network("8.8.8.8"))["network"] == "0.0.0.0/0"
    assert match_static_route(routes, ipaddress.ip_network("52.79.112.47"))["network"] == "52.79.0.0/16"


def test_dotted_netmask_input_is_normalized_and_non_contiguous_mask_rejected(tmp_path: Path) -> None:
    service = FirewallPathCheckService(tmp_path)
    result = service.check("101.1.3.50/255.255.252.0", "52.79.112.47/255.255.255.0", "ANY", None)
    assert result["source"]["input"] == "101.1.3.50/255.255.252.0"
    assert result["source"]["network"] == "101.1.0.0/22"
    assert result["destination"]["network"] == "52.79.112.0/24"
    with pytest.raises(ValueError, match="IP 또는 CIDR"):
        service.check("101.1.3.50/255.0.255.0", "52.79.112.47", "ANY", None)


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
