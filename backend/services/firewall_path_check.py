from __future__ import annotations

import ipaddress
import re
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.services.firewall import FirewallClient, FirewallService, parse_status
from backend.services.firewall_network_mapping import IP_TOKEN, MASKED_NETWORK, determine_firewall_path, expected_zones_for_path, resolve_input_network
from backend.services.firewall_rule_export import ENTITIES, _nodes, _tag, is_wildcard_value, parse_firewall_rules


PORT_RANGE = re.compile(r"(?<!\d)(\d{1,5})(?:\s*[:-]\s*(\d{1,5}))?(?!\d)")


def _networks(text: str) -> list[ipaddress.IPv4Network]:
    remaining, values = text, []
    for match in MASKED_NETWORK.finditer(text):
        try: values.append(ipaddress.ip_network(f"{match.group(1)}/{match.group(2)}", strict=False))
        except ValueError: pass
        remaining = remaining.replace(match.group(0), " ")
    for token in IP_TOKEN.findall(remaining):
        try: values.append(ipaddress.ip_network(token, strict=False))
        except ValueError: pass
    for start, end in re.findall(r"((?:\d{1,3}\.){3}\d{1,3})\s*-\s*((?:\d{1,3}\.){3}\d{1,3})", text):
        try: values.extend(ipaddress.summarize_address_range(ipaddress.ip_address(start), ipaddress.ip_address(end)))
        except ValueError: pass
    return list(dict.fromkeys(values))


def address_match_details(requested: ipaddress.IPv4Network, objects: str, resolved: str) -> dict[str, Any]:
    values = [value.strip() for value in f"{objects}\n{resolved}".splitlines() if value.strip()]
    wildcard = any(is_wildcard_value(value) for value in values)
    if wildcard:
        return {"match": "full", "wildcard": True, "resolverFailed": False}
    partial = False
    networks = _networks(resolved)
    for network in networks:
        if requested.subnet_of(network):
            return {"match": "full", "wildcard": False, "resolverFailed": False}
        if requested.overlaps(network): partial = True
    return {"match": "partial" if partial else "none", "wildcard": False, "resolverFailed": bool(objects.strip()) and not networks}


def address_match(requested: ipaddress.IPv4Network, objects: str, resolved: str) -> str:
    return address_match_details(requested, objects, resolved)["match"]


def zone_match(expected: str | None, rule_zones: str) -> bool:
    if not expected:
        return True
    zones = [value.strip() for value in re.split(r"[\n,;]", rule_zones) if value.strip()]
    return any(is_wildcard_value(value) or value.casefold() == expected.casefold() for value in zones)


def service_match_details(protocol: str, port: int | None, service_names: str, resolved: str) -> dict[str, Any]:
    any_service = any(is_wildcard_value(value) for value in f"{service_names}\n{resolved}".splitlines())
    if any_service:
        return {"protocolMatch": True, "portMatch": True, "serviceMatch": True, "anyService": True, "serviceProtocols": ["ANY"], "servicePorts": ["ANY"]}
    protocol = protocol.upper()
    protocols: list[str] = []
    ports: list[str] = []
    protocol_match = protocol == "ANY"
    port_match = port is None
    for line in resolved.splitlines():
        match = re.search(r"Protocol:\s*([^|]+)", line, re.I)
        if not match:
            continue
        service_protocol = match.group(1).strip().upper()
        if service_protocol not in protocols:
            protocols.append(service_protocol)
        line_protocol_match = protocol == "ANY" or service_protocol == protocol
        if line_protocol_match:
            protocol_match = True
        destination = re.search(r"Destination:\s*([^|]+)", line, re.I)
        if not destination:
            if line_protocol_match and port is None:
                port_match = True
            continue
        port_text = destination.group(1).strip()
        if port_text and port_text not in ports:
            ports.append(port_text)
        for start, end in PORT_RANGE.findall(destination.group(1)):
            if line_protocol_match and (port is None or int(start) <= port <= int(end or start)):
                port_match = True
                break
    return {"protocolMatch": protocol_match, "portMatch": port_match, "serviceMatch": protocol_match and port_match, "anyService": False, "serviceProtocols": protocols, "servicePorts": ports}


def service_match(protocol: str, port: int | None, service_names: str, resolved: str) -> bool:
    return service_match_details(protocol, port, service_names, resolved)["serviceMatch"]


def _position(value: str) -> int | None:
    match = re.fullmatch(r"\s*#?(\d+)\s*", value or "")
    return int(match.group(1)) if match else None


def _action_state(candidate: dict[str, Any]) -> str:
    action = candidate["action"].casefold()
    return "allow" if action in {"allow", "accept"} else "deny" if action in {"deny", "drop", "reject"} else "matched"


def match_rules(
    rows: list[dict[str, str]],
    source: ipaddress.IPv4Network,
    destination: ipaddress.IPv4Network,
    protocol: str = "ANY",
    port: int | None = None,
    expected_source_zone: str | None = None,
    expected_destination_zone: str | None = None,
) -> dict[str, Any]:
    broad_query = protocol == "ANY" or port is None
    matches = []
    evaluations = []
    for row in rows:
        source_result = address_match_details(source, row.get("Source Object", ""), row.get("Source Resolved", ""))
        destination_result = address_match_details(destination, row.get("Destination Object", ""), row.get("Destination Resolved", ""))
        source_match, destination_match = source_result["match"], destination_result["match"]
        source_zone_match = zone_match(expected_source_zone, row.get("Source Zone", ""))
        destination_zone_match = zone_match(expected_destination_zone, row.get("Destination Zone", ""))
        service = service_match_details(protocol, port, row.get("Service", ""), row.get("Service Resolved / Protocol / Port", ""))
        active = row.get("Status", "") == "활성" or row.get("Status", "").casefold() in {"enable", "enabled"}
        address_candidate = source_match == destination_match == "full" and source_zone_match and destination_zone_match
        reject_reasons = []
        if not active: reject_reasons.append("status_inactive")
        if source_result["resolverFailed"]: reject_reasons.append("source_resolver_failed")
        if destination_result["resolverFailed"]: reject_reasons.append("destination_resolver_failed")
        if source_match != "full": reject_reasons.append("source_partial" if source_match == "partial" else "source_no_match")
        if destination_match != "full": reject_reasons.append("destination_partial" if destination_match == "partial" else "destination_no_match")
        if not source_zone_match: reject_reasons.append("source_zone_no_match")
        if not destination_zone_match: reject_reasons.append("destination_zone_no_match")
        if not broad_query and not service["protocolMatch"]: reject_reasons.append("protocol_no_match")
        if not broad_query and not service["portMatch"]: reject_reasons.append("port_no_match")
        evaluation = {
            "rule": row.get("Rule Name", ""),
            "status": row.get("Status", ""),
            "action": row.get("Action", ""),
            "sourceMatch": source_match,
            "destinationMatch": destination_match,
            **service,
            "sourceZone": row.get("Source Zone", ""),
            "destinationZone": row.get("Destination Zone", ""),
            "service": row.get("Service", ""),
            "serviceResolved": row.get("Service Resolved / Protocol / Port", ""),
            "position": _position(row.get("_Rule Position", "")),
            "fullMatch": address_candidate and service["serviceMatch"],
            "addressCandidate": address_candidate,
            "source_match": source_match,
            "destination_match": destination_match,
            "source_zone_match": source_zone_match,
            "destination_zone_match": destination_zone_match,
            "protocol_match": service["protocolMatch"],
            "port_match": service["portMatch"],
            "source_wildcard": source_result["wildcard"],
            "destination_wildcard": destination_result["wildcard"],
            "source_resolver_failed": source_result["resolverFailed"],
            "destination_resolver_failed": destination_result["resolverFailed"],
            "broad_query": broad_query,
            "full_match": address_candidate and service["serviceMatch"],
            "reject_reason": ",".join(reject_reasons),
        }
        evaluations.append(evaluation)
        if address_candidate:
            matches.append(evaluation)
    full = [item for item in matches if item["fullMatch"]]
    active = [item for item in full if item["status"] == "활성" or item["status"].casefold() in {"enable", "enabled"}]
    if broad_query:
        if len(active) == 1 and active[0]["anyService"]:
            return {"state": _action_state(active[0]), "orderReliable": True, "matchedRule": active[0], "matches": matches, "evaluations": evaluations, "broadQuery": True}
        if active:
            return {"state": "service_varies", "orderReliable": len(active) == 1, "matchedRule": None, "matches": matches, "evaluations": evaluations, "broadQuery": True}
        return {"state": "no_matching_rule", "orderReliable": True, "matchedRule": None, "matches": matches, "evaluations": evaluations, "broadQuery": True}
    if len(active) == 1:
        return {"state": _action_state(active[0]), "orderReliable": True, "matchedRule": active[0], "matches": matches, "evaluations": evaluations, "broadQuery": False}
    if len(active) > 1:
        positions = [item["position"] for item in active]
        if all(position is not None for position in positions) and len(set(positions)) == len(positions):
            first = min(active, key=lambda item: item["position"])
            state = _action_state(first)
            return {"state": state, "orderReliable": True, "orderSource": "explicit_position", "matchedRule": first, "matches": matches, "evaluations": evaluations}
        return {"state": "order_check_required", "orderReliable": False, "matchedRule": None, "matches": matches, "evaluations": evaluations}
    return {"state": "no_matching_rule", "orderReliable": True, "matchedRule": None, "matches": matches, "evaluations": evaluations, "broadQuery": False}


def parse_unicast_routes(xml_text: str) -> list[dict[str, str]]:
    rows = []
    for node in _nodes(xml_text, "UnicastRoute"):
        values = {(_tag(child)): (child.text or "").strip() for child in node.iter() if child is not node and (child.text or "").strip()}
        destination = values.get("Destination") or values.get("DestinationIP") or values.get("Network") or ""
        netmask = values.get("Netmask") or values.get("SubnetMask") or values.get("Prefix") or ""
        rows.append({"destination": destination, "netmask": netmask, "gateway": values.get("Gateway", ""), "interface": values.get("Interface", values.get("InterfaceName", "")), "distance": values.get("AdministrativeDistance", values.get("Distance", "")), "status": values.get("Status", ""), "description": values.get("Description", "")})
    return rows


def match_static_route(routes: list[dict[str, str]], destination: ipaddress.IPv4Network) -> dict[str, str] | None:
    candidates = []
    for route in routes:
        if route.get("status", "").strip().casefold() in {"disable", "disabled", "inactive"}:
            continue
        try:
            suffix = route["netmask"] or "32"
            network = ipaddress.ip_network(route["destination"] if "/" in route["destination"] else f"{route['destination']}/{suffix}", strict=False)
        except ValueError:
            continue
        if destination.subnet_of(network): candidates.append((network.prefixlen, route, str(network)))
    if not candidates: return None
    _prefix, route, network = max(candidates, key=lambda item: item[0])
    return {**route, "network": network}


class FirewallPathCheckService:
    def __init__(self, root: Path, ttl_seconds: int = 300):
        self.root, self.ttl_seconds = root, ttl_seconds
        self.firewalls = FirewallService(root)
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def _snapshot(self, config: dict[str, Any], refresh: bool) -> dict[str, Any]:
        with self._lock:
            cached = self._cache.get(config["name"])
            if cached and not refresh and time.monotonic() - cached[0] < self.ttl_seconds: return cached[1]
        client = FirewallClient(config); rule_response = client.get_rules_compatible(); payloads = {"Rule": rule_response["raw"]}
        for entity in ENTITIES:
            try:
                raw = client.get(entity)
                status = parse_status(raw)
                if status["code"] and status["code"] != "200":
                    raise RuntimeError(f"Firewall API entity {entity} {status['code']}: {status['message']}")
                _nodes(raw, entity)
                payloads[entity] = raw
            except Exception:
                # Object/service data enriches rule matching. A firmware-specific
                # entity failure must not discard otherwise usable rule data.
                pass
        rows, _columns = parse_firewall_rules(payloads, rule_response["entity"])
        route_error = ""
        try:
            route_xml = client.get("UnicastRoute")
            status = parse_status(route_xml)
            if status["code"] and status["code"] != "200": raise RuntimeError(f"Firewall API {status['code']}: {status['message']}")
            routes = parse_unicast_routes(route_xml)
        except Exception as exc:
            routes, route_error = [], f"{type(exc).__name__}: {exc}"
        snapshot = {"rules": rows, "routes": routes, "routeError": route_error, "checkedAt": datetime.now(timezone.utc).isoformat()}
        with self._lock: self._cache[config["name"]] = (time.monotonic(), snapshot)
        return snapshot

    def check(self, source_value: str, destination_value: str, protocol: str = "ANY", port: Any = None, refresh: bool = False) -> dict[str, Any]:
        try: source_network, destination_network = ipaddress.ip_network(source_value, strict=False), ipaddress.ip_network(destination_value, strict=False)
        except ValueError as exc: raise ValueError(f"Source/Destination IP 또는 CIDR을 확인하세요: {exc}") from exc
        if source_network.version != 4 or destination_network.version != 4:
            raise ValueError("Source/Destination은 IPv4만 지원합니다")
        protocol = (protocol or "ANY").strip().upper()
        if not re.fullmatch(r"[A-Z0-9][A-Z0-9 _+./-]{0,31}", protocol):
            raise ValueError("Protocol 형식을 확인하세요")
        normalized_port = None if port is None or str(port).strip().upper() in {"", "ANY"} else int(port)
        if normalized_port is not None and not 1 <= normalized_port <= 65535:
            raise ValueError("Destination Port는 비우거나 1~65535 범위여야 합니다")
        source, destination = resolve_input_network(source_value), resolve_input_network(destination_value)
        if source is None or destination is None: raise ValueError("Source/Destination IP 또는 CIDR을 확인하세요")
        path, partial = determine_firewall_path(source, destination)
        expected_zones = expected_zones_for_path(source, destination, path)
        configs = {item["name"]: item for item in self.firewalls.configurations()}
        results = []
        for name in path:
            config = configs.get(name)
            if not config or not config["configured"]:
                results.append({"firewall": name, "available": False, "error": "Firewall configuration unavailable", "policy": {"state": "unavailable"}, "routing": {"destination": None, "return": None}}); continue
            try:
                snapshot = self._snapshot(config, refresh)
                source_zone, destination_zone = expected_zones.get(name, (None, None))
                results.append({"firewall": name, "available": True, "checkedAt": snapshot["checkedAt"], "expectedZones": {"source": source_zone, "destination": destination_zone}, "policy": match_rules(snapshot["rules"], source_network, destination_network, protocol, normalized_port, source_zone, destination_zone), "routing": {"destination": match_static_route(snapshot["routes"], destination_network), "return": match_static_route(snapshot["routes"], source_network), "error": snapshot["routeError"]}})
            except Exception as exc:
                results.append({"firewall": name, "available": False, "error": f"{type(exc).__name__}: {exc}", "policy": {"state": "unavailable"}, "routing": {"destination": None, "return": None}})
        return {"source": source, "destination": destination, "protocol": protocol, "port": normalized_port, "path": path, "partialPath": partial, "firewalls": results, "checkedAt": datetime.now(timezone.utc).isoformat()}
