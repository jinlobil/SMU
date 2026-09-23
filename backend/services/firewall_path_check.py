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
from backend.services.firewall_network_mapping import IP_TOKEN, MASKED_NETWORK, determine_firewall_path, resolve_input_network
from backend.services.firewall_rule_export import ENTITIES, _nodes, _tag, parse_firewall_rules


ANY_VALUES = {"any", "all", "모든 호스트", "모든호스트", "*"}
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


def address_match(requested: ipaddress.IPv4Network, objects: str, resolved: str) -> str:
    if any(value.strip().casefold() in ANY_VALUES for value in f"{objects}\n{resolved}".splitlines()):
        return "full"
    partial = False
    for network in _networks(resolved):
        if requested.subnet_of(network): return "full"
        if requested.overlaps(network): partial = True
    return "partial" if partial else "none"


def service_match(protocol: str, port: int, service_names: str, resolved: str) -> bool:
    if any(
        value.strip().casefold() in ANY_VALUES
        or value.strip().casefold() in {"any service", "all services"}
        for value in f"{service_names}\n{resolved}".splitlines()
    ):
        return True
    protocol = protocol.upper()
    for line in resolved.splitlines():
        match = re.search(r"Protocol:\s*([^|]+)", line, re.I)
        if not match or match.group(1).strip().upper() != protocol:
            continue
        destination = re.search(r"Destination:\s*([^|]+)", line, re.I)
        if not destination:
            continue
        for start, end in PORT_RANGE.findall(destination.group(1)):
            if int(start) <= port <= int(end or start): return True
    return False


def match_rules(rows: list[dict[str, str]], source: ipaddress.IPv4Network, destination: ipaddress.IPv4Network, protocol: str, port: int) -> dict[str, Any]:
    matches = []
    for row in rows:
        source_match = address_match(source, row.get("Source Object", ""), row.get("Source Resolved", ""))
        destination_match = address_match(destination, row.get("Destination Object", ""), row.get("Destination Resolved", ""))
        service_ok = service_match(protocol, port, row.get("Service", ""), row.get("Service Resolved / Protocol / Port", ""))
        if source_match == "none" or destination_match == "none" or not service_ok: continue
        matches.append({"rule": row.get("Rule Name", ""), "status": row.get("Status", ""), "action": row.get("Action", ""), "sourceMatch": source_match, "destinationMatch": destination_match, "serviceMatch": service_ok})
    full = [item for item in matches if item["sourceMatch"] == item["destinationMatch"] == "full"]
    active = [item for item in full if item["status"] in {"활성", "Enable", "enable"}]
    if len(active) == 1:
        action = active[0]["action"].casefold()
        state = "allow" if action in {"allow", "accept"} else "deny" if action in {"deny", "drop", "reject"} else "matched"
        return {"state": state, "orderReliable": True, "matchedRule": active[0], "matches": matches}
    if len(active) > 1:
        return {"state": "order_check_required", "orderReliable": False, "matchedRule": None, "matches": matches}
    if full:
        return {"state": "disabled", "orderReliable": True, "matchedRule": full[0], "matches": matches}
    if matches:
        return {"state": "partial", "orderReliable": True, "matchedRule": matches[0], "matches": matches}
    return {"state": "missing", "orderReliable": True, "matchedRule": None, "matches": []}


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
            network = ipaddress.ip_network(f"{route['destination']}/{suffix}", strict=False)
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

    def check(self, source_value: str, destination_value: str, protocol: str, port: int, refresh: bool = False) -> dict[str, Any]:
        try: source_network, destination_network = ipaddress.ip_network(source_value, strict=False), ipaddress.ip_network(destination_value, strict=False)
        except ValueError as exc: raise ValueError(f"Source/Destination IP 또는 CIDR을 확인하세요: {exc}") from exc
        if source_network.version != 4 or destination_network.version != 4:
            raise ValueError("Source/Destination은 IPv4만 지원합니다")
        protocol = protocol.upper()
        if protocol not in {"TCP", "UDP"}: raise ValueError("Protocol은 TCP 또는 UDP만 지원합니다")
        if not 1 <= int(port) <= 65535: raise ValueError("Destination Port는 1~65535 범위여야 합니다")
        source, destination = resolve_input_network(source_value), resolve_input_network(destination_value)
        if source is None or destination is None: raise ValueError("Source/Destination IP 또는 CIDR을 확인하세요")
        path, partial = determine_firewall_path(source, destination)
        configs = {item["name"]: item for item in self.firewalls.configurations()}
        results = []
        for name in path:
            config = configs.get(name)
            if not config or not config["configured"]:
                results.append({"firewall": name, "available": False, "error": "Firewall configuration unavailable", "policy": {"state": "unavailable"}, "routing": {"destination": None, "return": None}}); continue
            try:
                snapshot = self._snapshot(config, refresh)
                results.append({"firewall": name, "available": True, "checkedAt": snapshot["checkedAt"], "policy": match_rules(snapshot["rules"], source_network, destination_network, protocol, int(port)), "routing": {"destination": match_static_route(snapshot["routes"], destination_network), "return": match_static_route(snapshot["routes"], source_network), "error": snapshot["routeError"]}})
            except Exception as exc:
                results.append({"firewall": name, "available": False, "error": f"{type(exc).__name__}: {exc}", "policy": {"state": "unavailable"}, "routing": {"destination": None, "return": None}})
        return {"source": source, "destination": destination, "protocol": protocol, "port": int(port), "path": path, "partialPath": partial, "firewalls": results, "checkedAt": datetime.now(timezone.utc).isoformat()}
