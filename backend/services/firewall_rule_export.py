from __future__ import annotations

import socket
import logging
import urllib.error
import xml.etree.ElementTree as ET
from datetime import date
from pathlib import Path
from typing import Any

from backend.services.firewall import FirewallClient, FirewallService, parse_status
from backend.services.spreadsheet import write_xlsx_workbook


ENTITIES = ("IPHost", "IPHostGroup", "FQDNHost", "FQDNHostGroup", "Service", "ServiceGroup")
RULE_ENTITIES = ("FirewallRule", "SecurityPolicy")
log = logging.getLogger("smu.firewall.rule_export")
CORE_COLUMNS = [
    "Rule Name", "Status / Enable", "Action", "Source Zone", "Source Object", "Source Resolved",
    "Destination Zone", "Destination Object", "Destination Resolved", "Service",
    "Service Resolved / Protocol / Port", "Schedule", "Log Traffic", "Web Filter",
    "Application Control", "IPS Policy", "NAT Policy", "Source NAT", "Destination NAT",
]


def _tag(node: ET.Element) -> str:
    return node.tag.split("}")[-1]


def _values(node: ET.Element, names: set[str]) -> list[str]:
    result: list[str] = []
    for child in node.iter():
        value = (child.text or "").strip()
        if _tag(child) in names and value and value not in result:
            result.append(value)
    return result


def _first(node: ET.Element, *names: str) -> str:
    return next(iter(_values(node, set(names))), "")


def _under(node: ET.Element, containers: set[str]) -> list[str]:
    result: list[str] = []
    for container in node.iter():
        if _tag(container) not in containers:
            continue
        for child in container.iter():
            value = (child.text or "").strip()
            if child is not container and value and value not in result:
                result.append(value)
    return result


def _flatten(node: ET.Element, prefix: str = "") -> dict[str, str]:
    values: dict[str, list[str]] = {}
    for child in list(node):
        key = f"{prefix}.{_tag(child)}" if prefix else _tag(child)
        if list(child):
            for nested_key, nested_value in _flatten(child, key).items():
                values.setdefault(nested_key, []).extend(nested_value.split("\n"))
        else:
            value = (child.text or "").strip()
            if value:
                values.setdefault(key, []).append(value)
    return {key: "\n".join(dict.fromkeys(items)) for key, items in values.items()}


def _nodes(xml_text: str, entity: str) -> list[ET.Element]:
    root = ET.fromstring(xml_text)
    status = parse_status(xml_text)
    if status["code"] and status["code"] != "200":
        raise RuntimeError(f"Firewall API {status['code']}: {status['message']}")
    return [node for node in root.iter() if _tag(node) == entity]


def _object_maps(payloads: dict[str, str]) -> tuple[dict[str, str], dict[str, str]]:
    objects: dict[str, str] = {}
    groups: dict[str, list[str]] = {}
    for entity in ("IPHost", "FQDNHost"):
        for node in _nodes(payloads[entity], entity):
            name = _first(node, "Name")
            detail = _first(node, "IPAddress", "FQDN", "HostName", "IPRange")
            if name:
                objects[name] = detail or name
    for entity in ("IPHostGroup", "FQDNHostGroup"):
        for node in _nodes(payloads[entity], entity):
            name = _first(node, "Name")
            members = [value for value in _values(node, {"IPHost", "FQDNHost", "Host", "Member", "HostName"}) if value != name]
            if name:
                groups[name] = members
    resolved = dict(objects)
    for name, members in groups.items():
        resolved[name] = "\n".join(f"{member} ({objects.get(member, member)})" for member in members) or name

    services: dict[str, str] = {}
    service_groups: dict[str, list[str]] = {}
    for node in _nodes(payloads["Service"], "Service"):
        name = _first(node, "Name")
        details = _values(node, {"Protocol", "ProtocolName", "SourcePort", "DestinationPort", "Port", "ICMPType", "ICMPCode"})
        if name:
            services[name] = " / ".join(details) or name
    for node in _nodes(payloads["ServiceGroup"], "ServiceGroup"):
        name = _first(node, "Name")
        members = [value for value in _values(node, {"Service", "Member", "ServiceName"}) if value != name]
        if name:
            service_groups[name] = members
    for name, members in service_groups.items():
        services[name] = "\n".join(f"{member} ({services.get(member, member)})" for member in members) or name
    return resolved, services


def _join(values: list[str]) -> str:
    return "\n".join(values)


def parse_firewall_rules(payloads: dict[str, str], rule_entity: str | None = None) -> tuple[list[dict[str, str]], list[str]]:
    resolved_objects, resolved_services = _object_maps(payloads)
    rows: list[dict[str, str]] = []
    extra_columns: list[str] = []
    rule_xml = payloads.get("Rule") or payloads.get("FirewallRule") or payloads.get("SecurityPolicy") or ""
    root = ET.fromstring(rule_xml)
    status = parse_status(rule_xml)
    if status["code"] and status["code"] != "200":
        raise RuntimeError(f"Firewall API {status['code']}: {status['message']}")
    supported = {rule_entity} if rule_entity in RULE_ENTITIES else set(RULE_ENTITIES)
    rule_nodes = [node for node in root.iter() if _tag(node) in supported]
    for node in rule_nodes:
        source = _under(node, {"SourceNetworks", "SourceNetwork", "SourceHosts", "SourceObjects"})
        destination = _under(node, {"DestinationNetworks", "DestinationNetwork", "DestinationHosts", "DestinationObjects"})
        services = _under(node, {"Services", "ServiceList"})
        flat = _flatten(node)
        row = {
            "Rule Name": _first(node, "Name", "RuleName"),
            "Status / Enable": _first(node, "Status", "Enable", "Enabled"),
            "Action": _first(node, "Action"),
            "Source Zone": _join(_under(node, {"SourceZones", "SourceZone"})),
            "Source Object": _join(source),
            "Source Resolved": _join([resolved_objects.get(value, value) for value in source]),
            "Destination Zone": _join(_under(node, {"DestinationZones", "DestinationZone"})),
            "Destination Object": _join(destination),
            "Destination Resolved": _join([resolved_objects.get(value, value) for value in destination]),
            "Service": _join(services),
            "Service Resolved / Protocol / Port": _join([resolved_services.get(value, value) for value in services]),
            "Schedule": _first(node, "Schedule"),
            "Log Traffic": _first(node, "LogTraffic", "LogFirewallTraffic"),
            "Web Filter": _first(node, "WebFilter", "WebFilterPolicy"),
            "Application Control": _first(node, "ApplicationControl", "ApplicationControlPolicy"),
            "IPS Policy": _first(node, "IntrusionPrevention", "IPSPolicy", "IPS"),
            "NAT Policy": _first(node, "NATPolicy", "NATRule"),
            "Source NAT": _first(node, "SourceNAT", "TranslatedSource"),
            "Destination NAT": _first(node, "DestinationNAT", "TranslatedDestination"),
        }
        for key, value in flat.items():
            column = f"XML: {key}"
            if column not in extra_columns:
                extra_columns.append(column)
            row[column] = value
        rows.append(row)
    return rows, [*CORE_COLUMNS, *extra_columns]


def classify_export_error(exc: Exception) -> str:
    if isinstance(exc, ET.ParseError):
        return "XML Parse Error"
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "Connection Timeout"
    if isinstance(exc, urllib.error.HTTPError) and exc.code in {401, 403}:
        return "Authentication Failure"
    if "401" in str(exc) or "403" in str(exc) or "auth" in str(exc).lower():
        return "Authentication Failure"
    if isinstance(exc, (urllib.error.URLError, ConnectionError)):
        return "Connection Error"
    return type(exc).__name__


class FirewallRuleExportService:
    def __init__(self, project_root: Path):
        self.root = project_root
        self.firewalls = FirewallService(project_root)

    def build(self, firewall_names: list[Any], progress=lambda _message: None) -> dict[str, Any]:
        configs = self.firewalls.selected_for_export(firewall_names)
        sheets: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        counts: dict[str, int] = {}
        diagnostics: dict[str, dict[str, str]] = {}
        for config in configs:
            name = config["name"]
            progress(f"{name} Firewall Rule 및 Object 조회 중")
            try:
                client = FirewallClient(config)
                rule_response = client.get_rules_compatible()
                diagnostics[name] = {"apiVersion": rule_response["apiVersion"], "ruleEntity": rule_response["entity"]}
                log.info("Firewall rule API selected firewall=%s api_version=%s entity=%s", name, rule_response["apiVersion"] or "unknown", rule_response["entity"])
                payloads = {"Rule": rule_response["raw"]}
                for entity in ENTITIES:
                    payloads[entity] = client.get(entity)
                    entity_status = parse_status(payloads[entity])
                    log.info("Firewall XML entity validated firewall=%s api_version=%s entity=%s status=%s", name, rule_response["apiVersion"] or "unknown", entity, entity_status["code"] or "unknown")
                    if entity_status["code"] and entity_status["code"] != "200":
                        raise RuntimeError(f"Firewall API entity {entity} {entity_status['code']}: {entity_status['message']}")
                rows, columns = parse_firewall_rules(payloads, rule_response["entity"])
                sheets.append({"name": name, "rows": rows, "columns": columns})
                counts[name] = len(rows)
            except Exception as exc:
                errors.append({"Firewall": name, "Error Type": classify_export_error(exc), "Message": str(exc)})
        if errors:
            sheets.append({"name": "Export Errors", "rows": errors, "columns": ["Firewall", "Error Type", "Message"]})
        export_dir = self.root / "exports"
        path = export_dir / f"Sophos_Firewall_Rules_{date.today().isoformat()}.xlsx"
        names = write_xlsx_workbook(path, sheets)
        return {"filename": path.name, "path": str(path), "sheets": names, "counts": counts, "errors": errors, "diagnostics": diagnostics}
