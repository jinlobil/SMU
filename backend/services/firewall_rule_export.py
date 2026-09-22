from __future__ import annotations

import logging
import socket
import urllib.error
import xml.etree.ElementTree as ET
from datetime import date
from pathlib import Path
from typing import Any

from backend.services.firewall import FirewallClient, FirewallService, parse_status
from backend.services.spreadsheet import write_xlsx_workbook


ENTITIES = ("IPHost", "IPHostGroup", "FQDNHost", "FQDNHostGroup", "Services", "ServiceGroup")
RULE_ENTITIES = ("FirewallRule", "SecurityPolicy")
log = logging.getLogger("smu.firewall.rule_export")
MANAGEMENT_COLUMNS = [
    "Rule Name", "Status", "Policy Type", "Rule Group", "Action",
    "Source Zone", "Source Object", "Source Resolved",
    "Destination Zone", "Destination Object", "Destination Resolved",
    "Service", "Service Resolved / Protocol / Port",
    "Schedule", "IPS", "AV", "Web", "Application", "QoS", "Heartbeat",
    "Linked NAT", "Proxy", "Log", "Description",
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


def _direct_child(node: ET.Element, names: set[str]) -> ET.Element | None:
    return next((child for child in list(node) if _tag(child) in names), None)


def _direct_text(node: ET.Element, *names: str) -> str:
    child = _direct_child(node, set(names))
    return (child.text or "").strip() if child is not None else ""


def _under_direct(node: ET.Element, containers: set[str]) -> list[str]:
    """Read only top-level rule containers, never same-named Exclusions descendants."""
    result: list[str] = []
    for container in list(node):
        if _tag(container) in containers:
            for child in container.iter():
                value = (child.text or "").strip()
                if child is not container and value and value not in result:
                    result.append(value)
    return result


def _nodes(xml_text: str, entity: str) -> list[ET.Element]:
    root = ET.fromstring(xml_text)
    status = parse_status(xml_text)
    if status["code"] and status["code"] != "200":
        raise RuntimeError(f"Firewall API {status['code']}: {status['message']}")
    return [node for node in root.iter() if _tag(node) == entity]


def _object_maps(payloads: dict[str, str]) -> tuple[dict[str, str], dict[str, str]]:
    objects: dict[str, str] = {}
    groups: dict[str, list[str]] = {}
    for node in _nodes(payloads.get("IPHost", "<Response/>"), "IPHost"):
        name, host_type = _direct_text(node, "Name"), _direct_text(node, "HostType")
        if host_type == "Network":
            parts = [_direct_text(node, "IPAddress"), _direct_text(node, "Subnet")]
            detail = " / ".join(part for part in parts if part)
        elif host_type == "IPRange":
            parts = [_direct_text(node, "StartIPAddress"), _direct_text(node, "EndIPAddress")]
            detail = " - ".join(part for part in parts if part)
        elif host_type == "IPList":
            ip_list = _direct_child(node, {"ListOfIPAddresses"})
            list_values = _values(ip_list, {"IPAddress", "IP"}) if ip_list is not None else []
            if ip_list is not None and not list_values and (ip_list.text or "").strip():
                list_values = [value.strip() for value in (ip_list.text or "").replace(";", ",").split(",") if value.strip()]
            detail = "\n".join(list_values)
        else:
            detail = _direct_text(node, "IPAddress")
        if name:
            objects[name] = detail or name
    for node in _nodes(payloads.get("FQDNHost", "<Response/>"), "FQDNHost"):
        name = _direct_text(node, "Name")
        if name:
            objects[name] = _direct_text(node, "FQDN", "HostName") or name
    for entity in ("IPHostGroup", "FQDNHostGroup"):
        for node in _nodes(payloads.get(entity, "<Response/>"), entity):
            name = _first(node, "Name")
            members = [value for value in _values(node, {"IPHost", "FQDNHost", "Host", "Member", "HostName"}) if value != name]
            if name:
                groups[name] = members
    resolved = dict(objects)
    for name, members in groups.items():
        resolved[name] = "\n".join(f"{member} ({objects.get(member, member)})" for member in members) or name

    services: dict[str, str] = {}
    service_groups: dict[str, list[str]] = {}
    for node in _nodes(payloads.get("Services", "<Response/>"), "Services"):
        name = _direct_text(node, "Name")
        details = []
        detail_container = _direct_child(node, {"ServiceDetails"})
        detail_nodes = [item for item in detail_container.iter() if _tag(item) == "ServiceDetail"] if detail_container is not None else []
        for item in detail_nodes:
            fields = []
            for label, tags in (("Protocol", ("Protocol", "ProtocolName")), ("Source", ("SourcePort",)), ("Destination", ("DestinationPort", "Port")), ("ICMP Type", ("ICMPType",)), ("ICMP Code", ("ICMPCode",))):
                value = _first(item, *tags)
                if value:
                    fields.append(f"{label}: {value}")
            if fields:
                details.append(" | ".join(fields))
        if name:
            services[name] = "\n".join(details) or name
    for node in _nodes(payloads.get("ServiceGroup", "<Response/>"), "ServiceGroup"):
        name = _first(node, "Name")
        members = [value for value in _values(node, {"Service", "Services", "Member", "ServiceName"}) if value != name]
        if name:
            service_groups[name] = members
    for name, members in service_groups.items():
        services[name] = "\n".join(f"{member} ({services.get(member, member)})" for member in members) or name
    return resolved, services


def _join(values: list[str]) -> str:
    return "\n".join(values)


def _feature(node: ET.Element, *names: str) -> str:
    values = _values(node, set(names))
    return _join(values)


def _rule_models(root: ET.Element, rule_entity: str | None) -> list[tuple[ET.Element, ET.Element, str]]:
    """Return real policy rows, excluding group/header nodes, in XML document order."""
    supported = {rule_entity} if rule_entity in RULE_ENTITIES else set(RULE_ENTITIES)
    rows: list[tuple[ET.Element, ET.Element, str]] = []
    policy_tags = {"NetworkPolicy", "UserPolicy"}
    group_tags = {"FirewallRuleGroup", "RuleGroup", "PolicyGroup"}

    def walk(parent: ET.Element, inherited_group: str = "", rule_root: ET.Element | None = None) -> None:
        current_group = inherited_group
        for child in list(parent):
            tag = _tag(child)
            if tag in group_tags:
                group_name = _direct_text(child, "Name", "GroupName", "RuleGroupName") or (child.text or "").strip()
                current_group = group_name or current_group
                walk(child, current_group, rule_root)
            elif tag in policy_tags:
                group_name = _direct_text(child, "PolicyGroup", "RuleGroup", "GroupName", "RuleGroupName") or current_group
                rows.append((rule_root if rule_root is not None else child, child, group_name))
            elif tag in supported:
                nested = [item for item in list(child) if _tag(item) in policy_tags]
                if nested:
                    walk(child, current_group, child)
                else:
                    rows.append((child, child, current_group))
            else:
                walk(child, current_group, rule_root)

    walk(root)
    return rows


def parse_firewall_rules(payloads: dict[str, str], rule_entity: str | None = None) -> tuple[list[dict[str, str]], list[str]]:
    resolved_objects, resolved_services = _object_maps(payloads)
    rows: list[dict[str, str]] = []
    rule_xml = payloads.get("Rule") or payloads.get("FirewallRule") or payloads.get("SecurityPolicy") or ""
    root = ET.fromstring(rule_xml)
    status = parse_status(rule_xml)
    if status["code"] and status["code"] != "200":
        raise RuntimeError(f"Firewall API {status['code']}: {status['message']}")
    rule_nodes = _rule_models(root, rule_entity)
    has_rule_id = any(_direct_text(rule_root, "RuleID", "PolicyID", "ID") for rule_root, _policy, _group in rule_nodes)
    columns = (["Rule ID"] if has_rule_id else []) + MANAGEMENT_COLUMNS
    for rule_root, policy, inherited_group in rule_nodes:
        source = _under_direct(policy, {"SourceNetworks", "SourceNetwork", "SourceHosts", "SourceObjects"})
        destination = _under_direct(policy, {"DestinationNetworks", "DestinationNetwork", "DestinationHosts", "DestinationObjects"})
        services = _under_direct(policy, {"Services", "ServiceList"})
        raw_status = _direct_text(rule_root, "Status", "Enable", "Enabled")
        normalized_status = {"enable": "활성", "disable": "비활성"}.get(raw_status.casefold(), raw_status)
        row = {
            "Rule ID": _direct_text(rule_root, "RuleID", "PolicyID", "ID").lstrip("#"),
            "Rule Name": _direct_text(rule_root, "Name", "RuleName"),
            "Status": normalized_status,
            "Policy Type": _direct_text(rule_root, "PolicyType"),
            "Rule Group": _direct_text(policy, "PolicyGroup", "RuleGroup", "GroupName", "RuleGroupName") or inherited_group,
            "Action": _direct_text(policy, "Action"),
            "Source Zone": _join(_under_direct(policy, {"SourceZones", "SourceZone"})),
            "Source Object": _join(source),
            "Source Resolved": _join([resolved_objects.get(value, value) for value in source]),
            "Destination Zone": _join(_under_direct(policy, {"DestinationZones", "DestinationZone"})),
            "Destination Object": _join(destination),
            "Destination Resolved": _join([resolved_objects.get(value, value) for value in destination]),
            "Service": _join(services),
            "Service Resolved / Protocol / Port": _join([resolved_services.get(value, value) for value in services]),
            "Schedule": _feature(policy, "Schedule"),
            "IPS": _feature(policy, "IntrusionPrevention", "IPSPolicy", "IPS"),
            "AV": _feature(policy, "MalwareScanning", "Antivirus", "AVPolicy", "ScanHTTP", "ScanFTP"),
            "Web": _feature(policy, "WebFilter", "WebFilterPolicy"),
            "Application": _feature(policy, "ApplicationControl", "ApplicationControlPolicy"),
            "QoS": _feature(policy, "TrafficShapingPolicy", "QoSPolicy", "TrafficShaping"),
            "Heartbeat": _feature(policy, "Heartbeat", "MinimumSourceHBPermitted", "MinimumDestinationHBPermitted"),
            "Linked NAT": _feature(policy, "LinkedNATRule", "LinkedNAT", "NATRule"),
            "Proxy": _feature(policy, "ProxyMode", "UseWebProxy", "Proxy"),
            "Log": _feature(policy, "LogTraffic", "LogFirewallTraffic"),
            "Description": _direct_text(rule_root, "Description"),
        }
        rows.append(row)
    return rows, columns


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
        diagnostics: dict[str, dict[str, Any]] = {}
        for config in configs:
            name = config["name"]
            progress(f"{name} Firewall Rule 및 Object 조회 중")
            try:
                client = FirewallClient(config)
                rule_response = client.get_rules_compatible()
                diagnostics[name] = {"apiVersion": rule_response["apiVersion"], "ruleEntity": rule_response["entity"]}
                log.info("Firewall rule API selected firewall=%s api_version=%s entity=%s", name, rule_response["apiVersion"] or "unknown", rule_response["entity"])
                payloads = {"Rule": rule_response["raw"]}
                enrichment_errors = []
                for entity in ENTITIES:
                    try:
                        raw = client.get(entity)
                        entity_status = parse_status(raw)
                        if entity_status["code"] and entity_status["code"] != "200":
                            raise RuntimeError(f"Firewall API entity {entity} {entity_status['code']}: {entity_status['message']}")
                        _nodes(raw, entity)  # Validate enrichment XML before it reaches the rule parser.
                        payloads[entity] = raw
                        log.info("Firewall XML enrichment validated firewall=%s api_version=%s entity=%s status=%s", name, rule_response["apiVersion"] or "unknown", entity, entity_status["code"] or "unknown")
                    except Exception as exc:
                        enrichment_errors.append(f"{entity}: {type(exc).__name__}: {exc}")
                        log.warning("Firewall XML enrichment unavailable firewall=%s api_version=%s entity=%s error=%s", name, rule_response["apiVersion"] or "unknown", entity, exc)
                diagnostics[name]["enrichmentErrors"] = enrichment_errors
                rows, columns = parse_firewall_rules(payloads, rule_response["entity"])
                sheets.append({"name": name, "rows": rows, "columns": columns, "cellStyles": {"Status": {"활성": 3, "비활성": 4}}})
                counts[name] = len(rows)
            except Exception as exc:
                errors.append({"Firewall": name, "Error Type": classify_export_error(exc), "Message": str(exc)})
        if errors:
            sheets.append({"name": "Export Errors", "rows": errors, "columns": ["Firewall", "Error Type", "Message"]})
        export_dir = self.root / "exports"
        path = export_dir / f"Sophos_Firewall_Rules_{date.today().isoformat()}.xlsx"
        names = write_xlsx_workbook(path, sheets)
        return {"filename": path.name, "path": str(path), "sheets": names, "counts": counts, "errors": errors, "diagnostics": diagnostics}
