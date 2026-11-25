"""Shared Sophos static route parser used by Path Check and Excel export."""
import ipaddress
import xml.etree.ElementTree as ET

from backend.services.firewall import parse_status


def _tag(node):
    return node.tag.split("}")[-1]


def parse_unicast_routes(xml_text: str) -> list[dict[str, str]]:
    root = ET.fromstring(xml_text)
    status = parse_status(xml_text)
    if status['code'] and status['code'] != '200':
        raise RuntimeError(f"Firewall API {status['code']}")
    rows = []
    for node in root.iter():
        if _tag(node) != "UnicastRoute": continue
        values = {(_tag(child)): (child.text or "").strip() for child in node.iter() if child is not node and (child.text or "").strip()}
        destination = values.get("DestinationIP") or values.get("Destination") or values.get("Network") or ""
        netmask = values.get("Netmask") or values.get("SubnetMask") or values.get("Prefix") or ""
        rows.append({"destination": destination, "netmask": netmask, "gateway": values.get("Gateway", ""), "interface": values.get("Interface", values.get("InterfaceName", "")), "distance": values.get("Distance", ""), "administrative_distance": values.get("AdministrativeDistance", ""), "ip_family": values.get("IPFamily", ""), "blackhole": values.get("Blackhole", ""), "status": values.get("Status", ""), "description": values.get("Description", "")})
    return rows



def route_cidr(destination, netmask):
    try:
        if not destination or not netmask: return ''
        network = ipaddress.IPv4Network(f'{destination}/{netmask}', strict=False)
        return str(network)
    except (ValueError, TypeError): return ''
