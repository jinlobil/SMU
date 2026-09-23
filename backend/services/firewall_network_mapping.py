from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class NetworkMapping:
    site: str
    category: str
    cidr: str
    aliases: tuple[str, ...] = ()

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(self.cidr)


NETWORK_MAPPINGS = (
    NetworkMapping("서울사업장 유선", "OFFICE", "101.1.0.0/22", ("KR_SEOUL_PRD_101.1.0.0_22",)),
    NetworkMapping("서울사업장 무선", "OFFICE", "101.1.4.0/22", ("KR_SEOUL_WAP_101.1.4.0_22",)),
    NetworkMapping("서울사업장 SSL-VPN", "OFFICE", "106.1.0.0/16", ("KR_SEOUL_VPN_106.1.0.0/16",)),
    NetworkMapping("안성사업장", "OFFICE", "101.2.1.0/24", ("KR_ANSEONG_PRD_101.2.1.0_24",)),
    NetworkMapping("이천사업장", "OFFICE", "101.3.0.0/23", ("KR_ICHEON_PRD_101.3.0.0_23",)),
    NetworkMapping("호치민 사무실", "OFFICE", "103.1.0.0/16"),
    NetworkMapping("호치민 물류창고", "OFFICE", "103.2.0.0/16"),
    NetworkMapping("하노이 사무실", "OFFICE", "103.3.0.0/16"),
    NetworkMapping("하노이 물류창고", "OFFICE", "103.4.0.0/16"),
    NetworkMapping("붕따우 유리", "OFFICE", "103.5.0.0/16"),
    NetworkMapping("붕따우 사출", "OFFICE", "103.6.0.0/16"),
    NetworkMapping("인도네시아 사무실", "OFFICE", "104.1.0.0/16"),
    NetworkMapping("태국 사무실", "OFFICE", "105.1.0.0/16"),
    NetworkMapping("중국 사무실", "OFFICE", "102.0.0.0/12"),
    NetworkMapping("AWS_LOCK_VPC", "LAN", "100.1.0.0/22", ("AWS_LOCK_VPC",)),
    NetworkMapping("AWS_AIDR_VPC", "LAN", "10.10.0.0/16", ("AWS_AIDR_VPC",)),
    NetworkMapping("AWS_BIGW_VPC", "LAN", "10.20.0.0/16", ("AWS_BIGW_VPC",)),
    NetworkMapping("NCP", "LAN", "10.0.0.0/16", ("NCP",)),
)

IP_TOKEN = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?:/(?:\d{1,2}|(?:\d{1,3}\.){3}\d{1,3}))?")
MASKED_NETWORK = re.compile(r"((?:\d{1,3}\.){3}\d{1,3})\s*/\s*((?:\d{1,3}\.){3}\d{1,3})")
UNKNOWN_NAMES = {"any", "all", "모든 호스트", "모든호스트", "*"}


def _matches_for_network(candidate: ipaddress.IPv4Network) -> list[NetworkMapping]:
    containing = [item for item in NETWORK_MAPPINGS if candidate.subnet_of(item.network)]
    if containing:
        longest = max(item.network.prefixlen for item in containing)
        return [item for item in containing if item.network.prefixlen == longest]
    return [item for item in NETWORK_MAPPINGS if item.network.subnet_of(candidate)]


def classify_rule_side(object_text: str, resolved_text: str) -> tuple[set[str], list[str]]:
    """Classify a parsed rule side from mapped object names and resolved addresses."""
    combined = f"{object_text}\n{resolved_text}"
    lowered_lines = {line.strip().casefold() for line in combined.splitlines() if line.strip()}
    if lowered_lines & UNKNOWN_NAMES:
        return set(), []

    matches: dict[tuple[str, str], NetworkMapping] = {}
    for item in NETWORK_MAPPINGS:
        names = (item.site, *item.aliases)
        if any(name.casefold() in lowered_lines for name in names):
            matches[(item.site, item.category)] = item

    saw_address = False
    saw_unmapped_address = False
    address_text = combined
    tokens: list[str] = []
    for match in MASKED_NETWORK.finditer(combined):
        tokens.append(f"{match.group(1)}/{match.group(2)}")
        address_text = address_text.replace(match.group(0), " ")
    tokens.extend(IP_TOKEN.findall(address_text))
    for token in tokens:
        try:
            candidate = ipaddress.ip_network(token, strict=False)
        except ValueError:
            continue
        saw_address = True
        mapped = _matches_for_network(candidate)
        if mapped:
            for item in mapped:
                matches[(item.site, item.category)] = item
        elif candidate.is_global:
            matches[("Internet", "WAN")] = NetworkMapping("Internet", "WAN", str(candidate))
        else:
            saw_unmapped_address = True

    if saw_unmapped_address or (not matches and not saw_address):
        return set(), []
    categories = {item.category for item in matches.values()}
    sites = list(dict.fromkeys(item.site for item in matches.values()))
    return categories, sites


def classify_analysis_sheet(source_categories: set[str], destination_categories: set[str]) -> str:
    if len(source_categories) != 1 or len(destination_categories) != 1:
        return "ETC"
    pair = {next(iter(source_categories)), next(iter(destination_categories))}
    if pair == {"LAN", "OFFICE"}:
        return "LAN ↔ OFFICE"
    if pair == {"LAN", "WAN"}:
        return "LAN ↔ WAN"
    return "ETC"
