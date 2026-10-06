"""Cache-only, forward-direction AWS Security Group policy checks."""
from __future__ import annotations

import ipaddress
import json
import logging
from pathlib import Path
from typing import Any

from backend.services.aws_assets import AwsAssetService


log = logging.getLogger("smu.aws.path_check")
PROTOCOLS = {"-1": "ALL", "6": "TCP", "TCP": "TCP", "17": "UDP", "UDP": "UDP",
             "1": "ICMP", "ICMP": "ICMP", "58": "ICMPV6", "ICMPV6": "ICMPV6",
             "47": "GRE", "GRE": "GRE", "50": "ESP", "ESP": "ESP", "51": "AH", "AH": "AH"}


def broad_query(protocol: str, port: int | None, protocol_number: int | None) -> bool:
    return protocol == "ANY" or (protocol in {"TCP", "UDP"} and port is None) or (protocol == "IP" and protocol_number is None)


def _protocol(value: Any) -> str:
    raw = str(value).upper()
    return PROTOCOLS.get(raw, raw)


def _service(rule: dict[str, Any], protocol: str, port: int | None, protocol_number: int | None) -> tuple[str, str]:
    if broad_query(protocol, port, protocol_number):
        return "CANDIDATE", "Protocol/Port 조건 확인 필요"
    if not isinstance(rule.get("IpProtocol"), (str, int)) or not str(rule["IpProtocol"]).strip():
        return "CANDIDATE", "Rule Protocol 데이터 누락"
    actual = _protocol(rule["IpProtocol"])
    requested = _protocol(protocol_number) if protocol == "IP" else _protocol(protocol)
    if actual == "ALL":
        return "MATCH", "모든 Protocol 허용"
    if actual != requested:
        return "NO_MATCH", "Protocol 불일치"
    if actual in {"TCP", "UDP"}:
        if port is None:
            return "CANDIDATE", "TCP/UDP Destination Port 확인 필요"
        start, end = rule.get("FromPort"), rule.get("ToPort")
        if not isinstance(start, int) or not isinstance(end, int) or not 0 <= start <= end <= 65535:
            return "CANDIDATE", "Rule Port 범위 확인 불가"
        return ("MATCH", "Destination Port 일치") if start <= port <= end else ("NO_MATCH", "Destination Port 불일치")
    if actual in {"ICMP", "ICMPV6"} and (rule.get("FromPort"), rule.get("ToPort")) != (-1, -1):
        return "CANDIDATE", "ICMP Type/Code 입력이 없어 제한 조건 확인 필요"
    return "MATCH", "Protocol 일치"


def _ip(value: Any):
    try:
        return ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return None


def _interface_addresses(interface: dict[str, Any]) -> list[tuple[Any, str]]:
    values = [(interface.get("PrivateIpAddress"), "private"), ((interface.get("Association") or {}).get("PublicIp"), "public")]
    for item in interface.get("PrivateIpAddresses", []):
        values.extend([(item.get("PrivateIpAddress"), "private"), ((item.get("Association") or {}).get("PublicIp"), "public")])
    values.extend((item.get("Ipv6Address"), "ipv6") for item in interface.get("Ipv6Addresses", []))
    return [(address, kind) for value, kind in values if (address := _ip(value)) is not None]


class AwsSecurityGroupPathService:
    def __init__(self, root: Path):
        self.path = root / "cache/aws.json"

    @staticmethod
    def _unknown_endpoint(reason: str, **fields) -> dict[str, Any]:
        return {"state": "UNKNOWN", "reason": reason, **fields}

    def _endpoint(self, query, data: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(data.get("instances"), list) or any(not isinstance(item, dict) for item in data["instances"]):
            return self._unknown_endpoint("AWS Instance 데이터 누락")
        found: dict[tuple[str, str], dict[str, Any]] = {}
        incomplete_addresses = False
        for instance in data["instances"]:
            identifier = str(instance.get("InstanceId") or "")
            if not identifier:
                return self._unknown_endpoint("AWS Instance ID 누락")
            interfaces = AwsAssetService.attached_interfaces(instance, data)
            has_address = False
            for interface in interfaces:
                addresses = _interface_addresses(interface)
                # EIPs are associated through exact ENI IDs, or through an
                # instance + private IP pair that identifies this ENI.
                for address in data.get("addresses", []):
                    attached = address.get("NetworkInterfaceId") == interface.get("NetworkInterfaceId") and bool(interface.get("NetworkInterfaceId"))
                    if not address.get("NetworkInterfaceId") and address.get("InstanceId") == identifier:
                        private = _ip(address.get("PrivateIpAddress"))
                        attached = private is not None and any(ip == private and kind == "private" for ip, kind in addresses)
                    if attached and (public := _ip(address.get("PublicIp"))) is not None:
                        addresses.append((public, "eip"))
                has_address = has_address or bool(addresses)
                matching = [(ip, kind) for ip, kind in addresses if ip.version == query.version and ip in query]
                if not matching:
                    continue
                tags = AwsAssetService._tags(instance)
                group_refs = interface.get("Groups")
                groups_valid = isinstance(group_refs, list) and all(isinstance(group, dict) and isinstance(group.get("GroupId"), str) and group["GroupId"] for group in group_refs)
                found[(identifier, str(interface.get("NetworkInterfaceId") or ""))] = {
                    "state": "IDENTIFIED", "reason": "IP와 연결 ENI exact match", "name": tags.get("Name") or "-",
                    "instanceId": identifier, "eniId": interface.get("NetworkInterfaceId") or "-", "ip": str(query.network_address),
                    "addressKind": matching[0][1], "vpcId": interface.get("VpcId") or instance.get("VpcId") or "",
                    "subnetId": interface.get("SubnetId") or instance.get("SubnetId") or "",
                    "groupIds": list(dict.fromkeys(str(group["GroupId"]) for group in group_refs)) if groups_valid else [],
                    "groupsValid": groups_valid and bool(interface.get("NetworkInterfaceId")),
                }
            # An instance/EIP match without an IP-specific ENI is not N/A.
            possible = [_ip(instance.get("PrivateIpAddress")), _ip(instance.get("PublicIpAddress"))]
            possible.extend(_ip(address.get("PublicIp")) for address in data.get("addresses", []) if address.get("InstanceId") == identifier)
            if not has_address and not any(ip is not None for ip in possible): incomplete_addresses = True
            if any(ip is not None and ip.version == query.version and ip in query for ip in possible) and not any(key[0] == identifier for key in found):
                found[(identifier, "")] = self._unknown_endpoint("EC2는 식별됐으나 IP에 연결된 ENI 확인 불가", instanceId=identifier, name=AwsAssetService._tags(instance).get("Name") or "-", ip=str(query.network_address))
        if not found:
            if incomplete_addresses: return self._unknown_endpoint("AWS Instance/ENI IP 데이터 누락")
            return {"state": "N/A", "reason": "입력 IP에 해당하는 AWS EC2 없음"}
        if query.num_addresses != 1:
            return self._unknown_endpoint("CIDR 입력으로 하나의 EC2/ENI를 특정할 수 없음")
        if len(found) != 1:
            return self._unknown_endpoint("동일 IP의 EC2/ENI 식별이 모호함", candidates=[{key: value.get(key) for key in ("instanceId", "eniId")} for value in found.values()])
        return next(iter(found.values()))

    @staticmethod
    def _address(rule: dict[str, Any], peer_query, peer: dict[str, Any], endpoint: dict[str, Any], path: list[str], partial: bool) -> tuple[str, str]:
        referenced = (rule.get("ReferencedGroupInfo") or {}).get("GroupId")
        if referenced:
            if peer["state"] == "UNKNOWN" or (peer["state"] == "IDENTIFIED" and not peer.get("groupsValid")):
                return "CANDIDATE", "참조 SG의 상대 ENI 식별/부착 관계 확인 필요"
            if peer["state"] != "IDENTIFIED" or referenced not in peer.get("groupIds", []):
                return ("CANDIDATE", "중간 장비/NAT로 참조 SG 의미 확인 필요") if path or partial else ("NO_MATCH", "상대 ENI에 참조 SG 부착 없음")
            direct = not path and not partial and peer.get("addressKind") in {"private", "ipv6"} and endpoint.get("addressKind") in {"private", "ipv6"}
            same_vpc = endpoint.get("vpcId") and endpoint.get("vpcId") == peer.get("vpcId")
            if direct and same_vpc:
                return "MATCH", "동일 VPC의 직접 경로, 상대 ENI GroupId exact match"
            return "CANDIDATE", "SG 부착은 일치하나 중간 장비/NAT/연결 경로 확인 필요"
        if rule.get("PrefixListId"):
            return "CANDIDATE", f"Prefix List: {rule['PrefixListId']} · 실제 CIDR 목록 미수집"
        cidr = rule.get("CidrIpv4") or rule.get("CidrIpv6")
        if not cidr:
            return "CANDIDATE", "Rule Source/Destination 데이터 확인 불가"
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return "CANDIDATE", "Rule CIDR 확인 불가"
        if network.version != peer_query.version:
            return "NO_MATCH", "IP address family 불일치"
        if peer_query.subnet_of(network):
            return "MATCH", "IP/CIDR containment 일치"
        if peer_query.overlaps(network):
            return "CANDIDATE", "Query CIDR 일부만 Rule에 포함됨"
        return "NO_MATCH", "Rule CIDR에 상대 IP/CIDR 포함 안 됨"

    def _step(self, direction: str, endpoint: dict[str, Any], peer: dict[str, Any], peer_query,
              protocol: str, port: int | None, protocol_number: int | None, data: dict[str, Any], path: list[str], partial: bool) -> dict[str, Any]:
        broad = broad_query(protocol, port, protocol_number)
        result = {"kind": "aws_sg", "label": f"AWS SG {direction}", "direction": direction, "state": endpoint["state"],
                  "endpoint": endpoint, "groups": [], "matches": [], "evaluations": [], "broadQuery": broad, "reason": endpoint["reason"]}
        if endpoint["state"] != "IDENTIFIED":
            return result
        if not endpoint.get("groupsValid") or not endpoint.get("groupIds"):
            return {**result, "state": "UNKNOWN", "reason": "입력 IP에 연결된 ENI의 Attached SG 데이터 확인 불가"}
        group_data, rules = data.get("security_groups"), data.get("security_group_rules")
        if not isinstance(group_data, list) or not isinstance(rules, list):
            return {**result, "state": "UNKNOWN", "reason": "AWS SG/Rule 데이터 누락"}
        groups = {str(group["GroupId"]): group for group in group_data if isinstance(group, dict) and group.get("GroupId")}
        result["groups"] = [{"id": identifier, "name": groups.get(identifier, {}).get("GroupName") or "-"} for identifier in endpoint["groupIds"]]
        incomplete = any(identifier not in groups for identifier in endpoint["groupIds"])
        for raw in rules:
            if not isinstance(raw, dict) or not isinstance(raw.get("GroupId"), str) or not raw["GroupId"] or not isinstance(raw.get("IsEgress"), bool):
                incomplete = True
                continue
            if raw["GroupId"] not in endpoint["groupIds"] or raw["IsEgress"] != (direction == "Outbound"):
                continue
            address_match, address_reason = self._address(raw, peer_query, peer, endpoint, path, partial)
            service_match, service_reason = _service(raw, protocol, port, protocol_number)
            state = "NO_MATCH" if "NO_MATCH" in {address_match, service_match} else "MATCH" if address_match == service_match == "MATCH" else "CANDIDATE"
            if state == "MATCH" and raw["GroupId"] not in groups:
                state = "CANDIDATE"
                address_reason += " · Attached SG 원본 데이터 누락"
            formatted = AwsAssetService._rule(raw, groups)
            actual_protocol = _protocol(raw.get("IpProtocol", "-"))
            start, end = raw.get("FromPort", "-"), raw.get("ToPort", "-")
            if actual_protocol == "ALL": start = end = "ALL"
            elif actual_protocol in {"ICMP", "ICMPV6"}: start, end = f"Type {start}", f"Code {end}"
            evaluation = {**formatted, "groupId": raw["GroupId"], "groupName": groups.get(raw["GroupId"], {}).get("GroupName") or "-",
                          "protocol": actual_protocol, "fromPort": start, "toPort": end, "direction": direction,
                          "addressMatch": address_match, "serviceMatch": service_match, "match": state,
                          "reason": f"{address_reason} · {service_reason}"}
            result["evaluations"].append(evaluation)
            if state != "NO_MATCH": result["matches"].append(evaluation)
        if any(rule["match"] == "MATCH" for rule in result["matches"]):
            result.update(state="PASS", reason="Attached SG의 Allow Rule이 Query 조건과 일치")
        elif broad or incomplete or result["matches"]:
            reason = "AWS SG 데이터 누락/불완전" if incomplete else "Broad Query · Protocol/Port 조건 확인 필요" if broad else "Candidate Rule의 추가 조건 확인 필요"
            result.update(state="UNKNOWN", reason=reason)
        else:
            result.update(state="FAIL", reason="Attached SG에서 Query 조건과 일치하는 Allow Rule 없음")
        return result

    def check(self, source, destination, protocol: str, port: int | None, protocol_number: int | None,
              path: list[str], partial: bool) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, dict): raise ValueError("AWS Cache object required")
            source_endpoint, destination_endpoint = self._endpoint(source, data), self._endpoint(destination, data)
            network_path = None
            if source_endpoint["state"] == destination_endpoint["state"] == "IDENTIFIED":
                source_vpc, destination_vpc = source_endpoint.get("vpcId"), destination_endpoint.get("vpcId")
                same_vpc = bool(source_vpc and destination_vpc and source_vpc == destination_vpc)
                # Site/LAN mappings and Sophos static routes do not prove AWS transit.
                path, partial = [], not same_vpc
                network_path = {"path": path, "partialPath": partial,
                                "mode": "same_vpc" if same_vpc else "unknown",
                                "reason": "동일 VPC · AWS SG 정책 검사" if same_vpc else "AWS 중간 Network Path 확인 불가 · Routing 정보 미수집"}
            return {"networkPath": network_path, "outbound": self._step("Outbound", source_endpoint, destination_endpoint, destination, protocol, port, protocol_number, data, path, partial),
                    "inbound": self._step("Inbound", destination_endpoint, source_endpoint, source, protocol, port, protocol_number, data, path, partial),
                    "cache": {"path": str(self.path), "exists": True, "fetchedAt": (data.get("metadata") or {}).get("fetched_at")}}
        except Exception as exc:
            # AWS data must never discard the already-evaluated Firewall hops.
            log.warning("AWS SG check unavailable error_type=%s", type(exc).__name__)
            reason = "AWS Cache 없음" if isinstance(exc, FileNotFoundError) else "AWS Cache 데이터 확인 불가"
            return {key: {"kind": "aws_sg", "label": f"AWS SG {direction}", "direction": direction, "state": "UNKNOWN", "reason": reason,
                          "endpoint": self._unknown_endpoint(reason), "groups": [], "matches": [], "evaluations": [], "broadQuery": broad_query(protocol, port, protocol_number)}
                    for key, direction in [("outbound", "Outbound"), ("inbound", "Inbound")]}


def policy_summary(steps: list[dict[str, Any]], partial: bool) -> dict[str, str]:
    active = [step for step in steps if step["state"] != "N/A"]
    states = [step["state"] for step in active]
    policy_type = "AWS SG" if active and all(step.get("kind") == "aws_sg" for step in active) else "Firewall / AWS SG"
    if "FAIL" in states:
        return {"state": "FAIL", "label": f"{policy_type} 정책 기준 차단"}
    if partial or not states or "UNKNOWN" in states:
        return {"state": "UNKNOWN", "label": "일부 정책 확인 불가"}
    return {"state": "PASS", "label": f"{policy_type} 정책 기준 허용"}


def firewall_step(result: dict[str, Any]) -> dict[str, Any]:
    policy = result["policy"]
    state = "PASS" if policy["state"] == "allow" else "FAIL" if policy["state"] == "deny" or (policy["state"] == "no_matching_rule" and not policy.get("broadQuery")) else "UNKNOWN"
    return {"kind": "firewall", "label": f"{result['firewall']} Firewall", **result, "state": state}
