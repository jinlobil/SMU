from __future__ import annotations

import json
import logging
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, Callable


AWS_OPERATIONS = {
    "instances": ("describe_instances", "Reservations"),
    "security_groups": ("describe_security_groups", "SecurityGroups"),
    "security_group_rules": ("describe_security_group_rules", "SecurityGroupRules"),
    "network_interfaces": ("describe_network_interfaces", "NetworkInterfaces"),
    "vpcs": ("describe_vpcs", "Vpcs"),
    "subnets": ("describe_subnets", "Subnets"),
    "instance_types": ("describe_instance_types", "InstanceTypes"),
    "volumes": ("describe_volumes", "Volumes"),
    "addresses": ("describe_addresses", "Addresses"),
}
log = logging.getLogger("smu.aws")


class AwsConfigurationError(ValueError):
    pass


def load_aws_credentials(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if path.exists():
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key.strip() in {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"}:
                values[key.strip()] = value.strip()
    missing = [key for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION") if not values.get(key)]
    if missing:
        raise AwsConfigurationError("AWS Credential 설정 필요")
    return values


def json_safe(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    return value


class AwsCollector:
    def __init__(self, root: Path, client_factory: Callable[..., Any] | None = None):
        self.root = root
        self.credential_path = root / "env/aws_env.txt"
        self.client_factory = client_factory

    def _client(self, credentials: dict[str, str]):
        if self.client_factory:
            return self.client_factory(credentials)
        try:
            import boto3
        except ModuleNotFoundError:
            raise RuntimeError("AWS SDK(boto3) 설치 필요") from None
        return boto3.client(
            "ec2", region_name=credentials["AWS_REGION"],
            aws_access_key_id=credentials["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=credentials["AWS_SECRET_ACCESS_KEY"],
        )

    @staticmethod
    def _pages(client: Any, operation: str, result_key: str) -> list[dict[str, Any]]:
        # DescribeAddresses has no paginator/NextToken in the EC2 API.
        if operation == "describe_addresses":
            return client.describe_addresses().get(result_key, [])
        rows: list[dict[str, Any]] = []
        for page in client.get_paginator(operation).paginate():
            values = page.get(result_key, [])
            if operation == "describe_instances":
                rows.extend(instance for reservation in values for instance in reservation.get("Instances", []))
            else:
                rows.extend(values)
        return rows

    def collect(self, progress: Callable[[str], None] = lambda _message: None) -> dict[str, Any]:
        credentials = load_aws_credentials(self.credential_path)
        operation = "create_ec2_client"
        try:
            client = self._client(credentials)
            output: dict[str, Any] = {}
            for number, (name, (operation, result_key)) in enumerate(AWS_OPERATIONS.items(), 1):
                progress(f"AWS {number}/{len(AWS_OPERATIONS)} · {operation}")
                output[name] = self._pages(client, operation, result_key)
        except AwsConfigurationError:
            raise
        except Exception as exc:
            code = str(getattr(exc, "response", {}).get("Error", {}).get("Code", ""))
            log.error("AWS fetch failed operation=%s error_type=%s error_code=%s", operation, type(exc).__name__, code or "-")
            if str(exc) == "AWS SDK(boto3) 설치 필요":
                raise
            if code in {"InvalidClientTokenId", "AuthFailure", "UnrecognizedClientException"}:
                raise RuntimeError("AWS API 인증 실패") from None
            if code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}:
                raise RuntimeError("AWS API 조회 권한 없음") from None
            if code in {"RequestLimitExceeded", "Throttling", "ThrottlingException"}:
                raise RuntimeError("AWS API 호출 제한") from None
            if code or type(exc).__name__ in {"EndpointConnectionError", "ConnectTimeoutError", "ReadTimeoutError"}:
                raise RuntimeError("AWS API 통신 실패") from None
            raise RuntimeError("기타 AWS 수집 오류") from None
        counts = {name: len(rows) for name, rows in output.items()}
        return json_safe({"metadata": {"region": credentials["AWS_REGION"], "fetched_at": datetime.now().astimezone().isoformat(), "counts": counts}, **output})


class AwsAssetService:
    SEARCH_FIELDS = {"all", "name", "instanceId", "privateIp", "publicIp", "description", "securityGroups"}
    SORT_FIELDS = {"name", "instanceId", "state", "privateIp", "publicIp", "os", "description"}

    def __init__(self, root: Path):
        self.path = root / "cache/aws.json"

    def _load(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    @staticmethod
    def _tags(instance: dict[str, Any]) -> dict[str, str]:
        return {str(tag.get("Key")): str(tag.get("Value", "")) for tag in instance.get("Tags", []) if isinstance(tag, dict) and tag.get("Key")}

    @staticmethod
    def attached_interfaces(instance: dict[str, Any], data: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Resolve actual ENI attachments without flattening their SG sets.

        Existing asset callers use the embedded DescribeInstances records.
        IP-specific consumers can enrich them from DescribeNetworkInterfaces,
        but only when the raw ENI attachment identifies the same instance.
        """
        interfaces = [item for item in instance.get("NetworkInterfaces", []) if isinstance(item, dict)]
        if data is None:
            return interfaces
        by_id = {str(item["NetworkInterfaceId"]): dict(item) for item in interfaces if item.get("NetworkInterfaceId")}
        for raw in data.get("network_interfaces", []):
            if not isinstance(raw, dict) or not raw.get("NetworkInterfaceId"):
                continue
            if not instance.get("InstanceId") or (raw.get("Attachment") or {}).get("InstanceId") != instance["InstanceId"]:
                continue
            identifier = str(raw["NetworkInterfaceId"])
            by_id[identifier] = {**by_id.get(identifier, {}), **raw}
        return list(by_id.values())

    @staticmethod
    def _group_references(instance: dict[str, Any]) -> list[dict[str, Any]]:
        """Return attached groups by AWS ID, including groups exposed through ENIs."""
        references: dict[str, dict[str, Any]] = {}
        candidates: list[dict[str, Any]] = []
        for interface in AwsAssetService.attached_interfaces(instance):
            if isinstance(interface, dict):
                candidates.extend(interface.get("Groups", []))
        if not instance.get("NetworkInterfaces"):
            candidates.extend(instance.get("SecurityGroups", []))
        for item in candidates:
            if isinstance(item, dict) and item.get("GroupId"):
                references.setdefault(str(item["GroupId"]), item)
        return list(references.values())

    def _row(self, instance: dict[str, Any], groups: dict[str, dict[str, Any]]) -> dict[str, Any]:
        tags = self._tags(instance)
        attached = [groups.get(str(item.get("GroupId")), item) for item in self._group_references(instance)]
        os_values = [tags.get(key, "").strip() for key in ("OS", "OS_type")]
        return {
            "name": tags.get("Name") or "-", "instanceId": str(instance.get("InstanceId") or "-"),
            "state": str((instance.get("State") or {}).get("Name") or "-"),
            "privateIp": str(instance.get("PrivateIpAddress") or "-"), "publicIp": str(instance.get("PublicIpAddress") or "-"),
            "os": " / ".join(value for value in os_values if value) or "-", "description": tags.get("Description") or "-",
            "securityGroups": [{"id": str(group.get("GroupId") or "-"), "name": str(group.get("GroupName") or "-")} for group in attached],
        }

    def _instances(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        return [item for item in data.get("instances", []) if isinstance(item, dict)]

    def _instance_group_map(self, data: dict[str, Any]) -> dict[str, dict[str, dict[str, Any]]]:
        """Map GroupId -> InstanceId -> instance/ENI data using attachment IDs only."""
        result: dict[str, dict[str, dict[str, Any]]] = {}
        for instance in self._instances(data):
            instance_id = str(instance.get("InstanceId") or "")
            if not instance_id:
                continue
            by_group: dict[str, set[str]] = {}
            for interface in self.attached_interfaces(instance):
                if not isinstance(interface, dict):
                    continue
                eni = str(interface.get("NetworkInterfaceId") or "")
                for group in interface.get("Groups", []):
                    if isinstance(group, dict) and group.get("GroupId"):
                        by_group.setdefault(str(group["GroupId"]), set()).add(eni)
            # AWS returns ENIs for normal EC2 responses; keep an instance-level
            # fallback only for older/minimal cache records that contain no ENIs.
            if not instance.get("NetworkInterfaces"):
                for group in instance.get("SecurityGroups", []):
                    if isinstance(group, dict) and group.get("GroupId"):
                        by_group.setdefault(str(group["GroupId"]), set())
            for group_id, eni_ids in by_group.items():
                result.setdefault(group_id, {})[instance_id] = {"instance": instance, "eniIds": sorted(value for value in eni_ids if value)}
        return result

    def instance_summary(self) -> dict[str, int]:
        instances = self._instances(self._load())
        running = sum((item.get("State") or {}).get("Name") == "running" for item in instances)
        stopped = sum((item.get("State") or {}).get("Name") == "stopped" for item in instances)
        return {"total": len(instances), "running": running, "stopped": stopped, "other": len(instances) - running - stopped}

    def list_instances(self, query: str = "", field: str = "all", page: int = 1, page_size: int = 50,
                       sort: str = "name", direction: str = "asc") -> dict[str, Any]:
        if field not in self.SEARCH_FIELDS or sort not in self.SORT_FIELDS or direction not in {"asc", "desc"}:
            raise ValueError("Unsupported AWS asset query")
        data = self._load(); groups = {str(item.get("GroupId")): item for item in data.get("security_groups", [])}
        rows = [self._row(instance, groups) for instance in data.get("instances", []) if isinstance(instance, dict)]
        keyword = query.strip().casefold()
        if keyword:
            fields = ("name", "instanceId", "privateIp", "publicIp", "description", "securityGroups") if field == "all" else (field,)
            def text(row, name):
                return " ".join(item["name"] for item in row[name]) if name == "securityGroups" else str(row[name])
            rows = [row for row in rows if any(keyword in text(row, name).casefold() for name in fields)]
        rows.sort(key=lambda row: (str(row[sort]).casefold(), row["instanceId"]), reverse=direction == "desc")
        total = len(rows); start = (page - 1) * page_size
        return {"items": rows[start:start + page_size], "pagination": {"page": page, "pageSize": page_size, "total": total, "totalPages": max(1, (total + page_size - 1) // page_size)}, "summary": self.instance_summary(), "source": {"path": str(self.path), "exists": self.path.exists()}, "metadata": data.get("metadata", {})}

    @staticmethod
    def _rule(rule: dict[str, Any], groups: dict[str, dict[str, Any]]) -> dict[str, Any]:
        protocol = str(rule.get("IpProtocol", "-"))
        if protocol == "-1": protocol_display, port = "ALL", "ALL"
        elif protocol in {"icmp", "icmpv6", "1", "58"}:
            protocol_display = "ICMPv6" if protocol in {"icmpv6", "58"} else "ICMP"
            port = f"Type {rule.get('FromPort', '-')} / Code {rule.get('ToPort', '-')}"
        else:
            protocol_display = protocol.upper()
            start, end = rule.get("FromPort"), rule.get("ToPort")
            port = "-" if start is None else str(start) if start == end else f"{start}-{end}"
        referenced = str(rule.get("ReferencedGroupInfo", {}).get("GroupId") or "")
        prefix = str(rule.get("PrefixListId") or "")
        cidr = str(rule.get("CidrIpv4") or rule.get("CidrIpv6") or "")
        source_type = "Referenced SG" if referenced else "Prefix List" if prefix else "IPv6 CIDR" if rule.get("CidrIpv6") else "IPv4 CIDR" if cidr else "-"
        target = referenced or prefix or cidr or "-"
        if referenced and referenced in groups:
            target = f"{groups[referenced].get('GroupName') or '-'} ({referenced})"
        return {"ruleId": str(rule.get("SecurityGroupRuleId") or "-"), "isEgress": bool(rule.get("IsEgress")),
                "protocol": protocol_display, "port": port, "target": target, "sourceType": source_type,
                "cidr": cidr or "-", "referencedGroupId": referenced or "-", "referencedGroupName": str(groups.get(referenced, {}).get("GroupName") or "-"),
                "prefixListId": prefix or "-", "fromPort": rule.get("FromPort", "-"), "toPort": rule.get("ToPort", "-"),
                "description": str(rule.get("Description") or "-")}

    def list_security_groups(self, query: str = "", page: int = 1, page_size: int = 50) -> dict[str, Any]:
        data = self._load(); groups = [item for item in data.get("security_groups", []) if isinstance(item, dict)]
        mappings = self._instance_group_map(data)
        rules: dict[str, list[dict[str, Any]]] = {}
        for raw in data.get("security_group_rules", []):
            rules.setdefault(str(raw.get("GroupId")), []).append(raw)
        rows = []
        for group in groups:
            group_id = str(group.get("GroupId") or "-"); attached = list(mappings.get(group_id, {}).values())
            search_servers = []
            for link in attached:
                instance = link["instance"]; tags = self._tags(instance)
                search_servers.extend([tags.get("Name", ""), str(instance.get("InstanceId", "")), str(instance.get("PrivateIpAddress", "")), str(instance.get("PublicIpAddress", ""))])
            group_rules = rules.get(group_id, [])
            rows.append({"name": str(group.get("GroupName") or "-"), "groupId": group_id, "vpcId": str(group.get("VpcId") or "-"),
                         "inbound": sum(not bool(item.get("IsEgress")) for item in group_rules), "outbound": sum(bool(item.get("IsEgress")) for item in group_rules),
                         "instances": len(attached), "search": " ".join(search_servers)})
        summary = {"total": len(groups), "attached": sum(bool(mappings.get(str(item.get("GroupId")))) for item in groups), "rules": len(data.get("security_group_rules", []))}
        summary["notAttached"] = summary["total"] - summary["attached"]
        keyword = query.strip().casefold()
        if keyword:
            rows = [row for row in rows if keyword in " ".join(str(row[key]) for key in ("name", "groupId", "vpcId", "search")).casefold()]
        rows.sort(key=lambda row: (row["name"].casefold(), row["groupId"])); total = len(rows); start = (page - 1) * page_size
        for row in rows: row.pop("search", None)
        return {"items": rows[start:start + page_size], "summary": summary, "pagination": {"page": page, "pageSize": page_size, "total": total, "totalPages": max(1, (total + page_size - 1) // page_size)}, "metadata": data.get("metadata", {})}

    def security_group_detail(self, group_id: str) -> dict[str, Any] | None:
        data = self._load(); groups = {str(item.get("GroupId")): item for item in data.get("security_groups", [])}
        group = groups.get(group_id)
        if not group: return None
        rules = [self._rule(item, groups) for item in data.get("security_group_rules", []) if str(item.get("GroupId")) == group_id]
        instances = []
        all_groups = {str(item.get("GroupId")): item for item in data.get("security_groups", [])}
        for link in self._instance_group_map(data).get(group_id, {}).values():
            row = self._row(link["instance"], all_groups); row["eniIds"] = link["eniIds"]; instances.append(row)
        return {"group": group, "inbound": [item for item in rules if not item["isEgress"]], "outbound": [item for item in rules if item["isEgress"]], "instances": instances,
                "summary": {"inbound": sum(not item["isEgress"] for item in rules), "outbound": sum(item["isEgress"] for item in rules), "instances": len(instances)}}

    def detail(self, instance_id: str) -> dict[str, Any] | None:
        data = self._load(); instance = next((item for item in data.get("instances", []) if item.get("InstanceId") == instance_id), None)
        if not instance:
            return None
        group_ids = {group_id for group_id, links in self._instance_group_map(data).items() if instance_id in links}
        eni_ids = {str(item.get("NetworkInterfaceId")) for item in instance.get("NetworkInterfaces", [])}
        network_interfaces = [item for item in data.get("network_interfaces", []) if str(item.get("NetworkInterfaceId")) in eni_ids]
        for interface in network_interfaces:
            group_ids.update(str(item.get("GroupId")) for item in interface.get("Groups", []) if item.get("GroupId"))
        rule_counts: dict[str, dict[str, int]] = {group_id: {"inbound": 0, "outbound": 0} for group_id in group_ids}
        for rule in data.get("security_group_rules", []):
            group_id = str(rule.get("GroupId"))
            if group_id in rule_counts:
                rule_counts[group_id]["outbound" if rule.get("IsEgress") else "inbound"] += 1
        attached_groups = [{"id": str(item.get("GroupId")), "name": str(item.get("GroupName") or "-"), **rule_counts[str(item.get("GroupId"))]}
                           for item in data.get("security_groups", []) if str(item.get("GroupId")) in group_ids]
        return {"instance": instance,
                "securityGroups": [item for item in data.get("security_groups", []) if str(item.get("GroupId")) in group_ids],
                "attachedSecurityGroups": attached_groups,
                "securityGroupRules": [item for item in data.get("security_group_rules", []) if str(item.get("GroupId")) in group_ids],
                "networkInterfaces": network_interfaces,
                "vpc": next((item for item in data.get("vpcs", []) if item.get("VpcId") == instance.get("VpcId")), None),
                "subnet": next((item for item in data.get("subnets", []) if item.get("SubnetId") == instance.get("SubnetId")), None)}
