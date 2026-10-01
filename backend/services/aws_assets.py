from __future__ import annotations

import json
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
}


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
        import boto3
        return boto3.client(
            "ec2", region_name=credentials["AWS_REGION"],
            aws_access_key_id=credentials["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=credentials["AWS_SECRET_ACCESS_KEY"],
        )

    @staticmethod
    def _pages(client: Any, operation: str, result_key: str) -> list[dict[str, Any]]:
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
            if code in {"InvalidClientTokenId", "AuthFailure", "UnrecognizedClientException"}:
                raise RuntimeError("AWS API 인증 실패") from None
            if code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}:
                raise RuntimeError("AWS API 조회 권한 없음") from None
            raise RuntimeError("AWS API 통신 실패") from None
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
    def _group_references(instance: dict[str, Any]) -> list[dict[str, Any]]:
        """Return attached groups by AWS ID, including groups exposed through ENIs."""
        references: dict[str, dict[str, Any]] = {}
        candidates = list(instance.get("SecurityGroups", []))
        for interface in instance.get("NetworkInterfaces", []):
            if isinstance(interface, dict):
                candidates.extend(interface.get("Groups", []))
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
        return {"items": rows[start:start + page_size], "pagination": {"page": page, "pageSize": page_size, "total": total, "totalPages": max(1, (total + page_size - 1) // page_size)}, "source": {"path": str(self.path), "exists": self.path.exists()}, "metadata": data.get("metadata", {})}

    def detail(self, instance_id: str) -> dict[str, Any] | None:
        data = self._load(); instance = next((item for item in data.get("instances", []) if item.get("InstanceId") == instance_id), None)
        if not instance:
            return None
        group_ids = {str(item.get("GroupId")) for item in self._group_references(instance)}
        eni_ids = {str(item.get("NetworkInterfaceId")) for item in instance.get("NetworkInterfaces", [])}
        network_interfaces = [item for item in data.get("network_interfaces", []) if str(item.get("NetworkInterfaceId")) in eni_ids]
        for interface in network_interfaces:
            group_ids.update(str(item.get("GroupId")) for item in interface.get("Groups", []) if item.get("GroupId"))
        return {"instance": instance,
                "securityGroups": [item for item in data.get("security_groups", []) if str(item.get("GroupId")) in group_ids],
                "securityGroupRules": [item for item in data.get("security_group_rules", []) if str(item.get("GroupId")) in group_ids],
                "networkInterfaces": network_interfaces,
                "vpc": next((item for item in data.get("vpcs", []) if item.get("VpcId") == instance.get("VpcId")), None),
                "subnet": next((item for item in data.get("subnets", []) if item.get("SubnetId") == instance.get("SubnetId")), None)}
