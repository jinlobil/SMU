from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from backend.services.aws_assets import AwsAssetService
from backend.services.spreadsheet import write_xlsx_workbook


def _tags(item: dict[str, Any]) -> dict[str, str]:
    return {str(tag.get("Key")): str(tag.get("Value", "")) for tag in item.get("Tags", []) if isinstance(tag, dict) and tag.get("Key")}


def _names(groups: list[dict[str, Any]], lookup: dict[str, dict[str, Any]]) -> str:
    values = []
    for group in groups:
        group_id = str(group.get("GroupId") or "")
        resolved = lookup.get(group_id, group)
        values.append(f"{resolved.get('GroupName') or '-'} ({group_id})")
    return "\n".join(dict.fromkeys(values)) or "-"


class AwsExportService:
    def __init__(self, root: Path):
        self.root = root
        self.cache = root / "cache/aws.json"

    def _load(self) -> dict[str, Any]:
        try:
            data = json.loads(self.cache.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _sheet(name: str, columns: list[tuple[str, str]], rows: list[dict[str, Any]]) -> dict[str, Any]:
        return {"name": name, "rows": rows, "columns": [key for key, _label in columns], "headers": dict(columns)}

    def _ec2_sheets(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        groups = {str(item.get("GroupId")): item for item in data.get("security_groups", [])}
        region = str((data.get("metadata") or {}).get("region") or "-")
        instances, interfaces = [], []
        for instance in data.get("instances", []):
            tags = _tags(instance); instance_id = str(instance.get("InstanceId") or "-"); name = tags.get("Name") or "-"
            attached_groups = [group for interface in instance.get("NetworkInterfaces", []) for group in interface.get("Groups", [])]
            if not instance.get("NetworkInterfaces"): attached_groups = instance.get("SecurityGroups", [])
            instances.append({"name": name, "instanceId": instance_id, "state": (instance.get("State") or {}).get("Name") or "-", "instanceType": instance.get("InstanceType") or "-",
                "privateIp": instance.get("PrivateIpAddress") or "-", "publicIp": instance.get("PublicIpAddress") or "-", "os": tags.get("OS") or "-", "osType": tags.get("OS_type") or "-",
                "description": tags.get("Description") or "-", "project": tags.get("Project") or "-", "environment": tags.get("Environment") or "-", "purpose": tags.get("Purpose") or "-",
                "region": region, "availabilityZone": (instance.get("Placement") or {}).get("AvailabilityZone") or "-", "vpcId": instance.get("VpcId") or "-", "subnetId": instance.get("SubnetId") or "-",
                "securityGroups": _names(attached_groups, groups), "launchTime": instance.get("LaunchTime") or "-"})
            for interface in instance.get("NetworkInterfaces", []):
                private_ips = [str(item.get("PrivateIpAddress")) for item in interface.get("PrivateIpAddresses", []) if item.get("PrivateIpAddress")]
                public_ips = [str((item.get("Association") or {}).get("PublicIp")) for item in interface.get("PrivateIpAddresses", []) if (item.get("Association") or {}).get("PublicIp")]
                interfaces.append({"name": name, "instanceId": instance_id, "eniId": interface.get("NetworkInterfaceId") or "-", "deviceIndex": (interface.get("Attachment") or {}).get("DeviceIndex", "-"),
                    "vpcId": interface.get("VpcId") or instance.get("VpcId") or "-", "subnetId": interface.get("SubnetId") or instance.get("SubnetId") or "-",
                    "primaryPrivateIp": interface.get("PrivateIpAddress") or "-", "privateIps": "\n".join(private_ips) or "-", "publicIp": "\n".join(public_ips) or "-",
                    "securityGroups": _names(interface.get("Groups", []), groups), "status": interface.get("Status") or "-"})
        return [self._sheet("EC2 List", [("name","Name"),("instanceId","Instance ID"),("state","State"),("instanceType","Instance Type"),("privateIp","Private IP"),("publicIp","Public IP"),("os","OS"),("osType","OS Type"),("description","Description"),("project","Project"),("environment","Environment"),("purpose","Purpose"),("region","Region"),("availabilityZone","Availability Zone"),("vpcId","VPC ID"),("subnetId","Subnet ID"),("securityGroups","Security Groups"),("launchTime","Launch Time")], instances),
                self._sheet("Network Interfaces", [("name","EC2 Name"),("instanceId","Instance ID"),("eniId","ENI ID"),("deviceIndex","Device Index"),("vpcId","VPC ID"),("subnetId","Subnet ID"),("primaryPrivateIp","Primary Private IP"),("privateIps","All Private IPs"),("publicIp","Public IP"),("securityGroups","Security Groups"),("status","Interface Status")], interfaces)]

    def _sg_sheets(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        service = AwsAssetService(self.root); groups = {str(item.get("GroupId")): item for item in data.get("security_groups", [])}; mappings = service._instance_group_map(data)
        rules_by_group: dict[str, list[dict[str, Any]]] = {}
        for raw in data.get("security_group_rules", []): rules_by_group.setdefault(str(raw.get("GroupId")), []).append(service._rule(raw, groups))
        summary, inbound, outbound, mapping_rows = [], [], [], []
        for group_id, group in groups.items():
            links = list(mappings.get(group_id, {}).values()); rules = rules_by_group.get(group_id, [])
            summary.append({"name": group.get("GroupName") or "-", "groupId": group_id, "description": group.get("Description") or "-", "vpcId": group.get("VpcId") or "-",
                "inbound": sum(not item["isEgress"] for item in rules), "outbound": sum(item["isEgress"] for item in rules), "instances": len(links),
                "instanceList": "\n".join(f"{_tags(link['instance']).get('Name') or '-'} ({link['instance'].get('InstanceId') or '-'})" for link in links) or "-"})
            for rule in rules:
                row = {"name": group.get("GroupName") or "-", "groupId": group_id, **rule}
                (outbound if rule["isEgress"] else inbound).append(row)
            for link in links:
                instance = link["instance"]
                mapping_rows.append({"name": group.get("GroupName") or "-", "groupId": group_id, "ec2Name": _tags(instance).get("Name") or "-", "instanceId": instance.get("InstanceId") or "-",
                    "state": (instance.get("State") or {}).get("Name") or "-", "privateIp": instance.get("PrivateIpAddress") or "-", "publicIp": instance.get("PublicIpAddress") or "-",
                    "eniId": "\n".join(link["eniIds"]) or "-", "vpcId": instance.get("VpcId") or "-", "subnetId": instance.get("SubnetId") or "-"})
        inbound_columns = [("name","SG Name"),("groupId","SG ID"),("ruleId","Rule ID"),("protocol","Protocol"),("fromPort","From Port"),("toPort","To Port"),("sourceType","Source Type"),("cidr","Source CIDR"),("referencedGroupId","Referenced SG ID"),("referencedGroupName","Referenced SG Name"),("prefixListId","Prefix List ID"),("description","Description")]
        outbound_columns = [(key, "Destination Type" if key == "sourceType" else "Destination CIDR" if key == "cidr" else label) for key, label in inbound_columns]
        return [self._sheet("SG Summary", [("name","SG Name"),("groupId","SG ID"),("description","Description"),("vpcId","VPC ID"),("inbound","Inbound Rules"),("outbound","Outbound Rules"),("instances","Applied EC2 Count"),("instanceList","Applied EC2 List")], summary),
                self._sheet("Inbound Rules", inbound_columns, inbound), self._sheet("Outbound Rules", outbound_columns, outbound),
                self._sheet("EC2 Mapping", [("name","SG Name"),("groupId","SG ID"),("ec2Name","EC2 Name"),("instanceId","Instance ID"),("state","State"),("privateIp","Private IP"),("publicIp","Public IP"),("eniId","ENI ID"),("vpcId","VPC ID"),("subnetId","Subnet ID")], mapping_rows)]

    def build(self, kind: str, progress=lambda _message: None) -> dict[str, Any]:
        if kind not in {"aws_ec2", "aws_sg"}: raise ValueError("Unknown AWS export type")
        data = self._load(); progress("AWS Raw Cache 전체 데이터 준비 중")
        sheets = self._ec2_sheets(data) if kind == "aws_ec2" else self._sg_sheets(data)
        directory = self.root / "exports"; directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{kind}_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.xlsx"
        names = write_xlsx_workbook(path, sheets); progress(f"AWS XLSX 생성 완료 · {len(names)} sheets")
        return {"filename": path.name, "path": str(path), "sheets": names, "rows": sum(len(sheet["rows"]) for sheet in sheets)}
