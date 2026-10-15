from __future__ import annotations

import json
from decimal import Decimal
from datetime import datetime
from pathlib import Path
from typing import Any

from backend.services.aws_assets import AwsAssetService
from backend.services.endpoints import load_json_list
from backend.services.spreadsheet import LEDGER_STYLES, write_xlsx_workbook


EC2_COLUMNS = list(zip(
    ["no", "type", "tier", "project", "hostname", "name", "purpose", "instanceId", "instanceType", "cpu", "memory", "ebs", "os", "osType", "kernel", "osEos", "was", "web", "db", "dbPlatform", "dbEos", "eip", "eipRequired", "privateIp", "installedAt", "state", "antivirus", "antivirusVersion"],
    ["NO", "Type", "티어", "종류", "Hostname", "Name", "용도", "Instance ID", "Instance", "vCPU(core)", "MEM", "EBS", "OS", "Platform", "Kernel", "OS EOS", "WAS", "WEB", "DB", "DB Platform", "DB EOS", "EIP", "EIP 필수 여부", "IP", "설치일", "Status", "Anti Virus", "Anti Virus Version"],
))
MAPPING_COLUMNS = list(zip(
    ["no", "ec2Name", "hostname", "instanceId", "state", "privateIp", "publicIp", "name", "groupId", "direction", "protocol", "fromPort", "toPort", "sourceType", "source", "destinationType", "destination", "description", "eniId", "vpcId", "subnetId"],
    ["NO", "EC2 Name", "Hostname", "Instance ID", "State", "Private IP", "Public IP", "SG Name", "SG ID", "Direction", "Protocol", "From Port", "To Port", "Source Type", "Source", "Destination Type", "Destination", "Rule Description", "ENI ID", "VPC ID", "Subnet ID"],
))
STATE_STYLES = {"Running": LEDGER_STYLES["running"], "Stop": LEDGER_STYLES["stop"]}
DIRECTION_STYLES = {"Inbound": LEDGER_STYLES["inbound"], "Outbound": LEDGER_STYLES["outbound"]}


def _state(instance: dict[str, Any]) -> str:
    state = str((instance.get("State") or {}).get("Name") or "-")
    return {"running": "Running", "stopped": "Stop"}.get(state, state.capitalize())


def _hostname(value: Any) -> str:
    return str(value or "").strip().rstrip(".").casefold()


class SophosMatcher:
    """One cache-only exact matcher shared by EC2 inventory and policy exports."""
    def __init__(self, root: Path):
        self.by_ip: dict[str, dict[str, Any]] = {}
        self.by_hostname: dict[str, dict[str, Any]] = {}
        endpoints = load_json_list(root / "cache/endpoints.json")
        for endpoint in sorted(endpoints, key=lambda item: (_hostname(item.get("hostname")), str(item.get("id") or ""))):
            for ip in endpoint.get("ipv4Addresses", []):
                if ip: self.by_ip.setdefault(str(ip), endpoint)
            name = _hostname(endpoint.get("hostname"))
            if name: self.by_hostname.setdefault(name, endpoint)

    def match(self, instance: dict[str, Any]) -> dict[str, Any] | None:
        ips = [instance.get("PrivateIpAddress")]
        for interface in instance.get("NetworkInterfaces", []):
            ips.append(interface.get("PrivateIpAddress"))
            ips.extend(item.get("PrivateIpAddress") for item in interface.get("PrivateIpAddresses", []))
        for ip in ips:
            if ip and str(ip) in self.by_ip: return self.by_ip[str(ip)]
        # AWS DNS/hostname fields only; a Name tag is never a hostname.
        for key in ("PrivateDnsName", "Hostname"):
            name = _hostname(instance.get(key))
            if name and name in self.by_hostname: return self.by_hostname[name]
        return None


def core_agent_version(endpoint):
    from backend.services.ssm_inventory import normalized
    for module in (endpoint or {}).get("modules", []) or []:
        if isinstance(module, dict) and module.get("name") == "coreAgent" and normalized(module.get("version")):
            return normalized(module["version"])
    for product in (endpoint or {}).get("assignedProducts", []) or []:
        if isinstance(product, dict) and product.get("code") == "coreAgent" and product.get("status") == "installed" and normalized(product.get("version")):
            return normalized(product["version"])
    return "-"


def ssm_excel_values(record):
    from backend.services.ssm_inventory import normalized
    if not isinstance(record, dict): return {}
    def product_cell(category, *, require_version=False, name_only=False):
        values = []
        for product in record.get(category, []) or []:
            if not isinstance(product, dict): continue
            name, version = normalized(product.get("product")), normalized(product.get("version"))
            if name:
                values.append("-" if require_version and not version else name if name_only or not version else f"{name} {version}")
        return "; ".join(values) or "-"
    # Failed first attempts carry platform discovery, but never fabricated inventory.
    values = {"os": record["platform_type"]} if record.get("platform_type") in {"Linux", "Windows"} else {}
    if record.get("last_success_at") and record.get("status") in {"success", "stale"}:
        values.update({"hostname": normalized(record.get("hostname")) or "-", "osType": normalized(record.get("os")) or "-",
                       "kernel": normalized(record.get("kernel")) or "-", "installedAt": normalized(record.get("os_install_date")) or "-",
                       "was": product_cell("was"), "web": product_cell("web"), "db": product_cell("db", name_only=True),
                       "dbPlatform": product_cell("db", require_version=True)})
    return values


class InventoryResources:
    def __init__(self, data: dict[str, Any]):
        self.types = {item.get("InstanceType"): item for item in data.get("instance_types", [])}
        self.has_volumes = "volumes" in data
        self.volumes: dict[str, dict[str, int]] = {}
        for number, volume in enumerate(data.get("volumes", [])):
            if not isinstance(volume.get("Size"), (int, float)): continue
            for attachment in volume.get("Attachments", []):
                if attachment.get("InstanceId") and attachment.get("State") != "detached":
                    self.volumes.setdefault(str(attachment["InstanceId"]), {})[str(volume.get("VolumeId") or number)] = volume["Size"]
        self.addresses = data.get("addresses", [])

    def values(self, instance: dict[str, Any]) -> dict[str, str]:
        spec = self.types.get(instance.get("InstanceType"), {})
        cpu = spec.get("VCpuInfo") or {}
        memory = (spec.get("MemoryInfo") or {}).get("SizeInMiB")
        eni_ids = {item.get("NetworkInterfaceId") for item in instance.get("NetworkInterfaces", []) if item.get("NetworkInterfaceId")}
        instance_id = instance.get("InstanceId")
        eips = sorted({str(item["PublicIp"]) for item in self.addresses if item.get("PublicIp") and
            ((instance_id and item.get("InstanceId") == instance_id) or item.get("NetworkInterfaceId") in eni_ids)})
        size = Decimal(str(memory)) / 1024 if memory is not None else None
        return {"cpu": f"{cpu['DefaultVCpus']}({cpu['DefaultCores']})" if cpu.get("DefaultVCpus") is not None and cpu.get("DefaultCores") is not None else "-",
                "memory": f"{format(size.normalize(), 'f')} GiB" if size is not None else "-",
                "ebs": f"{sum(self.volumes.get(str(instance_id), {}).values()):g} GB" if self.has_volumes else "-",
                "eip": "\n".join(eips) or "-"}


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
        matcher, resources = SophosMatcher(self.root), InventoryResources(data)
        instances, interfaces = [], []
        for number, instance in enumerate(data.get("instances", []), 1):
            tags = _tags(instance); instance_id = str(instance.get("InstanceId") or "-"); name = tags.get("Name") or "-"
            fallback_endpoint = matcher.match(instance)
            # Antivirus identity is restricted to the primary EC2 private address.
            endpoint = matcher.by_ip.get(str(instance.get("PrivateIpAddress") or ""))
            row = {key: "-" for key, _label in EC2_COLUMNS}
            row.update({"no": number, "type": "EC2", "tier": {"PRD": "PROD", "DEV": "DEV"}.get(tags.get("Environment"), tags.get("Environment") or "-"),
                "project": tags.get("Project") or "-", "hostname": (fallback_endpoint or {}).get("hostname") or "-", "name": name,
                "purpose": tags.get("Purpose") or tags.get("Description") or "-", "instanceId": instance_id,
                "instanceType": instance.get("InstanceType") or "-", "os": tags.get("OS") or "-", "osType": tags.get("OS_type") or "-",
                "privateIp": instance.get("PrivateIpAddress") or "-", "state": _state(instance), "antivirus": "Sophos" if endpoint is not None else "미설치",
                "antivirusVersion": core_agent_version(endpoint), **resources.values(instance)})
            ssm_values = ssm_excel_values((data.get("ssm_inventory") or {}).get("instances", {}).get(instance_id))
            if ssm_values.get("hostname") == "-": ssm_values.pop("hostname")
            row.update(ssm_values)
            instances.append(row)
            for interface in instance.get("NetworkInterfaces", []):
                private_ips = [str(item.get("PrivateIpAddress")) for item in interface.get("PrivateIpAddresses", []) if item.get("PrivateIpAddress")]
                public_ips = [str((item.get("Association") or {}).get("PublicIp")) for item in interface.get("PrivateIpAddresses", []) if (item.get("Association") or {}).get("PublicIp")]
                interfaces.append({"name": name, "instanceId": instance_id, "eniId": interface.get("NetworkInterfaceId") or "-", "deviceIndex": (interface.get("Attachment") or {}).get("DeviceIndex", "-"),
                    "vpcId": interface.get("VpcId") or instance.get("VpcId") or "-", "subnetId": interface.get("SubnetId") or instance.get("SubnetId") or "-",
                    "primaryPrivateIp": interface.get("PrivateIpAddress") or "-", "privateIps": "\n".join(private_ips) or "-", "publicIp": "\n".join(public_ips) or "-",
                    "securityGroups": _names(interface.get("Groups", []), groups), "status": interface.get("Status") or "-"})
        inventory = self._sheet("EC2 List", EC2_COLUMNS, instances)
        inventory.update({"tableStyle": "ledger", "cellStyles": {"state": STATE_STYLES, "antivirus": {"Sophos": LEDGER_STYLES["sophos"], "미설치": LEDGER_STYLES["stop"]}}})
        return [inventory,
                self._sheet("Network Interfaces", [("name","EC2 Name"),("instanceId","Instance ID"),("eniId","ENI ID"),("deviceIndex","Device Index"),("vpcId","VPC ID"),("subnetId","Subnet ID"),("primaryPrivateIp","Primary Private IP"),("privateIps","All Private IPs"),("publicIp","Public IP"),("securityGroups","Security Groups"),("status","Interface Status")], interfaces)]

    def _sg_sheets(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        service = AwsAssetService(self.root); groups = {str(item.get("GroupId")): item for item in data.get("security_groups", [])}; mappings = service._instance_group_map(data)
        rules_by_group: dict[str, list[dict[str, Any]]] = {}
        for raw in data.get("security_group_rules", []): rules_by_group.setdefault(str(raw.get("GroupId")), []).append(service._rule(raw, groups))
        summary, inbound, outbound = [], [], []
        for group_id, group in groups.items():
            links = list(mappings.get(group_id, {}).values()); rules = rules_by_group.get(group_id, [])
            summary.append({"name": group.get("GroupName") or "-", "groupId": group_id, "description": group.get("Description") or "-", "vpcId": group.get("VpcId") or "-",
                "inbound": sum(not item["isEgress"] for item in rules), "outbound": sum(item["isEgress"] for item in rules), "instances": len(links),
                "instanceList": "\n".join(f"{_tags(link['instance']).get('Name') or '-'} ({link['instance'].get('InstanceId') or '-'})" for link in links) or "-"})
            for rule in rules:
                row = {"name": group.get("GroupName") or "-", "groupId": group_id, **rule}
                (outbound if rule["isEgress"] else inbound).append(row)
        inbound_columns = [("name","SG Name"),("groupId","SG ID"),("ruleId","Rule ID"),("protocol","Protocol"),("fromPort","From Port"),("toPort","To Port"),("sourceType","Source Type"),("cidr","Source CIDR"),("referencedGroupId","Referenced SG ID"),("referencedGroupName","Referenced SG Name"),("prefixListId","Prefix List ID"),("description","Description")]
        outbound_columns = [(key, "Destination Type" if key == "sourceType" else "Destination CIDR" if key == "cidr" else label) for key, label in inbound_columns]
        mapping_rows = self._policy_rows(data, groups, rules_by_group)
        sheets = [self._sheet("SG Summary", [("name","SG Name"),("groupId","SG ID"),("description","Description"),("vpcId","VPC ID"),("inbound","Inbound Rules"),("outbound","Outbound Rules"),("instances","Applied EC2 Count"),("instanceList","Applied EC2 List")], summary),
                self._sheet("Inbound Rules", inbound_columns, inbound), self._sheet("Outbound Rules", outbound_columns, outbound),
                self._sheet("EC2 Mapping", MAPPING_COLUMNS, mapping_rows)]
        for sheet in sheets: sheet["tableStyle"] = "ledger"
        # Keep rule sheet columns/data unchanged; tint the policy identifier.
        for sheet, rows, style in [(sheets[1], inbound, LEDGER_STYLES["inbound"]), (sheets[2], outbound, LEDGER_STYLES["outbound"])]:
            sheet["cellStyles"] = {"ruleId": {row["ruleId"]: style for row in rows}}
        sheets[3].update({"cellStyles": {"state": STATE_STYLES, "direction": DIRECTION_STYLES},
                          "mergeColumns": [key for key, _label in MAPPING_COLUMNS[:7]], "groupKey": "no"})
        return sheets

    def _policy_rows(self, data: dict[str, Any], groups: dict[str, dict[str, Any]],
                     rules_by_group: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
        matcher = SophosMatcher(self.root)
        instances = sorted(data.get("instances", []), key=lambda item: ((_tags(item).get("Name") or "-").casefold(), str(item.get("InstanceId") or "-")))
        output = []
        for number, instance in enumerate(instances, 1):
            endpoint = matcher.match(instance)
            common = {"no": number, "ec2Name": _tags(instance).get("Name") or "-", "hostname": (endpoint or {}).get("hostname") or "-",
                      "instanceId": instance.get("InstanceId") or "-", "state": _state(instance),
                      "privateIp": instance.get("PrivateIpAddress") or "-", "publicIp": instance.get("PublicIpAddress") or "-"}
            rows = []
            # Each ENI attachment is an application of a rule. Do not flatten
            # distinct ENI/VPC/subnet relationships or follow referenced SGs.
            for interface in instance.get("NetworkInterfaces", []):
                group_ids = dict.fromkeys(str(group["GroupId"]) for group in interface.get("Groups", []) if group.get("GroupId"))
                for group_id in group_ids:
                    for rule in rules_by_group.get(group_id, []):
                        outbound = rule["isEgress"]
                        target = rule["referencedGroupId"] if rule["referencedGroupId"] != "-" else rule["prefixListId"] if rule["prefixListId"] != "-" else rule["cidr"]
                        target_type = "Security Group" if rule["sourceType"] == "Referenced SG" else rule["sourceType"]
                        start, end = rule["fromPort"], rule["toPort"]
                        if rule["protocol"] == "ALL": start = end = "ALL"
                        elif rule["protocol"] in {"ICMP", "ICMPv6"}:
                            start, end = f"Type {start}", f"Code {end}"
                        rows.append({**common, "name": groups.get(group_id, {}).get("GroupName") or "-", "groupId": group_id,
                            "direction": "Outbound" if outbound else "Inbound", "protocol": rule["protocol"], "fromPort": start, "toPort": end,
                            "sourceType": "-" if outbound else target_type, "source": "-" if outbound else target,
                            "destinationType": target_type if outbound else "-", "destination": target if outbound else "-", "description": rule["description"],
                            "eniId": interface.get("NetworkInterfaceId") or "-", "vpcId": interface.get("VpcId") or instance.get("VpcId") or "-",
                            "subnetId": interface.get("SubnetId") or instance.get("SubnetId") or "-"})
            if not rows:
                rows.append({**{key: "-" for key, _label in MAPPING_COLUMNS}, **common})
            def port_order(value):
                text = str(value).removeprefix("Type ").removeprefix("Code ")
                return (0, int(text)) if text.lstrip("-").isdigit() else (1, text)
            rows.sort(key=lambda row: (row["direction"] == "Outbound", str(row["name"]).casefold(), row["protocol"],
                port_order(row["fromPort"]), port_order(row["toPort"]), row["groupId"], row["eniId"]))
            output.extend(rows)
        return output

    def build(self, kind: str, progress=lambda _message: None) -> dict[str, Any]:
        if kind not in {"aws_ec2", "aws_sg"}: raise ValueError("Unknown AWS export type")
        data = self._load(); progress("AWS Raw Cache 전체 데이터 준비 중")
        sheets = self._ec2_sheets(data) if kind == "aws_ec2" else self._sg_sheets(data)
        directory = self.root / "exports"; directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{kind}_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.xlsx"
        names = write_xlsx_workbook(path, sheets); progress(f"AWS XLSX 생성 완료 · {len(names)} sheets")
        return {"filename": path.name, "path": str(path), "sheets": names, "rows": sum(len(sheet["rows"]) for sheet in sheets)}
