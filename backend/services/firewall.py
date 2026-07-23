import ipaddress
import re
import ssl
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from html import escape
from pathlib import Path
from typing import Any


FIREWALL_DEFINITIONS = {
    "Cloud": "",
    "Seoul": "SEOUL_",
    "Icheon": "ICHEON_",
    "Anseong": "ANSEONG_",
}
DOMAIN_PATTERN = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")


def load_values(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def parse_status(xml_text: str) -> dict[str, str]:
    try:
        status = ET.fromstring(xml_text).find(".//Status")
        return {"code": str(status.attrib.get("code", "")), "message": str(status.text or "").strip()} if status is not None else {"code": "", "message": xml_text}
    except ET.ParseError:
        code = re.search(r'code="([^"]+)"', xml_text)
        message = re.search(r"<Status[^>]*>(.*?)</Status>", xml_text, re.DOTALL)
        return {"code": code.group(1) if code else "", "message": message.group(1).strip() if message else xml_text}


class FirewallClient:
    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.name = str(config["name"])
        self.url = f"https://{config['host']}:{config['port']}/webconsole/APIController"

    def _post_xml(self, request_xml: str) -> str:
        boundary = f"----smu-{uuid.uuid4().hex}"
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"reqxml\"\r\n\r\n{request_xml}\r\n--{boundary}--\r\n").encode("utf-8")
        request = urllib.request.Request(self.url, data=body, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}, method="POST")
        context = None if self.config["verify_ssl"] else ssl._create_unverified_context()
        with urllib.request.urlopen(request, timeout=60, context=context) as response:
            return response.read().decode("utf-8", errors="replace")

    def login_xml(self) -> str:
        return f"<Login><Username>{escape(self.config['username'])}</Username><Password>{escape(self.config['password'])}</Password></Login>"

    def create(self, mode: str, target: str) -> dict[str, Any]:
        object_name = f"AIDR_{target}"
        if mode == "DOMAIN":
            group = f"<FQDNHostGroupList><FQDNHostGroup>{escape(self.config['fqdnhost_group'])}</FQDNHostGroup></FQDNHostGroupList>" if self.config["fqdnhost_group"] else ""
            object_xml = f"<FQDNHost><Name>{escape(object_name)}</Name><FQDN>{escape(target)}</FQDN>{group}</FQDNHost>"
        else:
            group = f"<HostGroupList><HostGroup>{escape(self.config['iphost_group'])}</HostGroup></HostGroupList>" if self.config["iphost_group"] else ""
            description = f"<Description>{escape(self.config['description'])}</Description>" if self.config["description"] else ""
            object_xml = f"<IPHost><Name>{escape(object_name)}</Name><IPFamily>IPv4</IPFamily>{description}<HostType>IP</HostType><IPAddress>{escape(target)}</IPAddress>{group}</IPHost>"
        raw = self._post_xml(f"<Request>{self.login_xml()}<Set operation=\"add\">{object_xml}</Set></Request>")
        parsed = parse_status(raw)
        result = "SUCCESS" if parsed["code"] == "200" else "EXISTS" if parsed["code"] in {"502", "503"} else "FAIL"
        return {"firewall": self.name, "target": target, "name": object_name, "result": result, "statusCode": parsed["code"], "message": parsed["message"], "error": "", "raw": raw}

    def group(self, mode: str) -> dict[str, Any]:
        tag = "FQDNHostGroup" if mode == "DOMAIN" else "IPHostGroup"
        group_name = self.config["fqdnhost_group"] if mode == "DOMAIN" else self.config["iphost_group"]
        raw = self._post_xml(f"<Request>{self.login_xml()}<Get><{tag}><Filter><key name=\"Name\" criteria=\"=\">{escape(group_name)}</key></Filter></{tag}></Get></Request>")
        parsed = parse_status(raw)
        members = []
        try:
            root = ET.fromstring(raw)
            group_node = root.find(f".//{tag}")
            if group_node is not None:
                group_name_value = (group_node.findtext(".//Name") or "").strip()
                for node in group_node.iter():
                    value = str(node.text or "").strip()
                    if value and value != group_name_value and node.tag.split("}")[-1] in {"IPHost", "FQDNHost", "Host", "Member", "HostName", "Name"} and value not in members:
                        members.append(value)
        except ET.ParseError:
            pass
        return {"firewall": self.name, "mode": mode, "group": group_name, "members": members, "statusCode": parsed["code"], "message": parsed["message"], "raw": raw}


class FirewallService:
    def __init__(self, project_root: Path):
        self.env_path = project_root / "env/Firewall_env.txt"

    def configurations(self) -> list[dict[str, Any]]:
        values = load_values(self.env_path)
        output = []
        for name, prefix in FIREWALL_DEFINITIONS.items():
            stem = f"FW_{prefix}"
            config = {
                "name": name, "host": values.get(f"{stem}HOST", ""), "port": values.get(f"{stem}PORT", ""),
                "username": values.get(f"{stem}USERNAME", ""), "password": values.get(f"{stem}PASSWORD", ""),
                "verify_ssl": values.get(f"{stem}VERIFY_SSL", "false").lower() == "true",
                "description": values.get("FW_IPHOST_DESCRIPTION", ""), "iphost_group": values.get("FW_IPHOST_GROUP", ""),
                "fqdnhost_group": values.get("FW_FQDNHOST_GROUP", ""),
            }
            config["configured"] = all(config[key] for key in ("host", "port", "username", "password"))
            output.append(config)
        return output

    def public_configurations(self) -> list[dict[str, Any]]:
        return [{"name": config["name"], "configured": config["configured"]} for config in self.configurations()]

    @staticmethod
    def targets(mode: str, raw_targets: list[Any]) -> list[str]:
        unique = list(dict.fromkeys(str(target).strip() for target in raw_targets if str(target).strip()))
        invalid = []
        for target in unique:
            try:
                valid = DOMAIN_PATTERN.fullmatch(target) is not None if mode == "DOMAIN" else ipaddress.ip_address(target).version == 4
            except ValueError:
                valid = False
            if not valid:
                invalid.append(target)
        if invalid:
            raise ValueError(f"Invalid {mode} targets: {', '.join(invalid)}")
        if not unique:
            raise ValueError("At least one target is required")
        return unique

    def selected(self, names: list[Any], mode: str) -> list[dict[str, Any]]:
        if mode not in {"IP", "DOMAIN"}:
            raise ValueError("mode must be IP or DOMAIN")
        selected_names = {str(name) for name in names}
        configs = [config for config in self.configurations() if config["name"] in selected_names]
        if not configs or any(not config["configured"] for config in configs):
            raise ValueError("Selected firewall configuration is missing in env/Firewall_env.txt")
        required_group = "fqdnhost_group" if mode == "DOMAIN" else "iphost_group"
        if any(not config[required_group] for config in configs):
            raise ValueError(f"{required_group} is required")
        return configs

    def execute(self, mode: str, raw_targets: list[Any], firewall_names: list[Any], progress=lambda _message: None) -> dict[str, Any]:
        mode = str(mode).upper()
        if mode not in {"IP", "DOMAIN"}:
            raise ValueError("mode must be IP or DOMAIN")
        targets = self.targets(mode, raw_targets)
        configs = self.selected(firewall_names, mode)
        results = []
        for config in configs:
            client = FirewallClient(config)
            for target in targets:
                progress(f"{config['name']} {target} 처리 중")
                try:
                    results.append(client.create(mode, target))
                except Exception as exc:
                    results.append({"firewall": config["name"], "target": target, "name": f"AIDR_{target}", "result": "FAIL", "statusCode": "", "message": "", "error": f"{type(exc).__name__}: {exc}", "raw": ""})
        return {"results": results, "counts": {name: sum(row["result"] == name for row in results) for name in ("SUCCESS", "EXISTS", "FAIL")}}

    def groups(self, mode: str, firewall_names: list[Any], progress=lambda _message: None) -> dict[str, Any]:
        mode = str(mode).upper()
        configs = self.selected(firewall_names, mode)
        groups = []
        for config in configs:
            progress(f"{config['name']} 그룹 조회 중")
            try:
                groups.append(FirewallClient(config).group(mode))
            except Exception as exc:
                groups.append({"firewall": config["name"], "mode": mode, "group": "", "members": [], "statusCode": "", "message": "", "error": f"{type(exc).__name__}: {exc}", "raw": ""})
        return {"groups": groups}
