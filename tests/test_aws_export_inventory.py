import copy
import json
import re
import threading
import time
from pathlib import Path
from xml.etree import ElementTree as ET
from zipfile import ZipFile

import pytest

from backend.services.aws_export import AwsExportService, SophosMatcher
from backend.services.spreadsheet import MAIN_NS, write_xlsx_workbook

NS = {"m": MAIN_NS}
EC2_HEADERS = ["NO", "Type", "티어", "종류", "Hostname", "Name", "용도", "Instance ID", "Instance", "vCPU(core)", "MEM", "EBS", "OS", "Platform", "Kernel", "OS EOS", "WAS", "WEB", "DB", "DB Platform", "DB EOS", "EIP", "EIP 필수 여부", "IP", "설치일", "Status", "anti virus"]
POLICY_HEADERS = ["NO", "EC2 Name", "Hostname", "Instance ID", "State", "Private IP", "Public IP", "SG Name", "SG ID", "Direction", "Protocol", "From Port", "To Port", "Source Type", "Source", "Destination Type", "Destination", "Rule Description", "ENI ID", "VPC ID", "Subnet ID"]


def inventory_payload():
    def tags(**values): return [{"Key": key, "Value": value} for key, value in values.items()]
    def eni(identifier, subnet, groups):
        return {"NetworkInterfaceId": identifier, "VpcId": "vpc-1", "SubnetId": subnet,
                "Groups": [{"GroupId": group} for group in groups], "PrivateIpAddress": "10.0.0.1",
                "PrivateIpAddresses": [{"PrivateIpAddress": "10.0.0.1", "Association": {"PublicIp": "203.0.113.1"}}, {"PrivateIpAddress": "10.0.0.11"}],
                "Attachment": {"DeviceIndex": 0}, "Status": "in-use"}
    return {
        "instances": [
            {"InstanceId": "i-1", "InstanceType": "m5.large", "PrivateIpAddress": "10.0.0.1", "PublicIpAddress": "203.0.113.1",
             "PrivateDnsName": "other-host", "State": {"Name": "running"}, "LaunchTime": "2026-01-01T00:00:00Z",
             "Tags": tags(Name="A", Environment="PRD", Project="Security", Purpose="API", Description="fallback", OS="Linux", OS_type="Ubuntu", Kernel="guessed", WAS="guessed", DB="guessed"),
             "SecurityGroups": [{"GroupId": "sg-reference"}], "NetworkInterfaces": [eni("eni-a", "subnet-a", ["sg-a", "sg-b"]) ]},
            {"InstanceId": "i-2", "InstanceType": "unknown", "PrivateIpAddress": "10.0.0.2", "PublicIpAddress": "203.0.113.2", "State": {"Name": "stopped"},
             "Tags": tags(Name="host-from-sophos", Environment="DEV", Description="Batch"), "NetworkInterfaces": []},
            {"InstanceId": "i-3", "State": {"Name": "pending"}, "Tags": tags(Name="Z", Environment="QA"), "NetworkInterfaces": []},
        ],
        "instance_types": [{"InstanceType": "m5.large", "VCpuInfo": {"DefaultVCpus": 4, "DefaultCores": 2}, "MemoryInfo": {"SizeInMiB": 8192}}],
        "volumes": [
            {"VolumeId": "vol-root", "Size": 20, "VolumeType": "gp3", "Attachments": [{"InstanceId": "i-1", "State": "attached"}]},
            {"VolumeId": "vol-data", "Size": 100, "VolumeType": "gp3", "Attachments": [{"InstanceId": "i-1", "State": "attached"}]},
            {"VolumeId": "vol-other", "Size": 200, "Attachments": [{"InstanceId": "i-other"}]},
            {"VolumeId": "vol-detached", "Size": 300, "Attachments": [{"InstanceId": "i-1", "State": "detached"}]},
        ],
        "addresses": [
            {"InstanceId": "i-1", "PublicIp": "198.51.100.1"},
            {"NetworkInterfaceId": "eni-a", "PrivateIpAddress": "10.0.0.11", "PublicIp": "198.51.100.2"},
            {"PublicIp": "198.51.100.3"},
        ],
        "security_groups": [{"GroupId": "sg-a", "GroupName": "Application", "VpcId": "vpc-1", "Description": "app"},
                            {"GroupId": "sg-b", "GroupName": "Database", "VpcId": "vpc-1"},
                            {"GroupId": "sg-reference", "GroupName": "Referenced", "VpcId": "vpc-1"}],
        "security_group_rules": [
            {"GroupId": "sg-a", "SecurityGroupRuleId": "in-443", "IsEgress": False, "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "CidrIpv4": "0.0.0.0/0", "Description": "HTTPS"},
            {"GroupId": "sg-a", "SecurityGroupRuleId": "in-22", "IsEgress": False, "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIpv4": "101.1.0.0/22"},
            {"GroupId": "sg-a", "SecurityGroupRuleId": "out-all", "IsEgress": True, "IpProtocol": "-1", "CidrIpv4": "0.0.0.0/0"},
            {"GroupId": "sg-b", "SecurityGroupRuleId": "in-icmp", "IsEgress": False, "IpProtocol": "icmp", "FromPort": 8, "ToPort": 0, "CidrIpv4": "10.0.0.0/8"},
            # A referenced SG is not an attachment and must not add its rules.
            {"GroupId": "sg-reference", "SecurityGroupRuleId": "not-applied", "IsEgress": False, "IpProtocol": "tcp", "FromPort": 9999, "ToPort": 9999, "CidrIpv4": "0.0.0.0/0"},
        ],
    }


def prepare(root: Path, data=None):
    data = inventory_payload() if data is None else data
    (root / "cache").mkdir(parents=True, exist_ok=True)
    (root / "cache/aws.json").write_text(json.dumps(data), encoding="utf-8")
    (root / "cache/endpoints.json").write_text(json.dumps([
        {"id": "sophos-1", "hostname": "host-from-sophos", "ipv4Addresses": ["10.0.0.1"]},
        {"id": "sophos-2", "hostname": "other-host", "ipv4Addresses": ["10.0.0.99"]},
    ]), encoding="utf-8")
    return AwsExportService(root), data


def cells(sheet): return {cell.attrib["r"]: cell for cell in sheet.findall("m:sheetData/m:row/m:c", NS)}


def text(cell): return cell.findtext("m:is/m:t", default="", namespaces=NS)


def style_info(styles, cell):
    xf = styles.find("m:cellXfs", NS)[int(cell.attrib["s"])]
    fill = styles.find("m:fills", NS)[int(xf.attrib["fillId"])]
    font = styles.find("m:fonts", NS)[int(xf.attrib["fontId"])]
    return (fill.find("m:patternFill/m:fgColor", NS).attrib["rgb"], font.find("m:color", NS).attrib["rgb"],
            font.find("m:b", NS) is not None, xf, styles.find("m:borders", NS)[int(xf.attrib["borderId"])])


def column_index(ref):
    index = 0
    for letter in re.match(r"[A-Z]+", ref).group(): index = index * 26 + ord(letter) - 64
    return index


def validate_xlsx(path):
    with ZipFile(path) as archive:
        assert archive.testzip() is None
        # Validate every XML part, including workbook and relationship files.
        for name in archive.namelist():
            if name.endswith((".xml", ".rels")): ET.fromstring(archive.read(name))
        for name in archive.namelist():
            if not name.startswith("xl/worksheets/"): continue
            sheet = ET.fromstring(archive.read(name))
            rows = sheet.findall("m:sheetData/m:row", NS)
            row_numbers = [int(row.attrib["r"]) for row in rows]
            assert row_numbers == sorted(set(row_numbers))
            refs = cells(sheet)
            for row in rows:
                positions = [column_index(cell.attrib["r"]) for cell in row]
                assert positions == sorted(set(positions))
                assert all(int(re.search(r"\d+$", cell.attrib["r"]).group()) == int(row.attrib["r"]) for cell in row)
            ranges = sheet.findall("m:mergeCells/m:mergeCell", NS)
            assert len(ranges) == len({item.attrib["ref"] for item in ranges})
            occupied = set()
            for merge in ranges:
                start, end = merge.attrib["ref"].split(":")
                assert start in refs and text(refs[start])
                first, last = (int(re.search(r"\d+$", ref).group()) for ref in (start, end))
                left, right = column_index(start), column_index(end)
                assert 2 <= first < last <= max(row_numbers) and left == right <= 7
                region = {(row, col) for row in range(first, last+1) for col in range(left, right+1)}
                assert occupied.isdisjoint(region)
                occupied.update(region)
                for ref, cell in refs.items():
                    pos = (int(re.search(r"\d+$", ref).group()), column_index(ref))
                    if pos in region and ref != start: assert text(cell) == ""
            if ranges: assert int(sheet.find("m:mergeCells", NS).attrib["count"]) == len(ranges)


def test_inventory_sources_and_no_inferred_values(tmp_path):
    exporter, data = prepare(tmp_path)
    spec, _interfaces = exporter._ec2_sheets(data)
    assert list(spec["headers"].values()) == EC2_HEADERS
    first, second, third = spec["rows"]
    assert {key: first[key] for key in ["no", "type", "tier", "project", "hostname", "name", "purpose", "instanceId", "instanceType", "cpu", "memory", "ebs", "os", "osType", "privateIp", "state", "antivirus"]} == {
        "no": 1, "type": "EC2", "tier": "PROD", "project": "Security", "hostname": "host-from-sophos", "name": "A", "purpose": "API", "instanceId": "i-1", "instanceType": "m5.large", "cpu": "4(2)", "memory": "8 GiB", "ebs": "120 GB", "os": "Linux", "osType": "Ubuntu", "privateIp": "10.0.0.1", "state": "Running", "antivirus": "Sophos"}
    assert first["eip"].splitlines() == ["198.51.100.1", "198.51.100.2"]
    assert second["eip"] == "-"  # PublicIpAddress is not proof of an EIP.
    assert second["hostname"] == "-" and second["antivirus"] == "미설치"  # Name tag must not match.
    assert second["tier"] == "DEV" and second["purpose"] == "Batch" and second["state"] == "Stop"
    assert third["tier"] == "QA" and third["state"] == "Pending" and third["purpose"] == "-"
    for row in spec["rows"]:
        assert all(row[key] == "-" for key in ["kernel", "osEos", "was", "web", "db", "dbPlatform", "dbEos", "eipRequired", "installedAt"])
    assert second["cpu"] == second["memory"] == "-"


@pytest.mark.parametrize("mib,expected", [(8192, "8 GiB"), (1536, "1.5 GiB"), (1048576, "1024 GiB")])
def test_memory_units(tmp_path, mib, expected):
    exporter, data = prepare(tmp_path)
    data["instance_types"][0]["MemoryInfo"]["SizeInMiB"] = mib
    assert exporter._ec2_sheets(data)[0]["rows"][0]["memory"] == expected


def test_legacy_cache_and_empty_cache_are_supported(tmp_path):
    exporter, data = prepare(tmp_path)
    for key in ["instance_types", "volumes", "addresses"]: del data[key]
    row = exporter._ec2_sheets(data)[0]["rows"][0]
    assert all(row[key] == "-" for key in ["cpu", "memory", "ebs", "eip"])
    for kind in ["aws_ec2", "aws_sg"]:
        (tmp_path / "cache/aws.json").write_text("{}")
        result = exporter.build(kind)
        validate_xlsx(result["path"])
        with ZipFile(result["path"]) as archive:
            assert all(len(ET.fromstring(archive.read(name)).findall("m:sheetData/m:row", NS)) == 1 for name in archive.namelist() if name.startswith("xl/worksheets/"))


def test_exact_sophos_matching_priority_and_secondary_ip(tmp_path):
    _exporter, _data = prepare(tmp_path)
    matcher = SophosMatcher(tmp_path)
    assert matcher.match({"PrivateIpAddress": "10.0.0.1", "PrivateDnsName": "other-host"})["id"] == "sophos-1"
    assert matcher.match({"PrivateIpAddress": "10.0.0.10", "Tags": [{"Key": "Name", "Value": "host-from-sophos"}]}) is None
    assert matcher.match({"PrivateDnsName": " OTHER-HOST. "})["id"] == "sophos-2"
    assert matcher.match({"PrivateDnsName": "other-host.example.com"}) is None
    assert matcher.match({"NetworkInterfaces": [{"PrivateIpAddresses": [{"PrivateIpAddress": "10.0.0.1"}]}]})["id"] == "sophos-1"


def test_policy_attachment_rules_sorting_and_common_hostname(tmp_path):
    exporter, data = prepare(tmp_path)
    inventory = {row["instanceId"]: row for row in exporter._ec2_sheets(data)[0]["rows"]}
    sheet = exporter._sg_sheets(data)[3]
    assert list(sheet["headers"].values()) == POLICY_HEADERS
    rows = [row for row in sheet["rows"] if row["instanceId"] == "i-1"]
    assert len(rows) == 4
    assert [row["direction"] for row in rows] == ["Inbound"] * 3 + ["Outbound"]
    assert [row["fromPort"] for row in rows] == [22, 443, "Type 8", "ALL"]
    assert rows[-1]["protocol"] == rows[-1]["toPort"] == "ALL"
    assert rows[-1]["sourceType"] == rows[-1]["source"] == "-"
    assert rows[-1]["destination"] == "0.0.0.0/0"
    assert rows[0]["source"] == "101.1.0.0/22" and rows[0]["destination"] == "-"
    assert rows[2]["toPort"] == "Code 0"
    assert all(row["groupId"] != "sg-reference" for row in rows)
    assert all(row["hostname"] == inventory[row["instanceId"]]["hostname"] for row in sheet["rows"])
    empty = next(row for row in sheet["rows"] if row["instanceId"] == "i-2")
    assert all(empty[key] == "-" for key in ["groupId", "direction", "protocol", "fromPort", "toPort", "source", "destination"])
    assert empty["ec2Name"] == "host-from-sophos" and empty["state"] == "Stop"


def test_multiple_enis_and_equal_ports_preserve_individual_applications(tmp_path):
    exporter, data = prepare(tmp_path)
    interface = copy.deepcopy(data["instances"][0]["NetworkInterfaces"][0])
    interface.update({"NetworkInterfaceId": "eni-b", "SubnetId": "subnet-b", "Groups": [{"GroupId": "sg-a"}]})
    data["instances"][0]["NetworkInterfaces"].append(interface)
    data["security_group_rules"].append({"GroupId": "sg-b", "SecurityGroupRuleId": "same-port", "IsEgress": False, "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "CidrIpv4": "0.0.0.0/0"})
    rows = [row for row in exporter._sg_sheets(data)[3]["rows"] if row["instanceId"] == "i-1"]
    assert len(rows) == 8  # 3 rules * 2 ENIs + 2 rules * 1 ENI.
    https = [row for row in rows if row["fromPort"] == 443]
    assert {(row["groupId"], row["eniId"], row["subnetId"]) for row in https} == {("sg-a", "eni-a", "subnet-a"), ("sg-a", "eni-b", "subnet-b"), ("sg-b", "eni-a", "subnet-a")}


@pytest.mark.parametrize("target,target_type,expected", [
    ({"CidrIpv4": "10.0.0.0/8"}, "IPv4 CIDR", "10.0.0.0/8"),
    ({"CidrIpv6": "::/0"}, "IPv6 CIDR", "::/0"),
    ({"ReferencedGroupInfo": {"GroupId": "sg-reference"}}, "Security Group", "sg-reference"),
    ({"PrefixListId": "pl-1"}, "Prefix List", "pl-1"),
])
@pytest.mark.parametrize("egress", [False, True])
def test_policy_target_types_and_direction(tmp_path, target, target_type, expected, egress):
    exporter, data = prepare(tmp_path)
    data["security_group_rules"] = [{"GroupId": "sg-a", "SecurityGroupRuleId": "r", "IsEgress": egress, "IpProtocol": "udp", "FromPort": 53, "ToPort": 54, **target}]
    row = exporter._sg_sheets(data)[3]["rows"][0]
    assert row["direction"] == ("Outbound" if egress else "Inbound")
    active, inactive = ("destination", "source") if egress else ("source", "destination")
    assert row[active + "Type"] == target_type and row[active] == expected
    assert row[inactive + "Type"] == row[inactive] == "-"
    assert row["protocol"] == "UDP" and (row["fromPort"], row["toPort"]) == (53, 54)


@pytest.mark.parametrize("protocol,expected", [("icmp", "ICMP"), ("1", "ICMP"), ("icmpv6", "ICMPv6"), ("58", "ICMPv6")])
def test_icmp_is_type_code_not_tcp_ports(tmp_path, protocol, expected):
    exporter, data = prepare(tmp_path)
    data["security_group_rules"] = [{"GroupId": "sg-a", "IsEgress": False, "IpProtocol": protocol, "FromPort": -1, "ToPort": -1, "CidrIpv6": "::/0"}]
    row = exporter._sg_sheets(data)[3]["rows"][0]
    assert (row["protocol"], row["fromPort"], row["toPort"]) == (expected, "Type -1", "Code -1")


def test_real_workbooks_styles_merge_xml_and_cache_only_export(tmp_path, monkeypatch):
    exporter, _data = prepare(tmp_path)
    import boto3
    monkeypatch.setattr(boto3, "client", lambda *_args, **_kwargs: pytest.fail("Export called AWS"))
    import requests
    monkeypatch.setattr(requests.sessions.Session, "request", lambda *_args, **_kwargs: pytest.fail("Export called an external API"))
    results = [exporter.build("aws_ec2"), exporter.build("aws_sg")]
    for result in results: validate_xlsx(result["path"])
    with ZipFile(results[0]["path"]) as archive:
        styles = ET.fromstring(archive.read("xl/styles.xml"))
        sheet = ET.fromstring(archive.read("xl/worksheets/sheet1.xml"))
        refs = cells(sheet)
        assert [text(cell) for cell in sheet.find("m:sheetData/m:row", NS)] == EC2_HEADERS
        for ref, color in [("Z2", "FF228B46"), ("Z3", "FFC62828"), ("AA2", "FF2463B5"), ("AA3", "FFC62828")]:
            fill, font, bold, xf, border = style_info(styles, refs[ref])
            assert (fill, font, bold) == (color, "FFFFFFFF", True)
        fill, font, bold, xf, border = style_info(styles, refs["B2"])
        assert (fill, font, bold) == ("FFFFFFFF", "FF000000", False)
        assert xf.find("m:alignment", NS).attrib["vertical"] == "center"
        assert all(border.find(f"m:{edge}", NS).attrib["style"] == "thin" for edge in ["left", "right", "top", "bottom"])
    with ZipFile(results[1]["path"]) as archive:
        styles = ET.fromstring(archive.read("xl/styles.xml"))
        for index in range(1, 5):
            sheet = ET.fromstring(archive.read(f"xl/worksheets/sheet{index}.xml"))
            refs = cells(sheet)
            fill, font, bold, xf, border = style_info(styles, refs["A1"])
            assert (fill, font, bold) == ("FF17365D", "FFFFFFFF", True)
            assert xf.find("m:alignment", NS).attrib["horizontal"] == "center"
            assert sheet.find("m:autoFilter", NS) is not None
            assert sheet.find("m:sheetViews/m:sheetView/m:pane", NS).attrib["state"] == "frozen"
            if index in [2, 3]:
                assert style_info(styles, refs["C2"])[0] == ("FFDDEBF7" if index == 2 else "FFFCE4D6")
                assert style_info(styles, refs["D2"])[0] == "FFFFFFFF"
            if index == 4:
                assert [text(cell) for cell in sheet.find("m:sheetData/m:row", NS)] == POLICY_HEADERS
                assert {item.attrib["ref"] for item in sheet.findall("m:mergeCells/m:mergeCell", NS)} == {f"{col}2:{col}5" for col in "ABCDEFG"}
                assert style_info(styles, refs["E2"])[0:3] == ("FF228B46", "FFFFFFFF", True)
                assert style_info(styles, refs["E6"])[0:3] == ("FFC62828", "FFFFFFFF", True)
                assert style_info(styles, refs["J2"])[0:3] == ("FFDDEBF7", "FF172B4D", True)
                assert style_info(styles, refs["J5"])[0:3] == ("FFFCE4D6", "FF172B4D", True)
                assert style_info(styles, refs["H2"])[4].find("m:top", NS).attrib["style"] == "medium"
                assert style_info(styles, refs["H3"])[4].find("m:top", NS).attrib["style"] == "thin"
                assert style_info(styles, refs["H6"])[4].find("m:top", NS).attrib["style"] == "medium"


def test_network_interfaces_and_original_sg_sheet_data_regression(tmp_path):
    exporter, data = prepare(tmp_path)
    interface_sheet = exporter._ec2_sheets(data)[1]
    assert list(interface_sheet["headers"].values()) == ["EC2 Name", "Instance ID", "ENI ID", "Device Index", "VPC ID", "Subnet ID", "Primary Private IP", "All Private IPs", "Public IP", "Security Groups", "Interface Status"]
    assert interface_sheet["rows"] == [{"name": "A", "instanceId": "i-1", "eniId": "eni-a", "deviceIndex": 0, "vpcId": "vpc-1", "subnetId": "subnet-a", "primaryPrivateIp": "10.0.0.1", "privateIps": "10.0.0.1\n10.0.0.11", "publicIp": "203.0.113.1", "securityGroups": "Application (sg-a)\nDatabase (sg-b)", "status": "in-use"}]
    summary, inbound, outbound, _mapping = exporter._sg_sheets(data)
    assert summary["rows"][0] == {"name": "Application", "groupId": "sg-a", "description": "app", "vpcId": "vpc-1", "inbound": 2, "outbound": 1, "instances": 1, "instanceList": "A (i-1)"}
    assert summary["rows"][2]["instances"] == 0
    assert "미사용" not in json.dumps(summary, ensure_ascii=False)
    assert len(inbound["rows"]) == 4 and len(outbound["rows"]) == 1
    assert list(inbound["headers"].values()) == ["SG Name", "SG ID", "Rule ID", "Protocol", "From Port", "To Port", "Source Type", "Source CIDR", "Referenced SG ID", "Referenced SG Name", "Prefix List ID", "Description"]
    assert outbound["headers"]["sourceType"] == "Destination Type" and outbound["headers"]["cidr"] == "Destination CIDR"
    assert inbound["rows"][0] == {"name": "Application", "groupId": "sg-a", "ruleId": "in-443", "isEgress": False, "protocol": "TCP", "port": "443", "target": "0.0.0.0/0", "sourceType": "IPv4 CIDR", "cidr": "0.0.0.0/0", "referencedGroupId": "-", "referencedGroupName": "-", "prefixListId": "-", "fromPort": 443, "toPort": 443, "description": "HTTPS"}


def test_multi_server_multi_eni_merge_ranges_do_not_overlap(tmp_path):
    exporter, data = prepare(tmp_path)
    second = copy.deepcopy(data["instances"][0])
    second.update({"InstanceId": "i-0", "State": {"Name": "stopped"}})
    second["Tags"] = [{"Key": "Name", "Value": "A"}]
    second["NetworkInterfaces"][0]["NetworkInterfaceId"] = "eni-other"
    data["instances"].insert(0, second)
    interface = copy.deepcopy(data["instances"][1]["NetworkInterfaces"][0])
    interface["NetworkInterfaceId"] = "eni-extra"
    data["instances"][1]["NetworkInterfaces"].append(interface)
    (tmp_path / "cache/aws.json").write_text(json.dumps(data))
    result = exporter.build("aws_sg")
    validate_xlsx(result["path"])
    with ZipFile(result["path"]) as archive:
        sheet = ET.fromstring(archive.read("xl/worksheets/sheet4.xml"))
        assert {item.attrib["ref"] for item in sheet.findall("m:mergeCells/m:mergeCell", NS)} == {f"{col}{start}:{col}{end}" for col in "ABCDEFG" for start, end in [(2, 5), (6, 13)]}
        refs = cells(sheet)
        assert text(refs["D2"]) == "i-0" and text(refs["D6"]) == "i-1"


def test_generic_xlsx_uses_common_ledger_style_without_merging(tmp_path):
    path = tmp_path / "generic.xlsx"
    write_xlsx_workbook(path, [{"name": "Data", "rows": [{"a": "x"}, {"a": "x"}], "columns": ["a"]}])
    with ZipFile(path) as archive:
        sheet = ET.fromstring(archive.read("xl/worksheets/sheet1.xml"))
        assert cells(sheet)["A1"].attrib["s"] == "10" and cells(sheet)["A2"].attrib["s"] == "11"
        assert sheet.find("m:mergeCells", NS) is None


def test_merge_rejects_data_loss_and_deduplicates_columns(tmp_path):
    path = tmp_path / "merge.xlsx"
    spec = {"name": "Data", "columns": ["no", "value"], "groupKey": "no", "mergeColumns": ["value", "value"], "tableStyle": "ledger",
            "rows": [{"no": 1, "value": "first"}, {"no": 1, "value": "second"}]}
    with pytest.raises(ValueError, match="Cannot merge differing values"):
        write_xlsx_workbook(path, [spec])
    spec["rows"][1]["value"] = "first"
    write_xlsx_workbook(path, [spec])
    validate_xlsx(path)
    with ZipFile(path) as archive:
        sheet = ET.fromstring(archive.read("xl/worksheets/sheet1.xml"))
        assert [item.attrib["ref"] for item in sheet.findall("m:mergeCells/m:mergeCell", NS)] == ["B2:B3"]


@pytest.mark.parametrize("kind", ["aws_ec2", "aws_sg"])
def test_existing_laborer_job_generates_inventory_workbook(tmp_path, kind):
    from system_monitor.laborer import LaborerAgent
    prepare(tmp_path)
    agent = LaborerAgent(tmp_path)
    job = agent.submit("aws_export", {"kind": kind})
    worker = threading.Thread(target=agent.worker_loop, daemon=True)
    worker.start()
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            result = agent.get(job["id"])
            if result["status"] in {"completed", "failed"}: break
            time.sleep(0.01)
        assert result["status"] == "completed", result
        assert Path(result["result"]["path"]).parent == tmp_path / "exports"
        validate_xlsx(result["result"]["path"])
    finally:
        agent.stop.set()
        agent.wake.set()
        worker.join(timeout=2)
        assert not worker.is_alive()
