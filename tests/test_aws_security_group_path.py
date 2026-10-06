import copy
import ipaddress
import json
from pathlib import Path

import pytest

from backend.services.aws_assets import AwsAssetService
from backend.services.aws_security_group_path import AwsSecurityGroupPathService, policy_summary
from backend.services.firewall_path_check import FirewallPathCheckService


def payload():
    def interface(identifier, private, groups):
        return {"NetworkInterfaceId": identifier, "PrivateIpAddress": private, "PrivateIpAddresses": [{"PrivateIpAddress": private}],
                "Ipv6Addresses": [], "Groups": [{"GroupId": group} for group in groups], "VpcId": "vpc-1", "SubnetId": "subnet-1"}
    return {
        "metadata": {"fetched_at": "2026-10-06T00:00:00Z"},
        "instances": [
            {"InstanceId": "i-a", "PrivateIpAddress": "10.10.0.10", "Tags": [{"Key": "Name", "Value": "Source Server"}],
             "NetworkInterfaces": [interface("eni-a", "10.10.0.10", ["sg-a"]), interface("eni-other", "10.10.0.11", ["sg-other"])]},
            {"InstanceId": "i-b", "PrivateIpAddress": "100.1.2.10", "Tags": [{"Key": "Name", "Value": "Destination Server"}],
             "NetworkInterfaces": [interface("eni-b", "100.1.2.10", ["sg-b"])]},
        ],
        "security_groups": [{"GroupId": identifier, "GroupName": identifier + "-name"} for identifier in ["sg-a", "sg-b", "sg-other", "sg-unused"]],
        "security_group_rules": [
            {"GroupId": "sg-a", "SecurityGroupRuleId": "out-a", "IsEgress": True, "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "CidrIpv4": "0.0.0.0/0", "Description": "Outbound HTTPS"},
            {"GroupId": "sg-b", "SecurityGroupRuleId": "in-b", "IsEgress": False, "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "CidrIpv4": "0.0.0.0/0", "Description": "Inbound HTTPS"},
            {"GroupId": "sg-other", "SecurityGroupRuleId": "other-eni", "IsEgress": True, "IpProtocol": "-1", "CidrIpv4": "0.0.0.0/0"},
        ],
        "addresses": [{"AllocationId": "eipalloc-1", "InstanceId": "i-b", "NetworkInterfaceId": "eni-b", "PrivateIpAddress": "100.1.2.10", "PublicIp": "52.79.112.47"}],
        "network_interfaces": [],
    }


def save(root: Path, data):
    (root / "cache").mkdir(exist_ok=True, parents=True)
    (root / "cache/aws.json").write_text(json.dumps(data), encoding="utf-8")


def sg_check(root, source="10.10.0.10", destination="100.1.2.10", protocol="TCP", port=443, path=None, partial=False, number=None):
    return AwsSecurityGroupPathService(root).check(ipaddress.ip_network(source, strict=False), ipaddress.ip_network(destination, strict=False), protocol, port, number, path or [], partial)


def path_service(root, monkeypatch):
    service = FirewallPathCheckService(root)
    monkeypatch.setattr(service.firewalls, "configurations", lambda: [{"name": name, "configured": True} for name in ["Seoul", "Cloud", "Icheon", "Anseong"]])
    any_rule = {"Rule Name": "existing-fw-allow", "Status": "활성", "Action": "Allow", "Source Object": "Any", "Source Resolved": "Any", "Destination Object": "Any", "Destination Resolved": "Any", "Service": "Any", "Source Zone": "Any", "Destination Zone": "Any"}
    monkeypatch.setattr(service, "_snapshot", lambda *_args: {"rules": [any_rule], "routes": [], "routeError": "", "checkedAt": "now"})
    return service


@pytest.mark.parametrize("source,destination,direction,path", [
    ("101.1.0.50", "100.1.2.10", "inbound", ["Seoul", "Cloud"]),
    ("10.10.0.10", "101.1.0.50", "outbound", ["Cloud", "Seoul"]),
    ("8.8.8.8", "100.1.2.10", "inbound", ["Cloud"]),
])
@pytest.mark.parametrize("allowed", [True, False])
def test_office_aws_wan_paths_keep_firewalls_and_add_endpoint_sg(tmp_path, monkeypatch, source, destination, direction, path, allowed):
    data = payload()
    if not allowed: data["security_group_rules"] = []
    save(tmp_path, data)
    result = path_service(tmp_path, monkeypatch).check(source, destination, "TCP", 443)
    assert result["path"] == path
    assert [hop["firewall"] for hop in result["firewalls"]] == path
    assert all(hop["policy"]["state"] == "allow" for hop in result["firewalls"])
    step = result["awsSecurityGroups"][direction]
    assert step["state"] == ("PASS" if allowed else "FAIL")
    assert result["policySummary"]["state"] == step["state"]
    assert result["awsSecurityGroups"]["outbound" if direction == "inbound" else "inbound"]["state"] == "N/A"
    if direction == "inbound": assert result["steps"][-1]["label"] == "AWS SG Inbound"
    else: assert result["steps"][0]["label"] == "AWS SG Outbound"


@pytest.mark.parametrize("path,partial", [([], False), (["Cloud"], False)])
def test_same_vpc_overrides_site_based_cloud_heuristic(tmp_path, monkeypatch, path, partial):
    import backend.services.firewall_path_check as module
    save(tmp_path, payload())
    monkeypatch.setattr(module, "determine_firewall_path", lambda *_args: (path, partial))
    result = path_service(tmp_path, monkeypatch).check("10.10.0.10", "100.1.2.10", "TCP", 443)
    assert result["path"] == []
    assert [step["kind"] for step in result["steps"]] == ["aws_sg", "aws_sg"]
    assert result["awsSecurityGroups"]["outbound"]["state"] == result["awsSecurityGroups"]["inbound"]["state"] == "PASS"
    assert result["policySummary"] == {"state": "PASS", "label": "AWS SG 정책 기준 허용"}
    # No Source Inbound or Destination Outbound rules exist in this fixture.
    assert [step["direction"] for step in result["steps"] if step["kind"] == "aws_sg"] == ["Outbound", "Inbound"]


def test_endpoint_identity_is_ip_based_and_eni_specific(tmp_path):
    save(tmp_path, payload())
    result = sg_check(tmp_path)
    assert result["outbound"]["endpoint"] == {"state": "IDENTIFIED", "reason": "IP와 연결 ENI exact match", "name": "Source Server", "instanceId": "i-a", "eniId": "eni-a", "ip": "10.10.0.10", "addressKind": "private", "vpcId": "vpc-1", "subnetId": "subnet-1", "groupIds": ["sg-a"], "groupsValid": True}
    assert [rule["ruleId"] for rule in result["outbound"]["matches"]] == ["out-a"]
    assert sg_check(tmp_path, source="10.10.0.100")["outbound"]["state"] == "N/A"
    assert sg_check(tmp_path, source="10.10.0.11", port=22)["outbound"]["state"] == "PASS"
    assert sg_check(tmp_path, port=22)["outbound"]["state"] == "FAIL"  # Other ENI's ALL rule cannot allow this IP.


def test_secondary_private_ip_and_eip_use_actual_attachment(tmp_path):
    data = payload()
    data["instances"][1]["NetworkInterfaces"][0]["PrivateIpAddresses"].append({"PrivateIpAddress": "100.1.2.20"})
    save(tmp_path, data)
    for ip in ["100.1.2.20", "52.79.112.47"]:
        step = sg_check(tmp_path, destination=ip)["inbound"]
        assert step["state"] == "PASS"
        assert (step["endpoint"]["instanceId"], step["endpoint"]["eniId"]) == ("i-b", "eni-b")
    data["addresses"][0].pop("NetworkInterfaceId")
    save(tmp_path, data)
    assert sg_check(tmp_path, destination="52.79.112.47")["inbound"]["state"] == "PASS"
    data["addresses"][0].pop("PrivateIpAddress")
    save(tmp_path, data)
    assert sg_check(tmp_path, destination="52.79.112.47")["inbound"]["state"] == "UNKNOWN"


def test_reuses_shared_interface_helper_and_raw_attachment_enrichment(tmp_path, monkeypatch):
    data = payload()
    original = copy.deepcopy(data["instances"][1]["NetworkInterfaces"][0])
    original["Attachment"] = {"InstanceId": "i-b"}
    data["instances"][1]["NetworkInterfaces"] = []
    data["network_interfaces"] = [original]
    called = []
    helper = AwsAssetService.attached_interfaces
    monkeypatch.setattr(AwsAssetService, "attached_interfaces", staticmethod(lambda instance, cache=None: called.append(instance["InstanceId"]) or helper(instance, cache)))
    save(tmp_path, data)
    assert sg_check(tmp_path)["inbound"]["state"] == "PASS" and "i-b" in called
    data["network_interfaces"][0]["Attachment"]["InstanceId"] = "wrong-instance"
    save(tmp_path, data)
    assert sg_check(tmp_path)["inbound"]["state"] == "UNKNOWN"


def test_multiple_attached_sgs_are_union_and_all_matches_remain_visible(tmp_path):
    data = payload()
    data["instances"][1]["NetworkInterfaces"][0]["Groups"].append({"GroupId": "sg-unused"})
    rule = copy.deepcopy(data["security_group_rules"][1])
    rule.update(GroupId="sg-unused", SecurityGroupRuleId="second-in")
    data["security_group_rules"].append(rule)
    save(tmp_path, data)
    step = sg_check(tmp_path)["inbound"]
    assert step["state"] == "PASS"
    assert {rule["ruleId"] for rule in step["matches"]} == {"in-b", "second-in"}
    data["security_group_rules"][1]["FromPort"] = data["security_group_rules"][1]["ToPort"] = 22
    save(tmp_path, data)
    step = sg_check(tmp_path)["inbound"]
    assert step["state"] == "PASS" and [rule["ruleId"] for rule in step["matches"]] == ["second-in"]


def test_egress_boolean_is_not_inferred_from_name_or_other_rules(tmp_path):
    data = payload()
    data["security_group_rules"][1].update(IsEgress=True, Description="Inbound by name only")
    save(tmp_path, data)
    assert sg_check(tmp_path)["inbound"]["state"] == "FAIL"
    data["security_group_rules"][0]["IsEgress"] = False
    save(tmp_path, data)
    assert sg_check(tmp_path)["outbound"]["state"] == "FAIL"


@pytest.mark.parametrize("cidr,source,expected", [
    ("10.10.0.0/24", "10.10.0.10", "PASS"),
    ("10.10.0.0/28", "10.10.0.100", "FAIL"),
    ("10.10.0.0/24", "10.10.0.0/16", "UNKNOWN"),
    ("10.10.0.0/16", "10.10.0.0/24", "PASS"),
    ("192.168.0.0/16", "10.10.0.10", "FAIL"),
])
def test_ipv4_cidr_containment_not_string_prefix(tmp_path, cidr, source, expected):
    data = payload()
    data["security_group_rules"][1]["CidrIpv4"] = cidr
    save(tmp_path, data)
    assert sg_check(tmp_path, source=source)["inbound"]["state"] == expected


@pytest.mark.parametrize("protocol,raw,start,end,port,expected", [
    ("TCP", "tcp", 443, 443, 443, "PASS"),
    ("TCP", "6", 400, 500, 443, "PASS"),
    ("TCP", "tcp", 400, 500, 399, "FAIL"),
    ("TCP", "tcp", 400, 500, 501, "FAIL"),
    ("UDP", "udp", 53, 53, 53, "PASS"),
    ("UDP", "17", 53, 53, 53, "PASS"),
    ("UDP", "tcp", 53, 53, 53, "FAIL"),
    ("TCP", "-1", None, None, 22, "PASS"),
    ("ICMP", "icmp", 8, 0, None, "UNKNOWN"),
    ("ICMP", "1", -1, -1, None, "PASS"),
    ("ICMPV6", "58", 128, 0, None, "UNKNOWN"),
    ("ICMPV6", "icmpv6", -1, -1, None, "PASS"),
])
def test_protocol_port_and_icmp_type_code_handling(tmp_path, protocol, raw, start, end, port, expected):
    data = payload()
    data["security_group_rules"][1].update(IpProtocol=raw, FromPort=start, ToPort=end)
    save(tmp_path, data)
    step = sg_check(tmp_path, protocol=protocol, port=port)["inbound"]
    assert step["state"] == expected
    if raw == "-1": assert step["matches"][0]["fromPort"] == step["matches"][0]["toPort"] == "ALL"
    if protocol in {"ICMP", "ICMPV6"}:
        assert step["matches"][0]["fromPort"] == f"Type {start}"
        assert step["matches"][0]["toPort"] == f"Code {end}"


@pytest.mark.parametrize("number,expected", [(47, "PASS"), (50, "FAIL"), (None, "UNKNOWN")])
def test_ip_protocol_number_supported_without_using_it_as_port(tmp_path, number, expected):
    data = payload()
    data["security_group_rules"][1].update(IpProtocol="47")
    save(tmp_path, data)
    assert sg_check(tmp_path, protocol="IP", port=None, number=number)["inbound"]["state"] == expected


@pytest.mark.parametrize("protocol,port", [("ANY", None), ("TCP", None), ("UDP", None)])
def test_broad_queries_show_address_rule_candidates_and_never_false_fail(tmp_path, protocol, port):
    data = payload()
    data["security_group_rules"].append({"GroupId": "sg-b", "SecurityGroupRuleId": "udp", "IsEgress": False, "IpProtocol": "udp", "FromPort": 53, "ToPort": 53, "CidrIpv4": "0.0.0.0/0"})
    save(tmp_path, data)
    step = sg_check(tmp_path, protocol=protocol, port=port)["inbound"]
    assert step["state"] == "UNKNOWN" and step["broadQuery"] is True
    assert {rule["ruleId"] for rule in step["matches"]} == {"in-b", "udp"}
    assert all(rule["match"] == "CANDIDATE" for rule in step["matches"])
    data["security_group_rules"] = []
    save(tmp_path, data)
    assert sg_check(tmp_path, protocol=protocol, port=port)["inbound"]["state"] == "UNKNOWN"


@pytest.mark.parametrize("direction", ["inbound", "outbound"])
def test_referenced_sg_exact_attachment_for_direct_same_vpc_only(tmp_path, direction):
    data = payload()
    index, referenced = (1, "sg-a") if direction == "inbound" else (0, "sg-b")
    data["security_group_rules"][index].pop("CidrIpv4")
    data["security_group_rules"][index]["ReferencedGroupInfo"] = {"GroupId": referenced}
    save(tmp_path, data)
    assert sg_check(tmp_path)[direction]["state"] == "PASS"
    assert sg_check(tmp_path, path=["Cloud"])[direction]["state"] == "PASS"
    assert sg_check(tmp_path, partial=True)[direction]["state"] == "PASS"
    data["security_group_rules"][index]["ReferencedGroupInfo"]["GroupId"] = referenced + "0"
    save(tmp_path, data)
    assert sg_check(tmp_path)[direction]["state"] == "FAIL"
    data["security_group_rules"][index]["ReferencedGroupInfo"]["GroupId"] = "sg-other" if direction == "inbound" else "sg-unused"
    save(tmp_path, data)
    assert sg_check(tmp_path)[direction]["state"] == "FAIL"  # Wrong ENI or unattached SG.


def test_sg_reference_does_not_attach_the_referenced_group(tmp_path):
    data = payload()
    data["security_group_rules"] = [{"GroupId": "sg-unused", "IsEgress": False, "IpProtocol": "-1", "CidrIpv4": "0.0.0.0/0"},
                                   {"GroupId": "sg-b", "IsEgress": False, "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "ReferencedGroupInfo": {"GroupId": "sg-unused"}}]
    save(tmp_path, data)
    assert sg_check(tmp_path)["inbound"]["state"] == "FAIL"


@pytest.mark.parametrize("public,different_vpc", [(True, False), (False, True)])
def test_reference_public_nat_or_uncollected_vpc_connectivity_is_candidate(tmp_path, public, different_vpc):
    data = payload()
    data["security_group_rules"][0].pop("CidrIpv4")
    data["security_group_rules"][0]["ReferencedGroupInfo"] = {"GroupId": "sg-b"}
    if different_vpc: data["instances"][1]["NetworkInterfaces"][0]["VpcId"] = "vpc-2"
    save(tmp_path, data)
    assert sg_check(tmp_path, destination="52.79.112.47" if public else "100.1.2.10")["outbound"]["state"] == "UNKNOWN"


def test_prefix_list_is_candidate_unless_an_independent_exact_allow_exists(tmp_path):
    data = payload()
    rule = data["security_group_rules"][1]
    rule.pop("CidrIpv4")
    rule["PrefixListId"] = "pl-123"
    save(tmp_path, data)
    step = sg_check(tmp_path)["inbound"]
    assert step["state"] == "UNKNOWN" and step["matches"][0]["target"] == "pl-123"
    assert "실제 CIDR 목록 미수집" in step["matches"][0]["reason"]
    data["security_group_rules"].append(copy.deepcopy(payload()["security_group_rules"][1]))
    save(tmp_path, data)
    assert sg_check(tmp_path)["inbound"]["state"] == "PASS"


def test_unrelated_endpoints_return_na(tmp_path):
    save(tmp_path, payload())
    result = sg_check(tmp_path, source="192.168.99.1", destination="8.8.8.8")
    assert result["outbound"]["state"] == result["inbound"]["state"] == "N/A"


@pytest.mark.parametrize("broken", [None, "{malformed", [], {"instances": []}, {"instances": "invalid"}])
def test_cache_errors_keep_existing_firewall_results_and_do_not_fail_request(tmp_path, monkeypatch, broken):
    if broken is not None:
        save(tmp_path, broken)
        if isinstance(broken, str): (tmp_path / "cache/aws.json").write_text(broken)
    result = path_service(tmp_path, monkeypatch).check("101.1.0.50", "100.1.2.10", "TCP", 443)
    assert result["firewalls"][0]["policy"]["state"] == "allow"
    if broken == {"instances": []}:
        assert result["awsSecurityGroups"]["inbound"]["state"] == "N/A"
    else:
        assert result["awsSecurityGroups"]["inbound"]["state"] == "UNKNOWN"
        assert result["policySummary"]["state"] == "UNKNOWN"


@pytest.mark.parametrize("missing", ["Groups", "security_groups", "security_group_rules"])
def test_missing_required_sg_data_is_unknown_not_default_deny(tmp_path, missing):
    data = payload()
    if missing == "Groups": del data["instances"][1]["NetworkInterfaces"][0][missing]
    else: del data[missing]
    save(tmp_path, data)
    assert sg_check(tmp_path)["inbound"]["state"] == "UNKNOWN"


def test_empty_rules_are_a_confirmed_fail_for_specific_query(tmp_path):
    data = payload()
    data["security_group_rules"] = []
    save(tmp_path, data)
    step = sg_check(tmp_path)["inbound"]
    assert step["state"] == "FAIL"
    assert step["reason"] == "Attached SG에서 Query 조건과 일치하는 Allow Rule 없음"


def test_cidr_and_duplicate_ip_never_select_arbitrary_instance(tmp_path):
    data = payload()
    save(tmp_path, data)
    assert sg_check(tmp_path, source="10.10.0.0/24")["outbound"]["state"] == "UNKNOWN"
    duplicate = copy.deepcopy(data["instances"][0])
    duplicate["InstanceId"] = "i-duplicate"
    duplicate["NetworkInterfaces"][0].update(NetworkInterfaceId="eni-duplicate", VpcId="vpc-other")
    data["instances"].append(duplicate)
    save(tmp_path, data)
    step = sg_check(tmp_path)["outbound"]
    assert step["state"] == "UNKNOWN" and len(step["endpoint"]["candidates"]) == 2


def test_ipv6_eni_lookup_containment_and_family_separation(tmp_path, monkeypatch):
    data = payload()
    data["instances"][0]["NetworkInterfaces"][0]["Ipv6Addresses"] = [{"Ipv6Address": "2001:db8:a::10"}]
    data["instances"][1]["NetworkInterfaces"][0]["Ipv6Addresses"] = [{"Ipv6Address": "2001:db8:b::10"}]
    for rule in data["security_group_rules"][:2]:
        rule.pop("CidrIpv4")
        rule["CidrIpv6"] = "2001:db8::/32"
    save(tmp_path, data)
    result = path_service(tmp_path, monkeypatch).check("2001:db8:a::10", "2001:db8:b::10", "TCP", 443)
    assert result["awsSecurityGroups"]["outbound"]["state"] == result["awsSecurityGroups"]["inbound"]["state"] == "PASS"
    assert result["awsSecurityGroups"]["inbound"]["endpoint"]["eniId"] == "eni-b"
    assert sg_check(tmp_path)["inbound"]["state"] == "FAIL"
    with pytest.raises(ValueError, match="same|同|같은"):
        path_service(tmp_path, monkeypatch).check("10.10.0.10", "2001:db8:b::10", "TCP", 443)


def test_only_collected_cache_is_used_and_reload_observes_existing_refresh(tmp_path, monkeypatch):
    import boto3
    import requests
    monkeypatch.setattr(boto3, "client", lambda *_args, **_kwargs: pytest.fail("AWS API called"))
    monkeypatch.setattr(requests.sessions.Session, "request", lambda *_args, **_kwargs: pytest.fail("External request called"))
    data = payload()
    save(tmp_path, data)
    service = path_service(tmp_path, monkeypatch)
    assert service.check("10.10.0.10", "100.1.2.10", "TCP", 443)["awsSecurityGroups"]["inbound"]["state"] == "PASS"
    data["security_group_rules"] = []
    save(tmp_path, data)
    assert service.check("10.10.0.10", "100.1.2.10", "TCP", 443, refresh=True)["awsSecurityGroups"]["inbound"]["state"] == "FAIL"


@pytest.mark.parametrize("mutation", ["invalid_rule", "unknown_group", "missing_rule_protocol", "null_rule_protocol", "missing_ports", "no_eni", "no_address"])
def test_partial_cache_cannot_become_false_allow_or_false_default_deny(tmp_path, mutation):
    data = payload()
    if mutation == "invalid_rule": data["security_group_rules"][1]["IsEgress"] = "false"
    elif mutation == "unknown_group": data["security_groups"] = []
    elif mutation == "missing_rule_protocol": del data["security_group_rules"][1]["IpProtocol"]
    elif mutation == "null_rule_protocol": data["security_group_rules"][1]["IpProtocol"] = None
    elif mutation == "missing_ports": del data["security_group_rules"][1]["ToPort"]
    elif mutation == "no_address":
        del data["instances"][1]["PrivateIpAddress"]
        data["instances"][1]["NetworkInterfaces"] = []
        data["addresses"] = []
    else:
        data["instances"][1]["NetworkInterfaces"] = []
        data["instances"][1]["SecurityGroups"] = [{"GroupId": "sg-b"}]
    save(tmp_path, data)
    assert sg_check(tmp_path)["inbound"]["state"] == "UNKNOWN"


def test_existing_fastapi_endpoint_returns_firewall_and_sg_results(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    import backend.app as app
    save(tmp_path, payload())
    monkeypatch.setattr(app, "firewall_path_check_service", path_service(tmp_path, monkeypatch))
    client = TestClient(app.app)
    response = client.post("/api/firewall/path-check", json={"source": "101.1.0.50", "destination": "100.1.2.10", "protocol": "TCP", "port": 443})
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["firewalls"][0]["policy"]["state"] == "allow"
    assert data["steps"][-1]["direction"] == "Inbound"
    assert data["steps"][-1]["matches"][0]["ruleId"] == "in-b"
    assert data["policySummary"]["state"] == "PASS"
    (tmp_path / "cache/aws.json").unlink()
    response = client.post("/api/firewall/path-check", json={"source": "101.1.0.50", "destination": "100.1.2.10", "protocol": "TCP", "port": 443})
    assert response.status_code == 200
    assert response.json()["data"]["firewalls"][0]["policy"]["state"] == "allow"
    assert response.json()["data"]["awsSecurityGroups"]["inbound"]["state"] == "UNKNOWN"
    invalid = client.post("/api/firewall/path-check", json={"source": "invalid", "destination": "100.1.2.10"})
    assert invalid.status_code == 400 and invalid.json()["error"]["code"] == "INVALID_PATH_CHECK"


@pytest.mark.parametrize("states,partial,expected", [(["PASS", "N/A"], False, "PASS"), (["PASS", "UNKNOWN"], False, "UNKNOWN"),
    (["FAIL", "UNKNOWN"], False, "FAIL"), (["PASS"], True, "UNKNOWN"), ([], False, "UNKNOWN")])
def test_policy_summary_does_not_claim_actual_connectivity(states, partial, expected):
    result = policy_summary([{"state": state} for state in states], partial)
    assert result["state"] == expected
    assert "실제 통신 가능" not in result["label"]


@pytest.mark.parametrize("destination_vpc,mode,partial", [("vpc-1", "same_vpc", False), ("vpc-10", "unknown", True), ("", "unknown", True)])
@pytest.mark.parametrize("blocked_direction", [None, "out-a", "in-b"])
def test_cached_vpc_identity_controls_path_before_sophos_queries(tmp_path, monkeypatch, destination_vpc, mode, partial, blocked_direction):
    data = payload()
    data["instances"][1]["NetworkInterfaces"][0]["VpcId"] = destination_vpc
    if blocked_direction:
        data["security_group_rules"] = [rule for rule in data["security_group_rules"] if rule["SecurityGroupRuleId"] != blocked_direction]
    save(tmp_path, data)
    service = path_service(tmp_path, monkeypatch)
    # Even a firewall snapshot with matching routes must not create a hop.
    snapshots = []
    def snapshot(*args):
        snapshots.append(args)
        return {"rules": [], "routes": [{"Destination": "0.0.0.0", "Netmask": "0.0.0.0"}], "routeError": "", "checkedAt": "now"}
    monkeypatch.setattr(service, "_snapshot", snapshot)
    result = service.check("10.10.0.10", "100.1.2.10", "TCP", 443)
    assert snapshots == []
    assert result["path"] == result["firewalls"] == []
    assert result["partialPath"] is partial
    assert result["awsSecurityGroups"]["networkPath"]["mode"] == mode
    assert [step["direction"] for step in result["steps"]] == ["Outbound", "Inbound"]
    assert result["steps"][0]["state"] == ("FAIL" if blocked_direction == "out-a" else "PASS")
    assert result["steps"][1]["state"] == ("FAIL" if blocked_direction == "in-b" else "PASS")
    assert result["policySummary"]["state"] == ("FAIL" if blocked_direction else "UNKNOWN" if partial else "PASS")
    if blocked_direction: assert result["policySummary"]["label"] == "AWS SG 정책 기준 차단"


def test_same_site_label_does_not_imply_same_vpc(tmp_path, monkeypatch):
    data = payload()
    destination = data["instances"][1]
    destination["PrivateIpAddress"] = "10.10.0.20"
    interface = destination["NetworkInterfaces"][0]
    interface.update(PrivateIpAddress="10.10.0.20", PrivateIpAddresses=[{"PrivateIpAddress": "10.10.0.20"}], VpcId="vpc-other")
    save(tmp_path, data)
    result = path_service(tmp_path, monkeypatch).check("10.10.0.10", "10.10.0.20", "TCP", 443)
    assert result["source"]["site"] == result["destination"]["site"]
    assert result["path"] == [] and result["partialPath"] is True


@pytest.mark.parametrize("eni_vpc", [True, False])
def test_vpc_identity_uses_eni_then_instance_without_site_mapping(tmp_path, monkeypatch, eni_vpc):
    data = payload()
    addresses = ["10.88.1.7", "10.99.2.9"]
    for instance, address in zip(data["instances"], addresses):
        instance["PrivateIpAddress"] = address
        instance["VpcId"] = "vpc-instance" if not eni_vpc else instance["InstanceId"]
        interface = instance["NetworkInterfaces"][0]
        interface.update(PrivateIpAddress=address, PrivateIpAddresses=[{"PrivateIpAddress": address}])
        if eni_vpc:
            interface["VpcId"] = "vpc-shared"
        else:
            interface.pop("VpcId")
        instance["NetworkInterfaces"] = [interface]
    save(tmp_path, data)
    result = path_service(tmp_path, monkeypatch).check(*addresses, "TCP", 443)
    assert result["path"] == [] and result["partialPath"] is False
    assert result["awsSecurityGroups"]["networkPath"]["mode"] == "same_vpc"
    assert all(step["state"] == "PASS" for step in result["steps"])
