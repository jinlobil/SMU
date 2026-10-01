import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from backend.services.aws_assets import AWS_OPERATIONS, AwsAssetService, AwsCollector, AwsConfigurationError, load_aws_credentials
from backend.services.refresh import RefreshService
from backend.services.settings import SchedulerService


class Paginator:
    def __init__(self, pages): self.pages = pages
    def paginate(self): return iter(self.pages)


class Client:
    def __init__(self, pages): self.pages = pages; self.calls = []
    def get_paginator(self, operation): self.calls.append(operation); return Paginator(self.pages[operation])


def credentials(root: Path, content="AWS_ACCESS_KEY_ID=test-key\nAWS_SECRET_ACCESS_KEY=test-secret\nAWS_REGION=ap-northeast-2\n"):
    path = root / "env/aws_env.txt"; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(content, encoding="utf-8"); return path


def all_pages():
    return {
        "describe_instances": [{"Reservations": [{"Instances": [{"InstanceId": "i-1"}]}], "NextToken": "next"}, {"Reservations": [{"Instances": [{"InstanceId": "i-2"}]}], "NextToken": "last"}, {"Reservations": [{"Instances": [{"InstanceId": "i-3"}]}]}],
        "describe_security_groups": [{"SecurityGroups": [{"GroupId": "sg-1", "GroupName": "one"}]}, {"SecurityGroups": [{"GroupId": "sg-2", "GroupName": "two"}]}],
        "describe_security_group_rules": [{"SecurityGroupRules": [{"SecurityGroupRuleId": "sgr-1"}]}, {"SecurityGroupRules": [{"SecurityGroupRuleId": "sgr-2"}]}],
        "describe_network_interfaces": [{"NetworkInterfaces": [{"NetworkInterfaceId": "eni-1"}]}, {"NetworkInterfaces": [{"NetworkInterfaceId": "eni-2"}]}],
        "describe_vpcs": [{"Vpcs": [{"VpcId": "vpc-1"}]}, {"Vpcs": [{"VpcId": "vpc-2"}]}],
        "describe_subnets": [{"Subnets": [{"SubnetId": "subnet-1"}]}, {"Subnets": [{"SubnetId": "subnet-2"}]}],
    }


def test_aws_credentials_are_parsed_and_missing_values_are_safe(tmp_path: Path):
    parsed = load_aws_credentials(credentials(tmp_path))
    assert parsed == {"AWS_ACCESS_KEY_ID": "test-key", "AWS_SECRET_ACCESS_KEY": "test-secret", "AWS_REGION": "ap-northeast-2"}
    with pytest.raises(AwsConfigurationError, match="AWS Credential 설정 필요"):
        load_aws_credentials(tmp_path / "missing.txt")
    with pytest.raises(AwsConfigurationError, match="AWS Credential 설정 필요"):
        load_aws_credentials(credentials(tmp_path, "AWS_ACCESS_KEY_ID=x\nAWS_SECRET_ACCESS_KEY=y\n"))


def test_every_aws_describe_operation_consumes_all_paginator_pages(tmp_path: Path):
    credentials(tmp_path); pages = all_pages(); pages["describe_vpcs"][0]["Vpcs"][0]["CreatedAt"] = datetime(2026, 10, 1, tzinfo=timezone.utc); client = Client(pages)
    payload = AwsCollector(tmp_path, lambda _credentials: client).collect()
    assert [item["InstanceId"] for item in payload["instances"]] == ["i-1", "i-2", "i-3"]
    assert set(client.calls) == {operation for operation, _key in AWS_OPERATIONS.values()}
    for name in ("security_groups", "security_group_rules", "network_interfaces", "vpcs", "subnets"):
        assert len(payload[name]) == 2
    assert payload["vpcs"][0]["CreatedAt"] == "2026-10-01T00:00:00+00:00"
    serialized = json.dumps(payload)
    assert "test-key" not in serialized and "test-secret" not in serialized


def test_refresh_writes_complete_json_atomically_and_failure_preserves_previous(tmp_path: Path):
    credentials(tmp_path); client = Client(all_pages()); service = RefreshService(tmp_path, aws_factory=lambda _credentials: client)
    result = service.refresh_aws(lambda _message: None)
    cache = tmp_path / "cache/aws.json"; payload = json.loads(cache.read_text(encoding="utf-8"))
    assert result["region"] == "ap-northeast-2" and payload["metadata"]["counts"]["instances"] == 3
    assert payload["instances"][0]["InstanceId"] == "i-1"
    previous = cache.read_bytes()
    broken = RefreshService(tmp_path, aws_factory=lambda _credentials: (_ for _ in ()).throw(RuntimeError("secret test-secret")))
    with pytest.raises(RuntimeError, match="AWS API 통신 실패"):
        broken.refresh_aws(lambda _message: None)
    assert cache.read_bytes() == previous


def test_instance_mapping_optional_fields_search_and_exact_group_links(tmp_path: Path):
    cache = tmp_path / "cache/aws.json"; cache.parent.mkdir(parents=True)
    cache.write_text(json.dumps({"metadata": {"region": "ap-northeast-2"}, "instances": [
        {"InstanceId": "i-1", "VpcId": "vpc-1", "SubnetId": "subnet-1", "State": {"Name": "running"}, "PrivateIpAddress": "10.0.0.1", "Tags": [{"Key": "Name", "Value": "App"}, {"Key": "OS", "Value": "Linux"}, {"Key": "OS_type", "Value": "CentOS"}, {"Key": "Description", "Value": "API"}], "SecurityGroups": [{"GroupId": "sg-1", "GroupName": "stale-name"}], "NetworkInterfaces": [{"NetworkInterfaceId": "eni-1", "Groups": [{"GroupId": "sg-2"}]}]},
        {"InstanceId": "i-2", "SecurityGroups": []},
    ], "security_groups": [{"GroupId": "sg-1", "GroupName": "exact-sg"}, {"GroupId": "sg-2", "GroupName": "eni-sg"}, {"GroupId": "sg-10", "GroupName": "wrong-prefix"}], "security_group_rules": [{"GroupId": "sg-1", "SecurityGroupRuleId": "rule-1"}, {"GroupId": "sg-2", "SecurityGroupRuleId": "rule-2"}, {"GroupId": "sg-10", "SecurityGroupRuleId": "wrong"}], "network_interfaces": [{"NetworkInterfaceId": "eni-1", "Groups": [{"GroupId": "sg-2"}]}], "vpcs": [{"VpcId": "vpc-1"}], "subnets": [{"SubnetId": "subnet-1"}]}), encoding="utf-8")
    service = AwsAssetService(tmp_path)
    result = service.list_instances(query="exact-sg", field="securityGroups")
    row = result["items"][0]
    assert row == {"name": "App", "instanceId": "i-1", "state": "running", "privateIp": "10.0.0.1", "publicIp": "-", "os": "Linux / CentOS", "description": "API", "securityGroups": [{"id": "sg-1", "name": "exact-sg"}, {"id": "sg-2", "name": "eni-sg"}]}
    optional = service.list_instances(query="i-2", field="instanceId")["items"][0]
    assert optional["name"] == optional["publicIp"] == optional["os"] == optional["description"] == "-"
    detail = service.detail("i-1")
    assert [item["GroupId"] for item in detail["securityGroups"]] == ["sg-1", "sg-2"]
    assert [item["SecurityGroupRuleId"] for item in detail["securityGroupRules"]] == ["rule-1", "rule-2"]
    assert detail["vpc"]["VpcId"] == "vpc-1" and detail["subnet"]["SubnetId"] == "subnet-1"


def test_scheduler_treats_aws_as_one_refresh_source(tmp_path: Path):
    class Refresh:
        def __init__(self): self.calls = 0
        def refresh_aws(self, progress): self.calls += 1; progress("AWS complete"); return {"counts": {"instances": 1}}

    refresh = Refresh(); service = SchedulerService(tmp_path, refresh)
    assert "aws" in service.TARGETS
    assert service._refresh_target("aws", datetime.now().date(), datetime.now().date()) == {"counts": {"instances": 1}}
    assert refresh.calls == 1
