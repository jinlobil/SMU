import json
import zipfile
from pathlib import Path
from xml.etree import ElementTree

import pytest

from backend.services.aws_assets import AwsAssetService, AwsCollector
from backend.services.aws_export import AwsExportService


def payload():
    return {"metadata":{"region":"ap-northeast-2"},"instances":[
        {"InstanceId":"i-1","State":{"Name":"running"},"InstanceType":"t3.small","PrivateIpAddress":"10.0.0.1","PublicIpAddress":"203.0.113.1","VpcId":"vpc-1","SubnetId":"sub-1","Tags":[{"Key":"Name","Value":"web"}],"SecurityGroups":[{"GroupId":"sg-1"}],"NetworkInterfaces":[{"NetworkInterfaceId":"eni-1","Groups":[{"GroupId":"sg-1"}],"PrivateIpAddresses":[{"PrivateIpAddress":"10.0.0.1"}],"Attachment":{"DeviceIndex":0}}]},
        {"InstanceId":"i-2","State":{"Name":"stopped"},"PrivateIpAddress":"10.0.0.2","Tags":[{"Key":"Name","Value":"batch"}],"NetworkInterfaces":[{"NetworkInterfaceId":"eni-2","Groups":[{"GroupId":"sg-1"},{"GroupId":"sg-1"}]}]},
        {"InstanceId":"i-3","State":{"Name":"pending"},"NetworkInterfaces":[]}],
        "security_groups":[{"GroupId":"sg-1","GroupName":"application","VpcId":"vpc-1","Description":"app"},{"GroupId":"sg-2","GroupName":"database","VpcId":"vpc-1"}],
        "security_group_rules":[
            {"GroupId":"sg-1","SecurityGroupRuleId":"r-in","IsEgress":False,"IpProtocol":"tcp","FromPort":443,"ToPort":8443,"CidrIpv4":"10.0.0.0/8"},
            {"GroupId":"sg-1","SecurityGroupRuleId":"r-out","IsEgress":True,"IpProtocol":"-1","CidrIpv6":"::/0"},
            {"GroupId":"sg-2","SecurityGroupRuleId":"r-icmp","IsEgress":False,"IpProtocol":"icmp","FromPort":8,"ToPort":0,"ReferencedGroupInfo":{"GroupId":"sg-1"}}],
        "network_interfaces":[],"vpcs":[],"subnets":[]}


def service(tmp_path: Path):
    path=tmp_path/"cache/aws.json";path.parent.mkdir();path.write_text(json.dumps(payload()),encoding="utf-8");return AwsAssetService(tmp_path)


def test_ec2_summary_is_independent_from_search(tmp_path):
    target=service(tmp_path); result=target.list_instances(query="web")
    assert result["pagination"]["total"]==1
    assert result["summary"]=={"total":3,"running":1,"stopped":1,"other":1}


def test_sg_summary_search_deduplication_and_rule_rendering(tmp_path):
    target=service(tmp_path); result=target.list_security_groups(query="batch")
    assert result["summary"]=={"total":2,"attached":1,"rules":3,"notAttached":1}
    assert result["items"][0]["groupId"]=="sg-1" and result["items"][0]["instances"]==2
    detail=target.security_group_detail("sg-1")
    assert detail["summary"]=={"inbound":1,"outbound":1,"instances":2}
    assert detail["inbound"][0]["port"]=="443-8443"
    assert detail["outbound"][0]["protocol"]==detail["outbound"][0]["port"]=="ALL"
    referenced=target.security_group_detail("sg-2")["inbound"][0]
    assert referenced["protocol"]=="ICMP" and referenced["port"]=="Type 8 / Code 0"
    assert referenced["target"]=="application (sg-1)"


def test_aws_exports_have_required_valid_sheets_and_zero_data_headers(tmp_path):
    service(tmp_path); exporter=AwsExportService(tmp_path)
    ec2=exporter.build("aws_ec2"); sg=exporter.build("aws_sg")
    assert ec2["sheets"]==["EC2 List","Network Interfaces"]
    assert sg["sheets"]==["SG Summary","Inbound Rules","Outbound Rules","EC2 Mapping"]
    for result in (ec2,sg):
        with zipfile.ZipFile(result["path"]) as archive:
            ElementTree.fromstring(archive.read("xl/workbook.xml"))
            for name in [entry for entry in archive.namelist() if entry.startswith("xl/worksheets/")]: ElementTree.fromstring(archive.read(name))
    empty=tmp_path/"cache/aws.json";empty.write_text(json.dumps({"metadata":{},"instances":[],"security_groups":[],"security_group_rules":[]}),encoding="utf-8")
    assert AwsExportService(tmp_path).build("aws_sg")["sheets"]==["SG Summary","Inbound Rules","Outbound Rules","EC2 Mapping"]


class AwsError(Exception):
    def __init__(self, code): self.response={"Error":{"Code":code}}


@pytest.mark.parametrize("code,message",[("InvalidClientTokenId","AWS API 인증 실패"),("UnauthorizedOperation","AWS API 조회 권한 없음"),("Throttling","AWS API 호출 제한"),("RequestTimeout","AWS API 통신 실패")])
def test_safe_aws_error_classification(tmp_path,code,message,caplog):
    env=tmp_path/"env";env.mkdir();(env/"aws_env.txt").write_text("AWS_ACCESS_KEY_ID=x\nAWS_SECRET_ACCESS_KEY=y\nAWS_REGION=r\n")
    class Client:
        def get_paginator(self,operation): raise AwsError(code)
    with pytest.raises(RuntimeError,match=message): AwsCollector(tmp_path,lambda _credentials:Client()).collect()
    assert "operation=describe_instances" in caplog.text and code in caplog.text and "AWS_SECRET" not in caplog.text


def test_boto3_missing_has_actionable_message(tmp_path,monkeypatch):
    env=tmp_path/"env";env.mkdir();(env/"aws_env.txt").write_text("AWS_ACCESS_KEY_ID=x\nAWS_SECRET_ACCESS_KEY=y\nAWS_REGION=r\n")
    import builtins
    original=builtins.__import__
    def missing(name,*args,**kwargs):
        if name=="boto3": raise ModuleNotFoundError(name)
        return original(name,*args,**kwargs)
    monkeypatch.setattr(builtins,"__import__",missing)
    with pytest.raises(RuntimeError,match=r"AWS SDK\(boto3\) 설치 필요"): AwsCollector(tmp_path).collect()
