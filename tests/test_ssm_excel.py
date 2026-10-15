import copy
import json
from zipfile import ZipFile
from xml.etree import ElementTree as ET

import pytest

from backend.services.aws_export import AwsExportService, core_agent_version
from test_aws_export_inventory import prepare, NS, cells, text, style_info
from test_ssm_inventory import LINUX, validate_inventory


@pytest.mark.parametrize('endpoint,version', [
    ({'modules': [{'name': 'other', 'version': 'x'}, {'name': 'coreAgent', 'version': '2026.1-fixture'}], 'assignedProducts': [{'code': 'coreAgent', 'status': 'installed', 'version': 'fallback'}]}, '2026.1-fixture'),
    ({'assignedProducts': [{'code': 'coreAgent', 'status': 'installed', 'version': 'FTS fixture-version'}]}, 'FTS fixture-version'),
    ({'assignedProducts': [{'code': 'coreAgent', 'status': 'notInstalled', 'version': 'wrong'}]}, '-'),
    ({'modules': [{'name': 'coreAgent', 'version': 'unknown'}]}, '-'), ({}, '-'), (None, '-'),
])
def test_core_agent_version_priority_and_absence(endpoint, version):
    assert core_agent_version(endpoint) == version


def test_excel_ssm_join_exact_primary_ip_and_style_cache_only(tmp_path, monkeypatch):
    exporter, data = prepare(tmp_path)
    first, second, third = data['instances']
    inventory = {**validate_inventory(json.loads(LINUX)), 'status': 'stale', 'last_success_at': '2026-10-14T09:00:00+09:00', 'platform_type': 'Linux'}
    inventory['was'].append({'product': 'SecondApp', 'version': None})
    inventory['web'].append({'product': 'SecondWeb', 'version': 'N/A'})
    inventory['db'].append({'product': 'PostgreSQL', 'version': '12.3'})
    data['ssm_inventory'] = {'instances': {first['InstanceId']: inventory, 'i-unrelated-fixture': {'hostname': 'must-not-join', 'status': 'success'}}}
    endpoints = [{'hostname': 'exact-primary', 'ipv4Addresses': [first['PrivateIpAddress']], 'modules': [{'name': 'coreAgent', 'version': 'fixture-version'}]},
                 {'hostname': 'not-primary', 'ipv4Addresses': ['10.0.0.11'], 'modules': [{'name': 'coreAgent', 'version': 'wrong-secondary'}]},
                 {'hostname': third.get('PrivateDnsName', 'hostname-only'), 'ipv4Addresses': ['192.0.2.123'], 'modules': [{'name': 'coreAgent', 'version': 'wrong-hostname'}]}]
    (tmp_path / 'cache/aws.json').write_text(json.dumps(data))
    (tmp_path / 'cache/endpoints.json').write_text(json.dumps(endpoints))
    import boto3
    monkeypatch.setattr(boto3, 'client', lambda *_args, **_kwargs: pytest.fail('Export called AWS/SSM'))
    import requests
    monkeypatch.setattr(requests.sessions.Session, 'request', lambda *_args, **_kwargs: pytest.fail('Export called external API'))
    spec, interfaces = exporter._ec2_sheets(data)
    row = spec['rows'][0]
    assert row['hostname'] == 'fixture-linux' and row['os'] == 'Linux' and row['osType'] == 'Example Linux 1'
    assert row['kernel'] == '6.1-fixture' and row['installedAt'] == '-'
    assert row['was'] == 'Tomcat 9.0.1; SecondApp' and row['web'] == 'Tengine 1.2; SecondWeb'
    assert row['db'] == 'MySQL; PostgreSQL' and row['dbPlatform'] == '-; PostgreSQL 12.3'
    assert row['osEos'] == row['dbEos'] == '-'
    assert row['antivirus'] == 'Sophos' and row['antivirusVersion'] == 'fixture-version'
    assert spec['rows'][2]['antivirus'] == '미설치' and spec['rows'][2]['antivirusVersion'] == '-'
    assert list(spec['headers'].values())[-3:] == ['Status', 'Anti Virus', 'Anti Virus Version']
    assert interfaces == exporter._ec2_sheets({**data, 'ssm_inventory': {}})[1]
    result = exporter.build('aws_ec2')
    assert result['sheets'] == ['EC2 List', 'Network Interfaces']
    with ZipFile(result['path']) as archive:
        sheet = ET.fromstring(archive.read('xl/worksheets/sheet1.xml'))
        styles = ET.fromstring(archive.read('xl/styles.xml'))
        refs = cells(sheet)
        assert text(refs['AA1']) == 'Anti Virus' and text(refs['AB1']) == 'Anti Virus Version'
        assert text(refs['AB2']) == 'fixture-version'
        assert sheet.find('m:autoFilter', NS).attrib['ref'].startswith('A1:AB')
        assert style_info(styles, refs['AA2'])[:3] == ('FF2463B5', 'FFFFFFFF', True)
        assert style_info(styles, refs['AB2'])[:3] == ('FFFFFFFF', 'FF000000', False)


def test_primary_ip_exact_no_secondary_or_hostname_antivirus_match(tmp_path):
    exporter, data = prepare(tmp_path)
    instance = copy.deepcopy(data['instances'][0])
    instance['PrivateIpAddress'] = '192.0.2.10'
    instance['PrivateDnsName'] = 'same-host'
    for addresses in [['192.0.2.100'], ['10.0.0.11']]:
        (tmp_path / 'cache/endpoints.json').write_text(json.dumps([{'hostname': 'same-host', 'ipv4Addresses': addresses, 'modules': [{'name': 'coreAgent', 'version': 'must-not-match'}]}]))
        row = AwsExportService(tmp_path)._ec2_sheets({**data, 'instances': [instance]})[0]['rows'][0]
        assert row['antivirus'] == '미설치' and row['antivirusVersion'] == '-'
        assert row['hostname'] == 'same-host'  # Legacy hostname display fallback remains.


def test_windows_columns_and_unknown_single_db_platform(tmp_path):
    from test_ssm_inventory import WINDOWS
    exporter, data = prepare(tmp_path)
    identifier = data['instances'][0]['InstanceId']
    record = {**validate_inventory(json.loads(WINDOWS)), 'status': 'success', 'platform_type': 'Windows', 'last_success_at': '2026-10-15T09:00:00+09:00'}
    record['db'] = [{'product': 'FixtureDB', 'version': None}]
    data['ssm_inventory'] = {'instances': {identifier: record}}
    row = exporter._ec2_sheets(data)[0]['rows'][0]
    assert row['os'] == 'Windows' and row['osType'] == 'Example Windows Server'
    assert row['installedAt'] == '2025-01-02 03:04:05' and row['kernel'] == '10.0.fixture'
    assert row['was'] == '-' and row['web'] == 'IIS 10.0'
    assert row['db'] == 'FixtureDB' and row['dbPlatform'] == '-'
    record['hostname'] = None
    assert exporter._ec2_sheets(data)[0]['rows'][0]['hostname'] == 'host-from-sophos'
