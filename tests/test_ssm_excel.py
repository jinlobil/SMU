import copy
import json
from zipfile import ZipFile
from xml.etree import ElementTree as ET

import pytest

from backend.services.aws_export import AwsExportService, core_agent_version
from test_aws_export_inventory import prepare, NS, cells, text, style_info
from test_ssm_inventory import LINUX, parse_inventory


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
    inventory = {**parse_inventory(LINUX), 'status': 'stale', 'last_success_at': '2026-10-14T09:00:00+09:00', 'platform_type': 'Linux'}
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
    assert row['osEos'] == '-'
    assert row['dbEos'] == '-; -'  # One unmatched EOS placeholder per DB, preserving order.
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
        assert text(refs['AE1']) == 'Anti Virus' and text(refs['AF1']) == 'Anti Virus Version'
        assert text(refs['AF2']) == 'fixture-version'
        assert sheet.find('m:autoFilter', NS).attrib['ref'].startswith('A1:AF')
        assert style_info(styles, refs['AE2'])[:3] == ('FF2463B5', 'FFFFFFFF', True)
        assert style_info(styles, refs['AF2'])[:3] == ('FFFFFFFF', 'FF000000', False)


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
    record = {**parse_inventory(WINDOWS), 'status': 'success', 'platform_type': 'Windows', 'last_success_at': '2026-10-15T09:00:00+09:00'}
    record['db'] = [{'product': 'FixtureDB', 'version': None}]
    data['ssm_inventory'] = {'instances': {identifier: record}}
    row = exporter._ec2_sheets(data)[0]['rows'][0]
    assert row['os'] == 'Windows' and row['osType'] == 'Example Windows Server'
    assert row['installedAt'] == '2025-01-02 03:04:05' and row['kernel'] == '10.0.fixture'
    assert row['was'] == '-' and row['web'] == 'IIS 10.0'
    assert row['db'] == 'FixtureDB' and row['dbPlatform'] == '-'
    record['hostname'] = None
    assert exporter._ec2_sheets(data)[0]['rows'][0]['hostname'] == 'host-from-sophos'


def test_eos_multiple_db_order_placeholders_and_local_files_only_real_xlsx(tmp_path, monkeypatch):
    from test_hana_inventory_eos import catalogs
    exporter, data = prepare(tmp_path); catalogs(tmp_path)
    record = {**parse_inventory('HOSTNAME=fixture\nKERNEL=fixture-kernel\nOS=Ubuntu 24.04.5 LTS\n'
                               'WAS=None\nWEB=None\nDB=Oracle|12.1.0|/srv/oracle|running\n'
                               'DB=UnknownDB|unknown|/srv/unknown|running\nDB=MariaDB|10.2.19|/srv/maria|running'),
              'status': 'stale', 'last_success_at': '2026-11-08T09:00:00+09:00'}
    # EOS must come from original DB records, never a reparsed display string.
    record['db_platform'] = 'different display text retained verbatim'
    data['ssm_inventory'] = {'instances': {data['instances'][0]['InstanceId']: record}}
    (tmp_path / 'cache/aws.json').write_text(json.dumps(data))
    import boto3
    import requests
    monkeypatch.setattr(boto3, 'client', lambda *a, **kw: pytest.fail('EOS export called AWS/SSM'))
    monkeypatch.setattr(requests.sessions.Session, 'request', lambda *a, **kw: pytest.fail('EOS export called internet'))
    row = exporter._ec2_sheets(data)[0]['rows'][0]
    assert row['db'] == 'Oracle; UnknownDB; MariaDB'
    assert row['dbPlatform'] == 'different display text retained verbatim'
    assert row['dbEos'] == '2022-07-31; -; 2022-05-23'
    with ZipFile(exporter.build('aws_ec2')['path']) as archive:
        refs = cells(ET.fromstring(archive.read('xl/worksheets/sheet1.xml')))
        assert text(refs['R2']) == '2029-05-31'
        assert text(refs['W2']) == 'Oracle; UnknownDB; MariaDB'
        assert text(refs['Y2']) == '2022-07-31; -; 2022-05-23'
    # Reusing an exporter must pick up the local operator file's new value.
    (tmp_path / 'env/os_eos').write_text('Ubuntu|24.04=2030-05-31\n')
    with ZipFile(exporter.build('aws_ec2')['path']) as archive:
        refs = cells(ET.fromstring(archive.read('xl/worksheets/sheet1.xml')))
        assert text(refs['R2']) == '2030-05-31'
    assert json.loads((tmp_path / 'cache/aws.json').read_text()) == data


def test_eos_does_not_fabricate_inventory_for_failed_first_attempt(tmp_path):
    from test_hana_inventory_eos import catalogs
    exporter, data = prepare(tmp_path); catalogs(tmp_path)
    data['ssm_inventory'] = {'instances': {data['instances'][0]['InstanceId']: {
        'status': 'failed', 'os': 'Ubuntu 24.04 LTS', 'db': [{'product': 'Oracle', 'version': '12.1.0'}]}}}
    row = exporter._ec2_sheets(data)[0]['rows'][0]
    assert row['osEos'] == row['dbEos'] == '-'


@pytest.mark.parametrize('platform,expected', [
    ('Win 2016 D.E', '2027-01-12'),
    ('Windows 2016 D.E', '2027-01-12'),
    ('SLES for SAP12 SP2', '2018-03-31'),
    ('SLES for SAP12 SP3', '2019-06-30'),
    ('SLES for SAP12 SP4', '2020-06-30'),
    ('SUSE 12', '2024-10-31'),
    ('DSM 6.2', '2024-10-01'),
])
@pytest.mark.parametrize('state', ['failed', 'missing', 'success_without_os'])
def test_os_eos_uses_final_platform_without_successful_ssm(tmp_path, monkeypatch, platform, expected, state):
    from pathlib import Path
    exporter, data = prepare(tmp_path)
    env = tmp_path / 'env'; env.mkdir(exist_ok=True)
    (env / 'os_eos').write_text((Path(__file__).resolve().parents[1] / 'env/os_eos').read_text())
    instance = data['instances'][0]
    instance['Tags'] = [tag for tag in instance.get('Tags', []) if tag['Key'] != 'OS_type']
    instance['Tags'].append({'Key': 'OS_type', 'Value': platform})
    if state != 'missing':
        record = {'status': 'failed', 'os': 'Ubuntu 24.04 LTS'}
        if state == 'success_without_os':
            record = {'status': 'success', 'last_success_at': '2026-11-09T09:00:00+09:00', 'os': None}
        data['ssm_inventory'] = {'instances': {instance['InstanceId']: record}}
    (tmp_path / 'cache/aws.json').write_text(json.dumps(data))
    import boto3
    import requests
    monkeypatch.setattr(boto3, 'client', lambda *a, **kw: pytest.fail('Export called AWS/SSM'))
    monkeypatch.setattr(requests.sessions.Session, 'request', lambda *a, **kw: pytest.fail('Export called API'))
    before = copy.deepcopy(data)
    row = exporter._ec2_sheets(data)[0]['rows'][0]
    assert row['osType'] == platform and row['osEos'] == expected
    assert row['dbEos'] == '-'
    with ZipFile(exporter.build('aws_ec2')['path']) as archive:
        refs = cells(ET.fromstring(archive.read('xl/worksheets/sheet1.xml')))
        assert text(refs['P2']) == platform
        assert text(refs['R2']) == expected
    assert data == before == json.loads((tmp_path / 'cache/aws.json').read_text())


def test_valid_ssm_os_precedes_aws_platform_for_eos(tmp_path):
    from test_hana_inventory_eos import catalogs
    exporter, data = prepare(tmp_path); catalogs(tmp_path)
    data['instances'][0]['Tags'].append({'Key': 'OS_type', 'Value': 'SUSE 12'})
    data['ssm_inventory'] = {'instances': {data['instances'][0]['InstanceId']: {
        'status': 'stale', 'last_success_at': '2026-11-08T09:00:00+09:00', 'os': 'SLES for SAP12 SP3'}}}
    row = exporter._ec2_sheets(data)[0]['rows'][0]
    assert row['osType'] == 'SLES for SAP12 SP3' and row['osEos'] == '2019-06-30'
