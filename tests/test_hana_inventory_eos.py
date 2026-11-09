import json
from xml.etree import ElementTree as ET
from zipfile import ZipFile

import pytest

from backend.services.aws_export import AwsExportService
from backend.services.refresh import RefreshService
from backend.services.ssm_inventory import OutputParseError, parse_inventory
from test_ssm_inventory import SsmClient, collector, instances
from test_aws_assets import credentials
from test_aws_export_inventory import prepare, cells, text, NS, EC2_HEADERS, style_info


HANA = [
    (30, ['2.0 SP30 (2.00.030.00.1522209842)', '2.0 SP30 (2.00.030.00.1522210459)'], False, '2020-06-30'),
    (48, ['2.0 SP48 (2.00.048.02.1601540280)'], False, '2021-06-30'),
    (48, ['2.0 SP48 (2.00.048.02.1601540280)'], True, '2021-06-30'),
]


def hana_stdout(case):
    sp, versions, reverse, _ = case
    # Paths/hostname are synthetic; keep the reported whitespace/versions/record ordering.
    was = ['Tomcat|8.5.23|/srv/hana/xs/uaaserver/tomcat|running',
           'Tomcat|8.5.23 |META-INF/.sap_java_buildpack/tomcat|running']
    if reverse: was.reverse()
    db = [f'SAP HANA|{version}|/srv/hana/fixture-{index}|running' for index, version in enumerate(versions)]
    platform = '; '.join('HANA ' + version for version in versions)
    standard = ('HOSTNAME=fixture-hana\nKERNEL=fixture-kernel\nOS=SLES for SAP12 SP3\nOS_INSTALL_DATE=N/A\n' +
                '\n'.join('WAS=' + value for value in was) + '\nWEB=None\n' +
                '\n'.join('DB=' + value for value in db) + '\nWAS_PLATFORM=Java 1.8.0_162\nWEB_PLATFORM=None\nDB_PLATFORM=' + platform)
    raw = 'SSM_RAW=PROC[fixture]||REC_WAS[\n' + '\n'.join(was) + '\n]||REC_DB[\n' + '\n'.join(db) + '\n]'
    return standard, raw


def catalogs(root):
    env = root / 'env'; env.mkdir(exist_ok=True)
    (env / 'os_eos').write_text('SLES|12=2024-10-31\nSLES|12 SP3=2019-06-30\nUbuntu|24.04=2029-05-31\n')
    (env / 'db_eos').write_text('SAP HANA|2.0 SP30=2020-06-30\nSAP HANA|2.0 SP48=2021-06-30\nOracle|12.1=2022-07-31\nMariaDB|10.2=2022-05-23\n')


@pytest.mark.parametrize('case', HANA)
def test_reported_hana_records_whitespace_parentheses_and_raw_are_valid(case):
    standard, raw = hana_stdout(case)
    before = parse_inventory(standard)
    assert parse_inventory(standard + '\n' + raw) == before
    assert len(before['was']) == 2
    assert all(item['version'] == '8.5.23' for item in before['was'])
    assert [item['version'] for item in before['db']] == case[1]
    assert before['was_platform'] == 'Java 1.8.0_162'


def test_three_hana_shapes_force_refresh_cache_excel_eos_and_diagnostics(tmp_path, monkeypatch):
    exporter, data = prepare(tmp_path); catalogs(tmp_path); credentials(tmp_path)
    client = SsmClient(3)
    client.information = {item['InstanceId']: {'InstanceId': item['InstanceId'], 'PlatformType': 'Linux', 'PingStatus': 'Online'} for item in data['instances']}
    for instance, case in zip(data['instances'], HANA):
        standard, raw = hana_stdout(case)
        client.outputs[instance['InstanceId']] = standard + '\n' + raw
    service = RefreshService(tmp_path, ssm_factory=lambda _: client)
    assert service.refresh_ssm_inventory(lambda _: None) == {'ssm': 'success'}
    cache = json.loads((tmp_path / 'cache/aws.json').read_text())
    records = cache['ssm_inventory']['instances']
    raw_files = list((tmp_path / 'runtime/ssm_raw').glob('*.txt'))
    assert len(raw_files) == 1
    diagnostic = raw_files[0].read_text()
    assert diagnostic.count('Parse Status: Success') == 3
    assert 'was=2, web=0, db=2' in diagnostic
    assert 'REC_WAS' not in json.dumps(records)
    import boto3
    import requests
    monkeypatch.setattr(boto3, 'client', lambda *a, **kw: pytest.fail('Export called AWS/SSM'))
    monkeypatch.setattr(requests.sessions.Session, 'request', lambda *a, **kw: pytest.fail('Export called internet'))
    spec, interfaces = exporter._ec2_sheets(cache)
    assert list(spec['headers'].values()) == EC2_HEADERS
    for instance, case, row in zip(data['instances'], HANA, spec['rows']):
        record = records[instance['InstanceId']]
        assert record['status'] == 'success' and record['last_success_at']
        assert row['kernel'] == 'fixture-kernel'
        assert row['was'] == 'Tomcat 8.5.23; Tomcat 8.5.23'
        assert row['wasPlatform'] == 'Java 1.8.0_162' and row['web'] == row['webPlatform'] == '-'
        assert row['db'] == '; '.join(['SAP HANA'] * len(case[1]))
        assert row['dbEos'] == '; '.join([case[3]] * len(case[1]))
        assert row['osEos'] == '2019-06-30'
        assert row['dbPlatform'] == record['db_platform']
    result = exporter.build('aws_ec2')
    with ZipFile(result['path']) as archive:
        sheet = ET.fromstring(archive.read('xl/worksheets/sheet1.xml')); refs = cells(sheet)
        styles = ET.fromstring(archive.read('xl/styles.xml'))
        assert text(refs['P2']) == '2019-06-30'
        assert text(refs['W2']) == '2020-06-30; 2020-06-30'
        assert text(refs['W3']) == text(refs['W4']) == '2021-06-30'
        assert text(refs['R2']) == 'Java 1.8.0_162' and text(refs['Q2']) != '-'
        assert style_info(styles, refs['AB2'])[:3] == ('FF228B46', 'FFFFFFFF', True)
        assert sheet.find('m:autoFilter', NS).attrib['ref'] == 'A1:AD4'
    # New local EOS values do not affect ENIs or SG sheets.
    assert exporter._ec2_sheets({**cache, 'ssm_inventory': {}})[1] == interfaces
    assert exporter._sg_sheets(cache) == exporter._sg_sheets(data)


@pytest.mark.parametrize('bad,kind,count,flags', [
    ('WAS=Tomcat|8.5.23|/PRIVATE/path', 'WAS', 3, 'product=true, version=true, status=false'),
    ('DB=SAP HANA|2.0 SP48 (2.00.048.02)|/PRIVATE/path|running|extra', 'DB', 5, 'product=true, version=true, status=true'),
    ('WEB=|2.4|/PRIVATE/path|running', 'WEB', 4, 'product=false, version=true, status=true'),
])
def test_exact_invalid_product_paths_are_reproduced_with_private_metadata_only(tmp_path, caplog, bad, kind, count, flags):
    client = SsmClient(1); identifier = instances(1)[0]['InstanceId']
    standard, _ = hana_stdout(HANA[0])
    output = standard + '\n' + bad + '\nSSM_RAW=fixture-safe'
    with pytest.raises(OutputParseError) as caught: parse_inventory(output)
    assert caught.value.reason == 'invalid_product_record'
    assert caught.value.record_key.upper() == kind and caught.value.field_count == count
    client.outputs[identifier] = output
    result = collector(tmp_path, client).collect(instances(1), force=True)
    assert result['instances'][identifier]['error'] == 'invalid_product_record'
    content = next((tmp_path / 'runtime/ssm_raw').glob('*.txt')).read_text()
    assert 'Status: Success' in content and 'Response Code: 0' in content
    assert 'Parse Status: Failed' in content and 'Parse Error: invalid_product_record' in content
    assert f'Invalid Record Key: {kind}' in content and f'Invalid Record Field Count: {count}' in content
    assert 'Invalid Record Fields Present: ' + flags in content
    assert f'Output Length: {len(output)}' in content and 'Keys Present: hostname=true' in content
    assert 'Record Counts: was=' in content
    assert '/PRIVATE/path' not in content + caplog.text + json.dumps(result)
    assert 'HOSTNAME=fixture-hana' not in content
