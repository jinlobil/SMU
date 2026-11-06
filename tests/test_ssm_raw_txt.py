import copy
import json
import re
from zipfile import ZipFile

import pytest

from backend.services.aws_assets import AwsAssetService
from backend.services.ssm_inventory import parse_inventory
from test_ssm_inventory import SsmClient, collector, instances, LINUX, WINDOWS
from test_aws_export_inventory import prepare


RAW = 'PROC[fixture=one]||TOMCAT_HOMES[/fixture/private]||REC_WAS[Tomcat]; 한글'


def txt_files(root):
    return sorted((root / 'runtime/ssm_raw').glob('*.txt'))


def test_force_one_txt_for_multiple_platforms_raw_only_and_no_extra_requests(tmp_path, caplog):
    caplog.set_level('INFO', logger='smu.aws.ssm')
    client = SsmClient(2); calls = []; actual = client.get_command_invocation
    client.outputs[instances()[0]['InstanceId']] = LINUX + '\nSSM_RAW=' + RAW
    client.outputs[instances()[1]['InstanceId']] = WINDOWS + '\r\nSSM_RAW=SERVICE[fixture]||REC_WAS[None]\r\n'
    def get(**kwargs): calls.append(kwargs.copy()); return actual(**kwargs)
    client.get_command_invocation = get
    target = collector(tmp_path, client)
    result = target.collect(instances(), force=True)
    files = txt_files(tmp_path)
    assert len(files) == 1 and re.fullmatch(r'ssm_raw_\d{8}_\d{6}\.txt', files[0].name)
    content = files[0].read_text(encoding='utf-8')
    assert 'Collected At: 2026-10-15 01:00:00' in content  # Fake clock UTC → Seoul.
    assert content.count('Instance ID:') == 2
    assert 'Platform: Linux' in content and 'Plugin: linuxInventory' in content
    assert 'Platform: Windows' in content and 'Plugin: windowsInventory' in content
    assert 'Command ID: fixture-command-' in content
    assert 'Status: Success' in content and 'Response Code: 0' in content
    assert 'SSM_RAW=' + RAW in content and 'SSM_RAW=SERVICE[fixture]||REC_WAS[None]' in content
    assert 'HOSTNAME=' not in content and 'WAS=Tomcat|' not in content and 'OS_INSTALL_DATE=' not in content
    assert len(client.sent) == len(calls) == 2
    assert all(set(call) == {'CommandId', 'InstanceId', 'PluginName'} for call in calls)
    assert all(request['DocumentName'] == 'LNL-ServerInventory' and 'Parameters' not in request for request in client.requests)
    assert 'SSM_RAW' not in json.dumps(result) and RAW not in json.dumps(result)
    assert RAW not in caplog.text and 'fixture-command-' not in caplog.text
    assert target._raw_records is None


def test_success_without_raw_and_terminal_failure_have_distinct_markers(tmp_path):
    client = SsmClient(2)
    client.responses[instances()[1]['InstanceId']] = {'Status': 'Failed', 'ResponseCode': 1, 'StandardOutputContent': ''}
    result = collector(tmp_path, client).collect(instances(), force=True)
    content = txt_files(tmp_path)[0].read_text()
    assert 'SSM_RAW: NOT_FOUND' in content and 'SSM_RAW: NOT_AVAILABLE' in content
    assert 'Status: Failed' in content and 'Response Code: 1' in content
    assert result['instances'][instances()[1]['InstanceId']]['error'] == 'terminal_failed'


def test_raw_is_captured_before_existing_parser_failure(tmp_path):
    client = SsmClient(1); identifier = instances(1)[0]['InstanceId']
    client.outputs[identifier] = 'SSM_RAW=' + RAW
    result = collector(tmp_path, client).collect(instances(1), force=True)
    assert result['instances'][identifier]['error'] == 'missing_hostname'
    assert 'SSM_RAW=' + RAW in txt_files(tmp_path)[0].read_text()


def test_normal_scheduler_refresh_does_not_create_raw_files(tmp_path):
    client = SsmClient(1); client.outputs[instances(1)[0]['InstanceId']] = LINUX + '\nSSM_RAW=' + RAW
    target = collector(tmp_path, client)
    assert target.collect(instances(1))['status'] == 'success'
    assert not (tmp_path / 'runtime/ssm_raw').exists() and target._raw_records is None


def test_same_second_force_refresh_creates_unique_files_and_never_rotates(tmp_path):
    client = SsmClient(1); target = collector(tmp_path, client)
    directory = tmp_path / 'runtime/ssm_raw'; directory.mkdir(parents=True)
    old = directory / 'ssm_raw_20000101_000000.txt'; old.write_text('preserved diagnostic')
    target.collect(instances(1), force=True)
    first = {path.name: path.read_bytes() for path in txt_files(tmp_path)}
    target.collect(instances(1), force=True)
    assert len(txt_files(tmp_path)) == 3
    assert all((directory / name).read_bytes() == value for name, value in first.items())
    assert (directory / 'ssm_raw_20261015_010000_1.txt').exists()


def test_empty_and_repeated_raw_values_only_exact_keys_are_extracted(tmp_path):
    client = SsmClient(1); client.outputs[instances(1)[0]['InstanceId']] = LINUX + '\nSSM_RAW=\nOTHER_SSM_RAW=not-captured\nSSM_RAW=second=value||entry'
    collector(tmp_path, client).collect(instances(1), force=True)
    content = txt_files(tmp_path)[0].read_text()
    assert '\nSSM_RAW=\n' in content and '\nSSM_RAW=second=value||entry\n' in content
    assert 'NOT_FOUND' not in content and 'not-captured' not in content


def test_discovery_failure_and_offline_instances_have_not_available(tmp_path, monkeypatch):
    client = SsmClient(2); identifier = instances()[0]['InstanceId']
    client.information[identifier]['PingStatus'] = 'Offline'
    target = collector(tmp_path, client)
    result = target.collect(instances(), force=True)
    assert result['instances'][identifier]['error'] == 'not_online'
    assert txt_files(tmp_path)[0].read_text().count('SSM_RAW: NOT_AVAILABLE') == 1
    monkeypatch.setattr(client, 'describe_instance_information', lambda **_: (_ for _ in ()).throw(RuntimeError('fixture')))
    target.collect(instances(), force=True)
    assert txt_files(tmp_path)[1].read_text().count('SSM_RAW: NOT_AVAILABLE') == 2


def test_disk_failure_does_not_change_collection_result_or_stale_policy(tmp_path, monkeypatch, caplog):
    client = SsmClient(1); target = collector(tmp_path, client)
    expected = target.collect(instances(1)); original = copy.deepcopy(expected)
    monkeypatch.setattr(target, '_save_raw_txt', lambda: (_ for _ in ()).throw(PermissionError('PRIVATE error detail')))
    result = target.collect(instances(1), force=True)
    assert result == expected and expected == original and target._raw_records is None
    assert 'error_type=PermissionError' in caplog.text and 'PRIVATE' not in caplog.text
    client.fail.add(instances(1)[0]['InstanceId'])
    stale = target.collect(instances(1), result, force=True)['instances'][instances(1)[0]['InstanceId']]
    assert stale['status'] == 'stale' and stale['was'] == original['instances'][instances(1)[0]['InstanceId']]['was']


def test_refresh_writes_one_file_without_cache_api_or_excel_raw_fields(tmp_path, monkeypatch):
    from backend.services.aws_export import AwsExportService
    exporter, data = prepare(tmp_path)
    client = SsmClient(1)
    identifier = data['instances'][0]['InstanceId']
    client.information = {identifier: {'InstanceId': identifier, 'PlatformType': 'Linux', 'PingStatus': 'Online'}}
    client.outputs[identifier] = LINUX + '\nSSM_RAW=' + RAW
    from backend.services.refresh import RefreshService
    target = RefreshService(tmp_path, ssm_factory=lambda _: client)
    from test_aws_assets import credentials
    credentials(tmp_path)
    result = target.refresh_ssm_inventory(lambda _: None)
    assert result == {'ssm': 'partial'}  # Other fixture EC2s are not SSM managed.
    assert len(txt_files(tmp_path)) == 1
    cache = (tmp_path / 'cache/aws.json').read_text()
    assert 'SSM_RAW' not in cache and RAW not in cache
    record = json.loads(cache)['ssm_inventory']['instances'][identifier]
    assert record['was'] == parse_inventory(LINUX)['was'] and record['web'] == parse_inventory(LINUX)['web']
    assert record['db'] == parse_inventory(LINUX)['db']
    assert 'SSM_RAW' not in json.dumps(AwsAssetService(tmp_path).detail(identifier))
    before = exporter.build('aws_ec2')
    with ZipFile(before['path']) as archive:
        before_sheets = {name: archive.read(name) for name in archive.namelist() if name.startswith('xl/worksheets/')}
        assert all(b'SSM_RAW' not in sheet and RAW.encode() not in sheet for sheet in before_sheets.values())
    # Removing only the diagnostic line cannot change any Inventory/Excel cell.
    client.outputs[identifier] = LINUX
    target.refresh_ssm_inventory(lambda _: None)
    after = exporter.build('aws_ec2')
    with ZipFile(after['path']) as archive:
        assert all(archive.read(name) == value for name, value in before_sheets.items())
    assert len(txt_files(tmp_path)) == 2
