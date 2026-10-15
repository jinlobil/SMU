import copy
from datetime import datetime, timedelta, timezone
import json
import threading

import pytest

from backend.services.ssm_inventory import DOCUMENT, SsmInventoryCollector, parse_inventory
from test_aws_assets import credentials

LINUX = 'HOSTNAME=fixture-linux\nKERNEL=6.1-fixture\nOS=Example Linux 1\nOS_INSTALL_DATE=N/A\nWAS=Tomcat|9.0.1|/srv/app|running\nWEB=Tengine|1.2|/srv/web|running\nDB=MySQL|unknown|/srv/db|running'
WINDOWS = 'HOSTNAME=fixture-windows\nKERNEL=10.0.fixture\nOS=Example Windows Server\nOS_INSTALL_DATE=2025-01-02 03:04:05\nWEB=IIS|10.0|C:\\Windows\\inetsrv|running\nWAS=None\nDB=None'
TODAY = datetime(2026, 10, 14, 16, tzinfo=timezone.utc)  # Seoul 15th


def instances(count=2):
    return [{'InstanceId': f'i-fixture-{number:03}'} for number in range(count)]


class MissingInvocation(Exception):
    response = {'Error': {'Code': 'InvocationDoesNotExist'}}


class SsmClient:
    def __init__(self, count=2):
        self.information = {item['InstanceId']: {'InstanceId': item['InstanceId'], 'PingStatus': 'Online',
            'PlatformType': 'Windows' if number % 2 else 'Linux', 'AssociationStatus': 'Failed'} for number, item in enumerate(instances(count))}
        self.sent, self.plugins, self.filters = [], [], []
        self.fail, self.pending, self.missing, self.skip = set(), set(), set(), set()
        self.lock = threading.Lock()
        self.active, self.peak = 0, 0

    def describe_instance_information(self, **kwargs):
        self.filters.append(kwargs)
        ids = kwargs['Filters'][0]['Values']
        # Include a hybrid/foreign managed node to prove it is never targeted.
        return {'InstanceInformationList': [*self.information.values(), {'InstanceId': 'mi-fixture', 'PingStatus': 'Online', 'PlatformType': 'Linux'}]}

    def send_command(self, **kwargs):
        assert kwargs['DocumentName'] == DOCUMENT == 'LNL-ServerInventory'
        assert 'Parameters' not in kwargs and len(kwargs['InstanceIds']) == 1
        identifier = kwargs['InstanceIds'][0]
        self.sent.append(identifier)
        return {'Command': {'CommandId': identifier}}

    def list_command_invocations(self, **kwargs):
        assert kwargs['Details'] is True
        identifier = kwargs['InstanceId']
        return {'CommandInvocations': [{'InstanceId': identifier, 'CommandId': kwargs['CommandId'],
                'CommandPlugins': [{'Name': 'actual-step-fixture', 'Status': 'Success'}]}]}

    def get_command_invocation(self, **kwargs):
        identifier = kwargs['InstanceId']
        self.plugins.append(kwargs.get('PluginName'))
        assert 'PluginName' not in kwargs
        if identifier in self.fail: raise RuntimeError('fixture failure')
        if identifier in self.missing:
            self.missing.remove(identifier); raise MissingInvocation()
        if identifier in self.pending: return {'Status': 'InProgress'}
        output = WINDOWS if self.information[identifier]['PlatformType'] == 'Windows' else LINUX
        if identifier in self.skip: output = 'Step execution skipped due to unsupported plugin: aws:runShellScript'
        return {'Status': 'Success', 'ResponseCode': 0, 'StandardOutputContent': output}


def collector(root, client, now=TODAY):
    credentials(root)
    return SsmInventoryCollector(root, lambda _: client, now=lambda: now, poll_interval=0, sleep=lambda _: None)


@pytest.mark.parametrize('output,name,os_date', [(LINUX, 'fixture-linux', None), (WINDOWS, 'fixture-windows', '2025-01-02 03:04:05')])
def test_platform_output_parser(output, name, os_date):
    row = parse_inventory(output)
    assert row['hostname'] == name and row['os_install_date'] == os_date
    assert 'HOSTNAME=' not in json.dumps(row)
    if output == WINDOWS: assert row['was'] == row['db'] == []
    else: assert row['db'][0]['version'] is None


@pytest.mark.parametrize('version', ['unknown', 'N/A', '', 'null'])
def test_null_versions_and_repeated_products(version):
    row = parse_inventory(f'HOSTNAME=fixture\nOS=Example\nWAS=App|{version}|/a|running\nWAS=App2|2|/b|running\nWEB=None\nWEB=Web|3|/c|running\nWEB=Web2|4|/d|running\nDB=None\nDB=DB1|{version}|/e|running\nDB=DB2|5|/f|running')
    assert row['was'][0]['version'] is row['db'][0]['version'] is None
    assert len(row['was']) == len(row['web']) == len(row['db']) == 2


def test_seoul_date_same_day_new_instance_and_next_day(tmp_path):
    client = SsmClient()
    target = collector(tmp_path, client)
    cache = target.collect(instances())
    assert cache['snapshot_date'] == '2026-10-15' and cache['status'] == 'success'
    assert len(client.sent) == 2 and set(client.plugins) == {None}
    original = copy.deepcopy(cache)
    client.sent.clear()
    input_cache = cache
    cache = target.collect(instances(), cache)
    assert input_cache == original
    assert client.sent == [] and cache['collected_at'] == original['collected_at']
    client.information.update(SsmClient(3).information)
    cache = target.collect(instances(3), cache)
    assert client.sent == [instances(3)[-1]['InstanceId']]
    client.sent.clear()
    cache = collector(tmp_path, client, TODAY + timedelta(days=1)).collect(instances(3), cache)
    assert len(client.sent) == 3 and cache['snapshot_date'] == '2026-10-16'


@pytest.mark.parametrize('state', ['ConnectionLost', 'Offline', 'Unknown'])
def test_new_offline_instance_is_not_executed(tmp_path, state):
    client = SsmClient(); target = collector(tmp_path, client)
    cache = target.collect(instances())
    client.information.update(SsmClient(3).information)
    identifier = instances(3)[-1]['InstanceId']
    client.information[identifier]['PingStatus'] = state
    client.sent.clear()
    result = target.collect(instances(3), cache)
    assert client.sent == [] and result['instances'][identifier]['status'] == 'failed'


def test_same_date_force_collects_all_online_but_not_hybrid(tmp_path):
    client = SsmClient(); target = collector(tmp_path, client)
    cache = target.collect(instances())
    client.sent.clear()
    result = collector(tmp_path, client, TODAY + timedelta(hours=2)).collect(instances(), cache, force=True)
    assert set(client.sent) == {item['InstanceId'] for item in instances()}
    assert result['collected_at'] != cache['collected_at']


@pytest.mark.parametrize('failure', ['fail', 'pending', 'skip'])
def test_failure_preserves_last_good_values_without_same_day_retry(tmp_path, failure):
    client = SsmClient(); target = collector(tmp_path, client)
    cache = target.collect(instances())
    identifier = instances()[0]['InstanceId']
    getattr(client, failure).add(identifier)
    result = collector(tmp_path, client, TODAY + timedelta(days=1)).collect(instances(), cache)
    record = result['instances'][identifier]
    assert record['status'] == 'stale'
    for key in ('was', 'web', 'db', 'hostname', 'kernel', 'last_success_at'):
        assert record[key] == cache['instances'][identifier][key]
    assert record['last_attempt_at'] != cache['instances'][identifier]['last_attempt_at']
    client.sent.clear()
    collector(tmp_path, client, TODAY + timedelta(days=1)).collect(instances(), result)
    assert client.sent == []


def test_invocation_missing_retries_and_skip_never_parses_success(tmp_path):
    client = SsmClient(); identifier = instances()[0]['InstanceId']; client.missing.add(identifier)
    assert collector(tmp_path, client).collect(instances())['status'] == 'success'
    client.skip.add(identifier)
    result = collector(tmp_path, client).collect(instances(), force=True)
    assert result['instances'][identifier]['status'] == 'failed'
    assert result['instances'][identifier].get('hostname') is None


def test_small_concurrency(tmp_path):
    client = SsmClient(12)
    actual = client.get_command_invocation
    barrier = threading.Barrier(5)
    def invocation(**kwargs):
        with client.lock:
            client.active += 1; client.peak = max(client.active, client.peak)
            first = len(client.plugins) < 5
            client.plugins.append('started')
        if first: barrier.wait(timeout=5)
        try: return actual(**kwargs)
        finally:
            with client.lock: client.active -= 1
    client.get_command_invocation = invocation
    assert collector(tmp_path, client).collect(instances(12))['status'] == 'success'
    assert client.peak <= 5 and len(client.sent) == 12


def test_date_boundary_is_not_24_hour_ttl(tmp_path):
    client = SsmClient()
    before_midnight = datetime(2026, 10, 14, 14, 59, tzinfo=timezone.utc)
    cache = collector(tmp_path, client, before_midnight).collect(instances())
    client.sent.clear()
    after = collector(tmp_path, client, before_midnight + timedelta(minutes=2)).collect(instances(), cache)
    assert len(client.sent) == 2 and after['snapshot_date'] == '2026-10-15'
    client.sent.clear()
    collector(tmp_path, client, before_midnight + timedelta(hours=20)).collect(instances(), after)
    assert client.sent == []


def test_discovery_failure_preserves_good_cache_and_no_raw_output(tmp_path, monkeypatch):
    client = SsmClient(); target = collector(tmp_path, client)
    cache = target.collect(instances())
    def failed(**_): raise RuntimeError('raw fixture response must never be saved')
    monkeypatch.setattr(client, 'describe_instance_information', failed)
    result = target.collect(instances(), cache, force=True)
    assert result['status'] == 'stale'
    assert result['instances'][instances()[0]['InstanceId']]['was'] == cache['instances'][instances()[0]['InstanceId']]['was']
    assert 'raw fixture response' not in json.dumps(result)
    assert 'StandardOutputContent' not in json.dumps(result)


def test_discovery_paginates_and_bounds_filters(tmp_path):
    client = SsmClient(52); calls = []
    def describe(**kwargs):
        calls.append(kwargs.copy())
        ids = kwargs['Filters'][0]['Values']
        if not kwargs.get('NextToken'):
            return {'InstanceInformationList': [client.information[ids[0]]], 'NextToken': 'fixture-next'}
        return {'InstanceInformationList': [client.information[key] for key in ids[1:]]}
    client.describe_instance_information = describe
    assert collector(tmp_path, client).collect(instances(52))['status'] == 'success'
    assert [len(call['Filters'][0]['Values']) for call in calls] == [50, 50, 2, 2]
    assert len(client.sent) == 52


def test_same_day_cache_does_not_even_create_ssm_client(tmp_path, monkeypatch):
    client = SsmClient(); target = collector(tmp_path, client)
    cache = target.collect(instances())
    monkeypatch.setattr(target, '_client', lambda: pytest.fail('Unnecessary SSM lookup'))
    assert target.collect(instances(), cache)['status'] == 'success'


def test_only_missing_instance_ids_are_queried(tmp_path):
    client = SsmClient(); target = collector(tmp_path, client)
    cache = target.collect(instances())
    client.information.update(SsmClient(3).information)
    client.filters.clear()
    target.collect(instances(3), cache)
    assert client.filters[0]['Filters'] == [{'Key': 'InstanceIds', 'Values': [instances(3)[-1]['InstanceId']]}]


def test_failed_new_platform_attempt_preserves_entire_last_success(tmp_path):
    client = SsmClient(); target = collector(tmp_path, client)
    cache = target.collect(instances())
    identifier = instances()[0]['InstanceId']
    client.information[identifier]['PlatformType'] = 'Windows'
    client.fail.add(identifier)
    result = target.collect(instances(), cache, force=True)
    record = result['instances'][identifier]
    assert record['status'] == 'stale'
    for key in ['platform_type', 'hostname', 'kernel', 'os', 'os_install_date', 'was', 'web', 'db', 'last_success_at']:
        assert record[key] == cache['instances'][identifier][key]
    assert client.plugins and all(plugin is None for plugin in client.plugins)


@pytest.mark.parametrize('output', [WINDOWS, LINUX])
def test_bom_crlf_whitespace_and_product_fields(output):
    decorated = '\ufeff' + '\r\n'.join('  ' + line + '  ' for line in output.splitlines())
    assert parse_inventory(decorated) == parse_inventory(output)
    if output == WINDOWS:
        assert parse_inventory(decorated)['web'][0] == {
            'product': 'IIS', 'version': '10.0', 'path': r'C:\Windows\inetsrv', 'status': 'running'}


def test_s3_output_url_is_not_a_failure(tmp_path):
    client = SsmClient(); original = client.get_command_invocation
    def invocation(**kwargs):
        return {**original(**kwargs), 'StandardOutputUrl': 'https://example.invalid/sensitive-output'}
    client.get_command_invocation = invocation
    assert collector(tmp_path, client).collect(instances())['status'] == 'success'


@pytest.mark.parametrize('kind,stage,reason,status,code', [
    ('send', 'send_command', 'send_command_failed', None, None),
    ('get', 'get_command_invocation', 'get_command_invocation_failed', None, None),
    ('missing', 'get_command_invocation', 'invocation_not_found_timeout', None, None),
    ('pending', 'get_command_invocation', 'invocation_poll_timeout', 'InProgress', -1),
    ('failed', 'terminal_status', 'terminal_failed', 'Failed', 1),
    ('timedout', 'terminal_status', 'terminal_timed_out', 'TimedOut', -1),
    ('nonzero', 'terminal_status', 'response_code_nonzero', 'Success', 2),
    ('parse', 'parse', 'parse_failed', 'Success', 0),
    ('truncated', 'parse', 'output_may_be_truncated', 'Success', 0),
])
def test_failure_diagnostics_and_cache_are_safe(tmp_path, caplog, kind, stage, reason, status, code):
    client = SsmClient(1)
    class AwsFailure(Exception):
        response = {'Error': {'Code': 'AccessDeniedException'}}
    def fail(**kwargs): raise AwsFailure('SECRET exception credential command-id')
    if kind == 'send': client.send_command = fail
    elif kind == 'get': client.get_command_invocation = fail
    elif kind == 'missing':
        def missing(**kwargs): raise MissingInvocation('SECRET command-id')
        client.get_command_invocation = missing
    else:
        client.get_command_invocation = lambda **_: {
            'Status': status, 'ResponseCode': code,
            'StandardOutputContent': 'SECRET' * 4000 if kind == 'truncated' else 'SECRET output',
            'StandardErrorContent': 'SECRET stderr', 'CommandId': 'SECRET command-id'}
    result = collector(tmp_path, client).collect(instances(1))
    record = result['instances'][instances(1)[0]['InstanceId']]
    assert record['error'] == reason
    assert f'stage={stage}' in caplog.text and f'reason={reason}' in caplog.text
    assert 'instance_id=i-fixture-000 platform_type=Linux' in caplog.text
    assert f'status={status}' in caplog.text and f'response_code={code}' in caplog.text
    if kind in {'send', 'get'}:
        assert 'aws_error_code=AccessDeniedException' in caplog.text
        assert 'exception_type=AwsFailure' in caplog.text
    if kind == 'missing': assert 'aws_error_code=InvocationDoesNotExist' in caplog.text
    assert 'SECRET' not in caplog.text + json.dumps(result)
    assert 'CommandId' not in caplog.text + json.dumps(result)


def test_failed_attempt_daily_gate_force_new_instance_and_next_day(tmp_path):
    client = SsmClient(); client.fail.add(instances()[0]['InstanceId'])
    target = collector(tmp_path, client)
    cache = target.collect(instances())
    client.sent.clear()
    same = target.collect(instances(), cache)
    assert client.sent == [] and same['status'] == 'partial'
    assert same['instances'] == cache['instances']
    client.information.update(SsmClient(3).information)
    cache = target.collect(instances(3), same)
    assert client.sent == [instances(3)[2]['InstanceId']]
    client.sent.clear()
    cache = target.collect(instances(3), cache, force=True)
    assert len(client.sent) == 3
    client.sent.clear()
    collector(tmp_path, client, TODAY + timedelta(days=1)).collect(instances(3), cache)
    assert len(client.sent) == 3


def test_windows_document_output_regression():
    # Synthetic hostname; preserve the reported Windows document's other fields.
    output = ('HOSTNAME=fixture-windows\nKERNEL=10.0.14393\n'
              'OS=Microsoft Windows Server 2016 Datacenter\n'
              'OS_INSTALL_DATE=2025-01-14 19:48:22\n'
              'WEB=IIS|10.0|C:\\Windows\\System32\\inetsrv|running\nWAS=None\nDB=None')
    row = parse_inventory('\ufeff' + output.replace('\n', '\r\n'))
    assert row['kernel'] == '10.0.14393'
    assert row['os'] == 'Microsoft Windows Server 2016 Datacenter'
    assert row['os_install_date'] == '2025-01-14 19:48:22'
    assert row['was'] == row['db'] == []
    assert row['web'] == [{'product': 'IIS', 'version': '10.0',
                           'path': r'C:\Windows\System32\inetsrv', 'status': 'running'}]


def test_failed_attempt_gate_converts_timestamp_to_seoul(tmp_path):
    client = SsmClient(1); identifier = instances(1)[0]['InstanceId']
    previous = {'instances': {identifier: {'status': 'failed', 'error': 'terminal_failed',
                                         'last_attempt_at': TODAY.isoformat()}}}
    # UTC 14th is already Seoul 15th: do not retry, nor claim success.
    result = collector(tmp_path, client).collect(instances(1), previous)
    assert client.sent == client.filters == [] and result['status'] == 'failed'
    assert result['instances'] == previous['instances']


@pytest.mark.parametrize('platform', ['Windows', 'Linux'])
@pytest.mark.parametrize('multiple', [False, True])
def test_actual_plugin_metadata_single_omission_and_multi_name(tmp_path, platform, multiple):
    client = SsmClient(1); identifier = instances(1)[0]['InstanceId']
    client.information[identifier]['PlatformType'] = platform
    calls = []
    actual_name = 'runtime-generated-step-42'
    def listing(**kwargs):
        plugins = [{'Name': actual_name, 'Status': 'Success'}]
        if multiple:
            plugins.insert(0, {'Name': 'inactive-step', 'Status': 'Success',
                              'Output': 'Step execution skipped due to unsupported plugin: aws:runShellScript'})
        return {'CommandInvocations': [{'CommandId': kwargs['CommandId'], 'InstanceId': identifier,
                                       'CommandPlugins': plugins}]}
    class InvalidPluginName(Exception):
        response = {'Error': {'Code': 'InvalidPluginName'}}
    def invocation(**kwargs):
        calls.append(kwargs)
        if (multiple and kwargs.get('PluginName') != actual_name) or (not multiple and 'PluginName' in kwargs):
            raise InvalidPluginName('SECRET')
        return {'Status': 'Success', 'ResponseCode': 0, 'StandardOutputUrl': 'https://example.invalid/output',
                'StandardOutputContent': '\ufeff' + (WINDOWS if platform == 'Windows' else LINUX)}
    client.list_command_invocations = listing
    client.get_command_invocation = invocation
    result = collector(tmp_path, client).collect(instances(1))
    assert result['status'] == 'success'
    assert result['instances'][identifier]['platform_type'] == platform
    assert len(calls) == 1
    assert calls[0].get('PluginName') == (actual_name if multiple else None)


def test_invalid_plugin_name_is_query_error_not_execution_failure(tmp_path, caplog):
    client = SsmClient(1)
    class InvalidPluginName(Exception):
        response = {'Error': {'Code': 'InvalidPluginName'}}
    def invocation(**_): raise InvalidPluginName('SECRET')
    client.get_command_invocation = invocation
    result = collector(tmp_path, client).collect(instances(1))
    assert result['instances'][instances(1)[0]['InstanceId']]['error'] == 'invalid_plugin_name'
    assert 'stage=get_command_invocation' in caplog.text
    assert 'aws_error_code=InvalidPluginName' in caplog.text
    assert 'terminal_failed' not in caplog.text and 'SECRET' not in caplog.text


@pytest.mark.parametrize('metadata', ['empty', 'pending', 'ambiguous'])
def test_plugin_resolution_bounded_and_never_guesses(tmp_path, metadata):
    client = SsmClient(1); identifier = instances(1)[0]['InstanceId']; calls = []
    def listing(**kwargs):
        calls.append(1)
        plugins = [] if metadata == 'empty' else [
            {'Name': 'step-one', 'Status': 'Pending' if metadata == 'pending' else 'Success'},
            {'Name': 'step-two', 'Status': 'Pending' if metadata == 'pending' else 'Success'}]
        return {'CommandInvocations': [{'CommandId': kwargs['CommandId'], 'InstanceId': identifier,
                                       'CommandPlugins': plugins}]}
    client.list_command_invocations = listing
    client.get_command_invocation = lambda **_: pytest.fail('Must not guess PluginName')
    result = collector(tmp_path, client).collect(instances(1))
    reason = result['instances'][identifier]['error']
    assert reason == ('ambiguous_inventory_plugin' if metadata == 'ambiguous' else 'invocation_poll_timeout')
    assert len(calls) <= 46


def test_metadata_eventual_consistency_then_actual_failed_exit_code(tmp_path, caplog):
    client = SsmClient(1); identifier = instances(1)[0]['InstanceId']; calls = []
    original = client.list_command_invocations
    def listing(**kwargs):
        calls.append(1)
        if len(calls) == 1: return {'CommandInvocations': []}
        return original(**kwargs)
    client.list_command_invocations = listing
    client.get_command_invocation = lambda **_: {'Status': 'Failed', 'ResponseCode': 1,
                                                'StandardErrorContent': 'SECRET', 'StandardOutputContent': 'SECRET'}
    result = collector(tmp_path, client).collect(instances(1))
    assert result['instances'][identifier]['error'] == 'terminal_failed'
    assert len(calls) == 2
    assert 'stage=terminal_status' in caplog.text and 'status=Failed response_code=1' in caplog.text
    assert 'invalid_plugin_name' not in caplog.text and 'SECRET' not in caplog.text
