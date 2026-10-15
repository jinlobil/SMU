"""Verified LNL-ServerInventory KV contract, fixed steps and bounded collection."""
import copy
from datetime import datetime, timedelta, timezone
import json
import threading

import pytest
from botocore.exceptions import ClientError

from backend.services.ssm_inventory import DOCUMENT, STEPS, OutputParseError, SsmInventoryCollector, parse_inventory
from test_aws_assets import credentials

LINUX_DATA = {'hostname': 'fixture-linux', 'kernel': '6.1-fixture', 'os': 'Example Linux 1',
              'os_version': None, 'os_install_date': None,
              'was': [{'product': 'Tomcat', 'version': '9.0.1', 'path': '/srv/app', 'status': 'running'}],
              'web': [{'product': 'Tengine', 'version': '1.2', 'path': '/srv/web', 'status': 'running'}],
              'db': [{'product': 'MySQL', 'version': None, 'path': '/srv/db', 'status': 'running'}]}
WINDOWS_DATA = {'hostname': 'fixture-windows', 'kernel': '10.0.fixture', 'os': 'Example Windows Server',
                'os_version': None, 'os_install_date': '2025-01-02 03:04:05',
                'web': [{'product': 'IIS', 'version': '10.0', 'path': r'C:\Windows\System32\inetsrv', 'status': 'running'}],
                'was': [], 'db': []}
LINUX = ('HOSTNAME=fixture-linux\nKERNEL=6.1-fixture\nOS=Example Linux 1\nOS_INSTALL_DATE=N/A\n'
         'WAS=Tomcat|9.0.1|/srv/app|running\nWEB=Tengine|1.2|/srv/web|running\nDB=MySQL|unknown|/srv/db|running')
WINDOWS = ('HOSTNAME=fixture-windows\nKERNEL=10.0.fixture\nOS=Example Windows Server\nOS_INSTALL_DATE=2025-01-02 03:04:05\n'
           'WEB=IIS|10.0|C:\\Windows\\System32\\inetsrv|running\nWAS=None\nDB=None')
TODAY = datetime(2026, 10, 14, 16, tzinfo=timezone.utc)


def instances(count=2):
    return [{'InstanceId': f'i-fixture-{number:03}'} for number in range(count)]


def aws_error(code, operation='GetCommandInvocation'):
    return ClientError({'Error': {'Code': code, 'Message': 'SECRET exception credential'},
                        'ResponseMetadata': {'HTTPStatusCode': 400}}, operation)


class SsmClient:
    """Boto-shaped Custom Document fake; no ListCommandInvocations method."""
    def __init__(self, count=2):
        self.information = {item['InstanceId']: {'InstanceId': item['InstanceId'], 'PingStatus': 'Online',
            'PlatformType': 'Windows' if number % 2 else 'Linux', 'AssociationStatus': 'Failed'}
            for number, item in enumerate(instances(count))}
        self.sent, self.requests, self.filters = [], [], []
        self.fail, self.pending, self.missing = set(), set(), set()
        self.outputs, self.responses = {}, {}
        self.lock = threading.Lock()

    def describe_instance_information(self, **kwargs):
        self.filters.append(kwargs)
        return {'InstanceInformationList': [*self.information.values(),
                {'InstanceId': 'mi-fixture', 'PingStatus': 'Online', 'PlatformType': 'Linux'}]}

    def send_command(self, **kwargs):
        identifier = kwargs['InstanceIds'][0]
        platform = self.information[identifier]['PlatformType']
        assert kwargs['DocumentName'] == DOCUMENT == 'LNL-ServerInventory'
        assert set(kwargs) == {'InstanceIds', 'DocumentName', 'TimeoutSeconds'}
        assert 'Parameters' not in kwargs
        self.sent.append(identifier); self.requests.append(kwargs)
        return {'Command': {'CommandId': 'fixture-command-' + identifier, 'DocumentName': kwargs['DocumentName'],
                            'InstanceIds': [identifier], 'Status': 'Pending'}}

    def get_command_invocation(self, **kwargs):
        assert set(kwargs) == {'InstanceId', 'CommandId', 'PluginName'}
        assert kwargs['PluginName'] == STEPS[self.information[kwargs['InstanceId']]['PlatformType']]
        identifier = kwargs['InstanceId']
        assert kwargs['CommandId'] == 'fixture-command-' + identifier
        if identifier in self.fail: raise aws_error('AccessDeniedException')
        if identifier in self.missing:
            self.missing.remove(identifier); raise aws_error('InvocationDoesNotExist')
        base = {'CommandId': kwargs['CommandId'], 'InstanceId': identifier,
                'DocumentName': DOCUMENT, 'PluginName': kwargs['PluginName'],
                'Status': 'Success', 'ResponseCode': 0,
                'StandardOutputContent': self.outputs.get(identifier, WINDOWS if self.information[identifier]['PlatformType'] == 'Windows' else LINUX),
                'StandardErrorContent': '', 'StandardOutputUrl': 'https://example.invalid/output'}
        if identifier in self.pending: base.update(Status='InProgress', ResponseCode=-1, StandardOutputContent='')
        base.update(self.responses.get(identifier, {}))
        return base


def collector(root, client, now=TODAY, **kwargs):
    credentials(root)
    return SsmInventoryCollector(root, lambda _: client, now=lambda: now,
                                 poll_interval=0, sleep=lambda _: None, jitter=lambda: 0.5, **kwargs)


@pytest.mark.parametrize('platform,data', [('Linux', LINUX_DATA), ('Windows', WINDOWS_DATA)])
def test_custom_document_collection_selects_verified_platform_step(tmp_path, platform, data):
    client = SsmClient(1); identifier = instances(1)[0]['InstanceId']
    client.information[identifier]['PlatformType'] = platform
    result = collector(tmp_path, client).collect(instances(1))
    record = result['instances'][identifier]
    assert result['status'] == 'success' and record['status'] == 'success'
    for key, value in data.items(): assert record[key] == value
    assert client.requests[0]['DocumentName'] == 'LNL-ServerInventory'


@pytest.mark.parametrize('version', ['unknown', 'N/A', '', 'None', 'null'])
def test_repeated_products_nullable_versions_and_empty_categories(version):
    output = (f'HOSTNAME=fixture\nOS=Example\nWAS=App|{version}|/a|running\n'
              f'WAS=App2|2.0|/b|installed\nWEB=None\nDB=DB1|{version}|/c|running\nDB=DB2|3.0|/d|installed')
    result = parse_inventory(output)
    assert len(result['was']) == len(result['db']) == 2
    assert result['was'][0]['version'] is result['db'][0]['version'] is None
    assert result['was'][1]['version'] == '2.0' and result['web'] == []


@pytest.mark.parametrize('output,reason', [
    ('', 'empty_output'), (' \ufeff \r\n', 'empty_output'),
    ('OS=Example\nWAS=None\nWEB=None\nDB=None', 'missing_hostname'),
    ('HOSTNAME=fixture\nWAS=None\nWEB=None\nDB=None', 'missing_os'),
    ('HOSTNAME=fixture\nOS=Example\nWAS=App|1|/a\nWEB=None\nDB=None', 'invalid_product_record'),
    ('HOSTNAME=fixture\nOS=Example\nWAS=|1|/a|running\nWEB=None\nDB=None', 'invalid_product_record'),
    ('HOSTNAME=fixture\nOS=Example\nWAS=None\nWEB=None', 'parse_failed'),
    ('Step execution skipped due to unsupported plugin: aws:runShellScript', 'missing_hostname'),
    ('HOSTNAME=fixture\nOS=Example\nWAS=None\nWEB=None\nDB=None\n' + 'x' * 24000, 'output_truncated'),
])
def test_parser_detailed_failures(output, reason):
    with pytest.raises(OutputParseError) as caught: parse_inventory(output)
    assert caught.value.reason == reason


@pytest.mark.parametrize('output', [LINUX, WINDOWS])
def test_bom_crlf_whitespace_and_original_document_output(output):
    decorated = '\ufeff' + '\r\n'.join('  ' + line + '  ' for line in output.splitlines())
    assert parse_inventory(decorated) == parse_inventory(output)


def test_actual_windows_document_fields_with_synthetic_hostname():
    output = ('HOSTNAME=fixture-windows\nKERNEL=10.0.14393\nOS=Microsoft Windows Server 2016 Datacenter\n'
              'OS_INSTALL_DATE=2025-01-14 19:48:22\nWEB=IIS|10.0|C:\\Windows\\System32\\inetsrv|running\nWAS=None\nDB=None')
    result = parse_inventory('\ufeff' + output.replace('\n', '\r\n'))
    assert result['kernel'] == '10.0.14393' and result['os'] == 'Microsoft Windows Server 2016 Datacenter'
    assert result['os_install_date'] == '2025-01-14 19:48:22'
    assert result['was'] == result['db'] == []
    assert result['web'] == [{'product': 'IIS', 'version': '10.0', 'path': r'C:\Windows\System32\inetsrv', 'status': 'running'}]


@pytest.mark.parametrize('response,reason,stage', [
    ({'Status': 'Failed', 'ResponseCode': 1}, 'terminal_failed', 'terminal_status'),
    ({'Status': 'TimedOut', 'ResponseCode': -1}, 'terminal_failed', 'terminal_status'),
    ({'Status': 'Success', 'ResponseCode': 1}, 'nonzero_response_code', 'terminal_status'),
    ({'StandardOutputContent': ''}, 'empty_output', 'parse'),
    ({'StandardOutputContent': '  \r\n'}, 'empty_output', 'parse'),
    ({'StandardOutputContent': 'SECRET malformed stdout'}, 'missing_hostname', 'parse'),
    ({'StandardOutputContent': 'HOSTNAME=fixture\nOS=Example\nWAS=SECRET invalid\nWEB=None\nDB=None'}, 'invalid_product_record', 'parse'),
])
def test_failure_reasons_and_safe_logs(tmp_path, caplog, response, reason, stage):
    client = SsmClient(1); identifier = instances(1)[0]['InstanceId']
    client.responses[identifier] = {**response, 'StandardErrorContent': 'SECRET stderr'}
    result = collector(tmp_path, client).collect(instances(1))
    assert result['instances'][identifier]['error'] == reason
    assert f'stage={stage}' in caplog.text and f'reason={reason}' in caplog.text
    for field in ('instance_id=', 'platform_type=Linux', 'exception_type=', 'aws_error_code=', 'status=', 'response_code=', 'output_length=', 'selected_step=linuxInventory', 'has_hostname=', 'has_os='):
        assert field in caplog.text
    assert 'SECRET' not in caplog.text + json.dumps(result)
    assert 'fixture-command-' not in caplog.text + json.dumps(result)


class Clock:
    def __init__(self): self.value = 0; self.delays = []
    def __call__(self): return self.value
    def sleep(self, seconds): self.delays.append(seconds); self.value += seconds


def test_initial_invocation_not_ready_then_success(tmp_path):
    client = SsmClient(1); client.missing.add(instances(1)[0]['InstanceId'])
    assert collector(tmp_path, client).collect(instances(1))['status'] == 'success'


@pytest.mark.parametrize('missing,reason', [(True, 'invocation_not_ready'), (False, 'polling_timeout')])
def test_bounded_polling(tmp_path, missing, reason):
    client = SsmClient(1); clock = Clock(); calls = []
    def invocation(**kwargs):
        calls.append(1)
        if missing: raise aws_error('InvocationDoesNotExist')
        return {'Status': 'InProgress', 'ResponseCode': -1, 'StandardOutputContent': ''}
    client.get_command_invocation = invocation
    target = collector(tmp_path, client, timeout=3, clock=clock)
    target.sleep, target.poll_interval = clock.sleep, 1
    result = target.collect(instances(1))
    assert result['instances'][instances(1)[0]['InstanceId']]['error'] == reason
    assert len(calls) == 3 and clock.value == 3


@pytest.mark.parametrize('operation', ['send_command', 'get_command_invocation', 'describe_instance_information'])
@pytest.mark.parametrize('exhausted', [False, True])
def test_throttling_backoff_retry_and_limit(tmp_path, operation, exhausted, caplog):
    client = SsmClient(1); clock = Clock(); calls = []; original = getattr(client, operation)
    def throttled(**kwargs):
        calls.append(1)
        if exhausted or len(calls) <= 2: raise aws_error('ThrottlingException', operation)
        return original(**kwargs)
    setattr(client, operation, throttled)
    target = collector(tmp_path, client, clock=clock)
    target.sleep = clock.sleep
    result = target.collect(instances(1))
    if exhausted:
        assert len(calls) == 5
        assert result['instances'][instances(1)[0]['InstanceId']]['error'] == 'throttled'
        assert 'aws_error_code=ThrottlingException' in caplog.text
    else:
        assert len(calls) == 3 and result['status'] == 'success'
    assert all(0 < delay <= 4 for delay in clock.delays)
    assert clock.delays == sorted(clock.delays)
    assert 'SECRET' not in caplog.text + json.dumps(result)


def test_throttling_stops_at_collection_deadline(tmp_path):
    client = SsmClient(1); clock = Clock(); calls = []
    def throttled(**kwargs): calls.append(1); raise aws_error('ThrottlingException')
    client.send_command = throttled
    target = collector(tmp_path, client, clock=clock, collection_timeout=0.2)
    target.sleep = clock.sleep
    result = target.collect(instances(1))
    assert result['instances'][instances(1)[0]['InstanceId']]['error'] == 'throttled'
    assert len(calls) <= 2 and clock.value <= 0.2


def test_stale_daily_attempt_force_new_instance_and_next_day(tmp_path):
    client = SsmClient(); target = collector(tmp_path, client)
    first = target.collect(instances())
    client.fail.add(instances()[0]['InstanceId'])
    next_target = collector(tmp_path, client, TODAY + timedelta(days=1))
    failed = next_target.collect(instances(), first)
    identifier = instances()[0]['InstanceId']
    row = failed['instances'][identifier]
    assert row['status'] == 'stale'
    for key in (*LINUX_DATA, 'platform_type', 'last_success_at'):
        assert row[key] == first['instances'][identifier][key]
    client.sent.clear()
    assert next_target.collect(instances(), failed)['status'] == 'partial' and client.sent == []
    client.information.update(SsmClient(3).information)
    new = next_target.collect(instances(3), failed)
    assert client.sent == [instances(3)[2]['InstanceId']]
    client.sent.clear()
    forced = next_target.collect(instances(3), new, force=True)
    assert len(client.sent) == 3
    client.sent.clear()
    collector(tmp_path, client, TODAY + timedelta(days=2)).collect(instances(3), forced)
    assert len(client.sent) == 3


def test_calendar_gate_uses_seoul_not_24h_and_no_client_when_attempted(tmp_path, monkeypatch):
    client = SsmClient(1); before = datetime(2026, 10, 14, 14, 59, tzinfo=timezone.utc)
    cached = collector(tmp_path, client, before).collect(instances(1))
    client.sent.clear()
    today = collector(tmp_path, client, before + timedelta(minutes=2))
    cached = today.collect(instances(1), cached)
    assert len(client.sent) == 1
    cached['instances'][instances(1)[0]['InstanceId']].update(status='stale', last_attempt_at=TODAY.isoformat())
    monkeypatch.setattr(today, '_client', lambda: pytest.fail('Already attempted today'))
    assert today.collect(instances(1), cached)['status'] == 'partial'


@pytest.mark.parametrize('state', ['ConnectionLost', 'Offline', 'Unknown'])
def test_only_current_online_ec2s_run_despite_association_failed(tmp_path, state):
    client = SsmClient(2); client.information[instances()[0]['InstanceId']]['PingStatus'] = state
    result = collector(tmp_path, client).collect(instances())
    assert client.sent == [instances()[1]['InstanceId']]
    assert result['instances'][instances()[0]['InstanceId']]['error'] == 'not_online'


def test_discovery_failure_preserves_data_and_latest_attempt(tmp_path):
    client = SsmClient(); target = collector(tmp_path, client)
    cached = target.collect(instances()); before = copy.deepcopy(cached)
    def fail(**_): raise aws_error('AccessDeniedException')
    client.describe_instance_information = fail
    result = target.collect(instances(), cached, force=True)
    assert cached == before and result['status'] == 'stale'
    assert result['instances'][instances()[0]['InstanceId']]['was'] == before['instances'][instances()[0]['InstanceId']]['was']


def test_small_concurrency(tmp_path):
    client = SsmClient(9); original = client.get_command_invocation
    barrier = threading.Barrier(3); active = 0; peak = 0; calls = 0
    def invocation(**kwargs):
        nonlocal active, peak, calls
        with client.lock:
            active += 1; peak = max(peak, active); calls += 1; first = calls <= 3
        if first: barrier.wait(timeout=5)
        try: return original(**kwargs)
        finally:
            with client.lock: active -= 1
    client.get_command_invocation = invocation
    assert collector(tmp_path, client).collect(instances(9))['status'] == 'success'
    assert peak == 3


def test_discovery_pagination_and_filter_batches(tmp_path):
    client = SsmClient(52); calls = []
    def describe(**kwargs):
        calls.append(copy.deepcopy(kwargs)); ids = kwargs['Filters'][0]['Values']
        if 'NextToken' not in kwargs:
            return {'InstanceInformationList': [client.information[ids[0]]], 'NextToken': 'fixture-next'}
        return {'InstanceInformationList': [client.information[key] for key in ids[1:]]}
    client.describe_instance_information = describe
    assert collector(tmp_path, client).collect(instances(52))['status'] == 'success'
    assert [len(item['Filters'][0]['Values']) for item in calls] == [50, 50, 2, 2]


def test_first_failure_is_attempted_only_once_until_force_or_next_date(tmp_path):
    client = SsmClient(1); identifier = instances(1)[0]['InstanceId']; client.fail.add(identifier)
    target = collector(tmp_path, client)
    failed = target.collect(instances(1))
    assert failed['status'] == 'failed' and not failed['instances'][identifier].get('last_success_at')
    client.sent.clear()
    assert target.collect(instances(1), failed)['status'] == 'failed' and client.sent == []
    target.collect(instances(1), failed, force=True)
    assert client.sent == [identifier]
    client.sent.clear()
    collector(tmp_path, client, TODAY + timedelta(days=1)).collect(instances(1), failed)
    assert client.sent == [identifier]


def test_send_error_is_not_retried_without_explicit_throttling(tmp_path, caplog):
    client = SsmClient(1); calls = []
    def fail(**_): calls.append(1); raise aws_error('AccessDeniedException', 'SendCommand')
    client.send_command = fail
    result = collector(tmp_path, client).collect(instances(1))
    assert len(calls) == 1
    assert result['instances'][instances(1)[0]['InstanceId']]['error'] == 'send_command_failed'
    assert 'stage=send_command' in caplog.text and 'SECRET' not in caplog.text


def test_whole_collection_deadline_prevents_new_calls_after_discovery(tmp_path):
    client = SsmClient(2); clock = Clock(); original = client.describe_instance_information
    def describe(**kwargs):
        response = original(**kwargs); clock.value = 5; return response
    client.describe_instance_information = describe
    result = collector(tmp_path, client, clock=clock, collection_timeout=3).collect(instances())
    assert client.sent == []
    assert all(record['error'] == 'polling_timeout' for record in result['instances'].values())


@pytest.mark.parametrize('platform,step', [('Linux', 'linuxInventory'), ('Windows', 'windowsInventory')])
def test_official_boto_shapes_use_only_custom_document_and_exact_step(tmp_path, platform, step, monkeypatch):
    import boto3
    import botocore.session
    from botocore.stub import Stubber
    # Use explicit synthetic credentials and no ambient profile; Stubber makes no API calls.
    monkeypatch.delenv('AWS_PROFILE', raising=False)
    monkeypatch.delenv('AWS_DEFAULT_PROFILE', raising=False)
    session = botocore.session.get_session()
    client = boto3.Session(botocore_session=session).client('ssm', region_name='ap-northeast-2',
        aws_access_key_id='fixture-access', aws_secret_access_key='fixture-secret')
    target = collector(tmp_path, client)
    identifier = 'i-00000000000000000'
    command = '00000000-0000-0000-0000-000000000000'
    document = 'LNL-ServerInventory'
    with Stubber(client) as stub:
        stub.add_response('send_command', {'Command': {'CommandId': command, 'DocumentName': document,
                          'InstanceIds': [identifier], 'Status': 'Pending'}},
                          {'DocumentName': document, 'InstanceIds': [identifier], 'TimeoutSeconds': 60})
        stub.add_client_error('get_command_invocation', service_error_code='InvalidPluginName',
                              expected_params={'InstanceId': identifier, 'CommandId': command, 'PluginName': step})
        stub.add_client_error('get_command_invocation', service_error_code='InvocationDoesNotExist',
                              expected_params={'InstanceId': identifier, 'CommandId': command, 'PluginName': step})
        stub.add_response('get_command_invocation', {'CommandId': command, 'InstanceId': identifier,
                          'DocumentName': document, 'PluginName': step, 'Status': 'Success', 'ResponseCode': 0,
                          'StandardOutputContent': WINDOWS if platform == 'Windows' else LINUX,
                          'StandardErrorContent': ''}, {'InstanceId': identifier, 'CommandId': command, 'PluginName': step})
        result = target._invoke(client, identifier, platform, target.clock() + 90)
        assert result['hostname'] == ('fixture-windows' if platform == 'Windows' else 'fixture-linux')
        stub.assert_no_pending_responses()


@pytest.mark.parametrize('platform', ['Linux', 'Windows'])
@pytest.mark.parametrize('output,reason,has_hostname,has_os', [
    ('', 'empty_output', False, False),
    ('HOSTNAME=fixture\nWAS=None\nWEB=None\nDB=None', 'missing_os', True, False),
    ('OS=Example\nWAS=None\nWEB=None\nDB=None', 'missing_hostname', False, True),
    ('HOSTNAME=fixture\nOS=Example\nWAS=SECRET invalid\nWEB=None\nDB=None', 'invalid_product_record', True, True),
])
def test_parse_diagnostics_and_stale_preservation(tmp_path, caplog, platform, output, reason, has_hostname, has_os):
    client = SsmClient(1); identifier = instances(1)[0]['InstanceId']
    client.information[identifier]['PlatformType'] = platform
    target = collector(tmp_path, client)
    cached = target.collect(instances(1)); original = copy.deepcopy(cached)
    client.outputs[identifier] = output
    failed = target.collect(instances(1), cached, force=True)
    row = failed['instances'][identifier]
    assert row['status'] == 'stale' and row['error'] == reason
    for key in (*LINUX_DATA, 'last_success_at', 'platform_type'):
        assert row[key] == original['instances'][identifier][key]
    assert cached == original
    assert f'selected_step={STEPS[platform]}' in caplog.text
    assert 'status=Success response_code=0' in caplog.text
    assert f'has_hostname={has_hostname}' in caplog.text
    assert f'has_os={has_os}' in caplog.text
    assert 'SECRET' not in caplog.text + json.dumps(failed)
    assert 'fixture-command-' not in caplog.text + json.dumps(failed)


def test_every_product_category_repeated_and_document_specific_values_preserved():
    result = parse_inventory('HOSTNAME=fixture\nOS=Example\nOS_INSTALL_DATE=N/A\n'
        'WAS=Tomcat|9.0.46|/srv/app|running\nWAS=WebLogic|12.2.1.4|/srv/wls|installed\n'
        'WEB=Nginx|1.24.0|package:nginx|installed\nWEB=Tengine|2.3.3|/srv/web|running\n'
        'DB=Oracle|19.0.0.0.0|/srv/oracle|installed\nDB=MSSQL|16.0|instance=fixture (Example Edition)|stopped')
    assert len(result['was']) == len(result['web']) == len(result['db']) == 2
    assert result['web'][0]['path'] == 'package:nginx'
    assert result['db'][1]['path'] == 'instance=fixture (Example Edition)'
    assert result['db'][1]['product'] == 'MSSQL' and result['db'][1]['status'] == 'stopped'
    assert result['os_install_date'] is None


@pytest.mark.parametrize('platform,step', [('Linux', 'linuxInventory'), ('Windows', 'windowsInventory')])
def test_invalid_plugin_name_grace_expires_without_fallback(tmp_path, caplog, platform, step):
    client = SsmClient(1); calls = []; clock = Clock()
    client.information[instances(1)[0]['InstanceId']]['PlatformType'] = platform
    def get(**kwargs): calls.append(kwargs); raise aws_error('InvalidPluginName')
    client.get_command_invocation = get
    target = collector(tmp_path, client, clock=clock); target.sleep = clock.sleep
    result = target.collect(instances(1))
    assert result['instances'][instances(1)[0]['InstanceId']]['error'] == 'invalid_plugin_name'
    assert len(calls) == 7 and clock.value == 25
    assert clock.delays == [1, 2, 4, 5, 5, 5, 3]
    assert all(call['PluginName'] == step for call in calls)
    assert 'stage=get_command_invocation' in caplog.text
    assert 'aws_error_code=InvalidPluginName' in caplog.text
    assert 'attempt_count=7' in caplog.text and 'elapsed_seconds=25' in caplog.text
    assert 'SECRET' not in caplog.text


def test_document_300_second_execution_is_not_cut_off_by_previous_short_poll_window(tmp_path):
    client = SsmClient(1); clock = Clock(); actual = client.get_command_invocation
    def get(**kwargs):
        if clock.value < 299: return {'Status': 'InProgress', 'ResponseCode': -1, 'StandardOutputContent': ''}
        return actual(**kwargs)
    client.get_command_invocation = get
    target = collector(tmp_path, client, clock=clock)
    target.sleep, target.poll_interval = clock.sleep, 1
    assert target.collect(instances(1))['status'] == 'success' and clock.value == 299


@pytest.mark.parametrize('platform,step', [('Linux', 'linuxInventory'), ('Windows', 'windowsInventory')])
@pytest.mark.parametrize('invalid_count', [1, 3])
def test_initial_invalid_plugin_name_recovers_with_exact_same_step(tmp_path, caplog, platform, step, invalid_count):
    caplog.set_level('INFO', logger='smu.aws.ssm')
    client = SsmClient(1); identifier = instances(1)[0]['InstanceId']; calls = []; clock = Clock()
    client.information[identifier]['PlatformType'] = platform
    actual = client.get_command_invocation
    def get(**kwargs):
        calls.append(kwargs.copy())
        if len(calls) <= invalid_count: raise aws_error('InvalidPluginName')
        return actual(**kwargs)
    client.get_command_invocation = get
    target = collector(tmp_path, client, clock=clock); target.sleep = clock.sleep
    assert target.collect(instances(1))['status'] == 'success'
    assert len(calls) == invalid_count + 1 and len(client.sent) == 1
    assert all(call['PluginName'] == step for call in calls)
    assert clock.delays == ([1] if invalid_count == 1 else [1, 2, 4])
    parsed = next(record.getMessage() for record in caplog.records if 'reason=inventory_parsed ' in record.getMessage())
    assert f'invalid_plugin_name_count={invalid_count}' in parsed
    assert f'attempt_count={invalid_count + 1}' in parsed and 'document_name=LNL-ServerInventory' in parsed
    assert 'status=Success response_code=0' in parsed
    for key in ('hostname', 'kernel', 'os', 'os_install_date', 'was', 'web', 'db'):
        assert f'has_{key}=True' in parsed
    assert 'reason=send_command_succeeded' in caplog.text and 'send_success=True target_count=1' in caplog.text
    for secret in ('fixture-command-', '/srv/app', 'C:\\Windows', 'SECRET'):
        assert secret not in caplog.text


@pytest.mark.parametrize('platform', ['Linux', 'Windows'])
@pytest.mark.parametrize('terminal', [True, False])
def test_invalid_plugin_name_then_real_terminal_or_parse_failure(tmp_path, caplog, platform, terminal):
    client = SsmClient(1); identifier = instances(1)[0]['InstanceId']; calls = []; clock = Clock()
    client.information[identifier]['PlatformType'] = platform
    actual = client.get_command_invocation
    client.responses[identifier] = {'Status': 'Failed', 'ResponseCode': 1} if terminal else {'StandardOutputContent': 'SECRET malformed'}
    def get(**kwargs):
        calls.append(kwargs)
        if len(calls) == 1: raise aws_error('InvalidPluginName')
        return actual(**kwargs)
    client.get_command_invocation = get
    target = collector(tmp_path, client, clock=clock); target.sleep = clock.sleep
    result = target.collect(instances(1))
    reason = 'terminal_failed' if terminal else 'missing_hostname'
    assert result['instances'][identifier]['error'] == reason and len(calls) == 2
    assert ('stage=terminal_status' if terminal else 'stage=parse') in caplog.text
    assert ('status=Failed response_code=1' if terminal else 'status=Success response_code=0') in caplog.text
    assert 'invalid_plugin_name_count=1' in caplog.text and 'attempt_count=2' in caplog.text
    assert 'SECRET' not in caplog.text


def test_plugin_and_throttle_retries_share_one_lookup_budget(tmp_path, caplog):
    client = SsmClient(1); calls = []; clock = Clock()
    def get(**kwargs):
        calls.append(kwargs)
        raise aws_error('ThrottlingException' if len(calls) % 2 else 'InvalidPluginName')
    client.get_command_invocation = get
    target = collector(tmp_path, client, clock=clock); target.sleep = clock.sleep
    result = target.collect(instances(1))
    assert result['instances'][instances(1)[0]['InstanceId']]['error'] == 'throttled'
    assert len(calls) == 9 and len(client.sent) == 1
    assert clock.value < 25
    assert all(call['PluginName'] == 'linuxInventory' for call in calls)
    assert 'last_aws_error_code=ThrottlingException' in caplog.text


def test_invalid_plugin_name_after_registered_response_is_not_initial_grace(tmp_path):
    client = SsmClient(1); calls = []; clock = Clock()
    def get(**kwargs):
        calls.append(kwargs)
        if len(calls) == 1: return {'Status': 'InProgress', 'ResponseCode': -1}
        raise aws_error('InvalidPluginName')
    client.get_command_invocation = get
    target = collector(tmp_path, client, clock=clock); target.sleep, target.poll_interval = clock.sleep, 1
    result = target.collect(instances(1))
    assert result['instances'][instances(1)[0]['InstanceId']]['error'] == 'invalid_plugin_name'
    assert len(calls) == 2 and clock.value == 1


@pytest.mark.parametrize('send_delay,timeout,expected_time', [(10, 330, 35), (0, 3, 3)])
def test_grace_starts_after_send_and_obeys_outer_deadline(tmp_path, send_delay, timeout, expected_time):
    client = SsmClient(1); clock = Clock(); actual = client.send_command
    def send(**kwargs): clock.value += send_delay; return actual(**kwargs)
    def get(**kwargs): raise aws_error('InvalidPluginName')
    client.send_command, client.get_command_invocation = send, get
    target = collector(tmp_path, client, clock=clock, timeout=timeout); target.sleep = clock.sleep
    result = target.collect(instances(1))
    assert result['instances'][instances(1)[0]['InstanceId']]['error'] == 'invalid_plugin_name'
    assert clock.value == expected_time


def test_not_ready_throttle_recovery_and_parse_diagnostics_only_metadata(tmp_path, caplog):
    caplog.set_level('INFO', logger='smu.aws.ssm')
    client = SsmClient(1); calls = []; clock = Clock(); actual = client.get_command_invocation
    def get(**kwargs):
        calls.append(kwargs)
        if len(calls) == 1: raise aws_error('InvocationDoesNotExist')
        if len(calls) == 2: raise aws_error('ThrottlingException')
        return actual(**kwargs)
    client.get_command_invocation = get
    target = collector(tmp_path, client, clock=clock); target.sleep, target.poll_interval = clock.sleep, 1
    assert target.collect(instances(1))['status'] == 'success'
    assert len(calls) == 3 and clock.delays == [1, 0.1875]
    assert 'invocation_not_ready_count=1' in caplog.text
    assert 'reason=stdout_received' in caplog.text and 'reason=inventory_parsed' in caplog.text
    assert 'was_record_count=1 web_record_count=1 db_record_count=1' in caplog.text
    caplog.clear()
    client.outputs[instances(1)[0]['InstanceId']] = 'HOSTNAME=fixture\nOS=Example\nWAS=SECRET bad\nWAS=Tomcat|1|/SECRET/path|running\nWEB=None\nDB=None'
    failed = target.collect(instances(1), force=True)
    assert failed['instances'][instances(1)[0]['InstanceId']]['error'] == 'invalid_product_record'
    message = next(record.getMessage() for record in caplog.records if record.levelname == 'WARNING')
    assert 'parse_reason=invalid_product_record' in message and 'line_count=6' in message
    assert 'was_record_count=2 web_record_count=0 db_record_count=0' in message
    assert 'has_kernel=False' in message and 'has_os_install_date=False' in message
    assert 'SECRET' not in caplog.text and 'fixture-command-' not in caplog.text


def test_request_started_inside_grace_accepts_valid_response_after_grace(tmp_path):
    client = SsmClient(1); actual = client.get_command_invocation; calls = []; clock = Clock()
    def get(**kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            clock.value = 23
            raise aws_error('InvalidPluginName')
        clock.value = 26
        return actual(**kwargs)
    client.get_command_invocation = get
    target = collector(tmp_path, client, clock=clock); target.sleep = clock.sleep
    assert target.collect(instances(1))['status'] == 'success'
    assert len(calls) == 2 and clock.value == 26
