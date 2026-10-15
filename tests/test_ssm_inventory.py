"""SSM single-step JSON contract, bounded calls, and existing cache policies."""
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import threading

import pytest
from botocore.exceptions import ClientError

from backend.services.ssm_inventory import DOCUMENTS, SsmInventoryCollector, validate_inventory
from test_aws_assets import credentials

LINUX_DATA = {'hostname': 'fixture-linux', 'kernel': '6.1-fixture', 'os': 'Example Linux 1',
              'os_version': '1', 'os_install_date': None,
              'was': [{'product': 'Tomcat', 'version': '9.0.1', 'path': '/srv/app', 'status': 'running'}],
              'web': [{'product': 'Tengine', 'version': '1.2', 'path': '/srv/web', 'status': 'running'}],
              'db': [{'product': 'MySQL', 'version': None, 'path': '/srv/db', 'status': 'running'}]}
WINDOWS_DATA = {'hostname': 'fixture-windows', 'kernel': '10.0.fixture', 'os': 'Example Windows Server',
                'os_version': '10.0.fixture', 'os_install_date': '2025-01-02 03:04:05',
                'web': [{'product': 'IIS', 'version': '10.0', 'path': r'C:\Windows\System32\inetsrv', 'status': 'running'}],
                'was': [], 'db': []}
LINUX, WINDOWS = json.dumps(LINUX_DATA), json.dumps(WINDOWS_DATA)
TODAY = datetime(2026, 10, 14, 16, tzinfo=timezone.utc)


def instances(count=2):
    return [{'InstanceId': f'i-fixture-{number:03}'} for number in range(count)]


def aws_error(code, operation='GetCommandInvocation'):
    return ClientError({'Error': {'Code': code, 'Message': 'SECRET exception credential'},
                        'ResponseMetadata': {'HTTPStatusCode': 400}}, operation)


class SsmClient:
    """Boto-shaped single-step fake. No ListCommandInvocations method by design."""
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
        assert kwargs['DocumentName'] == DOCUMENTS[platform][0]
        assert set(kwargs['Parameters']) == {'commands', 'executionTimeout'}
        assert len(kwargs['Parameters']['commands']) == 1
        assert kwargs['Parameters']['executionTimeout'] == ['60']
        assert kwargs['Parameters']['commands'][0] == (Path(__file__).parents[1] / 'backend/services/ssm_scripts' / DOCUMENTS[platform][1]).read_text()
        self.sent.append(identifier); self.requests.append(kwargs)
        return {'Command': {'CommandId': 'fixture-command-' + identifier, 'DocumentName': kwargs['DocumentName'],
                            'InstanceIds': [identifier], 'Status': 'Pending'}}

    def get_command_invocation(self, **kwargs):
        assert set(kwargs) == {'InstanceId', 'CommandId'}
        identifier = kwargs['InstanceId']
        assert kwargs['CommandId'] == 'fixture-command-' + identifier
        if identifier in self.fail: raise aws_error('AccessDeniedException')
        if identifier in self.missing:
            self.missing.remove(identifier); raise aws_error('InvocationDoesNotExist')
        base = {'CommandId': kwargs['CommandId'], 'InstanceId': identifier,
                'DocumentName': DOCUMENTS[self.information[identifier]['PlatformType']][0],
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
def test_platform_json_collection_and_single_step_document(tmp_path, platform, data):
    client = SsmClient(1); identifier = instances(1)[0]['InstanceId']
    client.information[identifier]['PlatformType'] = platform
    result = collector(tmp_path, client).collect(instances(1))
    record = result['instances'][identifier]
    assert result['status'] == 'success' and record['status'] == 'success'
    for key, value in data.items(): assert record[key] == value
    assert client.requests[0]['DocumentName'] == ('AWS-RunPowerShellScript' if platform == 'Windows' else 'AWS-RunShellScript')


@pytest.mark.parametrize('version', ['unknown', 'N/A', '', None])
def test_json_arrays_multiple_products_and_nullable_versions(version):
    data = {**LINUX_DATA, 'web': [], 'db': [], 'was': [
        {'product': 'App', 'version': version, 'path': None, 'status': 'running'},
        {'product': 'App2', 'version': '2.0'}]}
    result = validate_inventory(json.loads(json.dumps(data)))
    assert result['was'][0]['version'] is None and result['was'][1]['version'] == '2.0'
    assert result['web'] == result['db'] == []


@pytest.mark.parametrize('data', [None, [], {}, {**LINUX_DATA, 'hostname': None},
    {**LINUX_DATA, 'os': {}}, {**LINUX_DATA, 'web': None}, {**LINUX_DATA, 'db': ['invalid']},
    {**LINUX_DATA, 'was': [{'product': None}]}, {**LINUX_DATA, 'was': [{'product': 'App', 'version': 3}]}])
def test_schema_validation_rejects_invalid_inventory(data):
    with pytest.raises(ValueError): validate_inventory(data)


@pytest.mark.parametrize('response,reason,stage', [
    ({'Status': 'Failed', 'ResponseCode': 1}, 'terminal_failed', 'terminal_status'),
    ({'Status': 'TimedOut', 'ResponseCode': -1}, 'terminal_failed', 'terminal_status'),
    ({'Status': 'Success', 'ResponseCode': 1}, 'nonzero_response_code', 'terminal_status'),
    ({'StandardOutputContent': ''}, 'empty_output', 'parse'),
    ({'StandardOutputContent': '  \r\n'}, 'empty_output', 'parse'),
    ({'StandardOutputContent': 'not JSON SECRET'}, 'json_parse_failed', 'parse'),
    ({'StandardOutputContent': '{}'}, 'schema_validation_failed', 'parse'),
])
def test_failure_reasons_and_safe_logs(tmp_path, caplog, response, reason, stage):
    client = SsmClient(1); identifier = instances(1)[0]['InstanceId']
    client.responses[identifier] = {**response, 'StandardErrorContent': 'SECRET stderr'}
    result = collector(tmp_path, client).collect(instances(1))
    assert result['instances'][identifier]['error'] == reason
    assert f'stage={stage}' in caplog.text and f'reason={reason}' in caplog.text
    for field in ('instance_id=', 'platform_type=Linux', 'exception_type=', 'aws_error_code=', 'status=', 'response_code=', 'output_length='):
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


def test_linux_script_emits_one_json_object_without_extra_dependency():
    script = Path(__file__).parents[1] / 'backend/services/ssm_scripts/linux.sh'
    result = subprocess.run(['sh', str(script)], capture_output=True, text=True, timeout=30, check=True)
    data = json.loads(result.stdout)
    validate_inventory(data)
    assert data['os_install_date'] is None
    assert all(isinstance(data[key], list) for key in ('was', 'web', 'db'))


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


@pytest.mark.parametrize('platform', ['Linux', 'Windows'])
def test_official_boto_response_and_request_shapes_without_pluginname(tmp_path, platform, monkeypatch):
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
    document, filename = DOCUMENTS[platform]
    script = (Path(__file__).parents[1] / 'backend/services/ssm_scripts' / filename).read_text()
    with Stubber(client) as stub:
        stub.add_response('send_command', {'Command': {'CommandId': command, 'DocumentName': document,
                          'InstanceIds': [identifier], 'Status': 'Pending'}},
                          {'DocumentName': document, 'InstanceIds': [identifier], 'TimeoutSeconds': 60,
                           'Parameters': {'commands': [script], 'executionTimeout': ['60']}})
        stub.add_client_error('get_command_invocation', service_error_code='InvocationDoesNotExist',
                              expected_params={'InstanceId': identifier, 'CommandId': command})
        stub.add_response('get_command_invocation', {'CommandId': command, 'InstanceId': identifier,
                          'DocumentName': document, 'Status': 'Success', 'ResponseCode': 0,
                          'StandardOutputContent': WINDOWS if platform == 'Windows' else LINUX,
                          'StandardErrorContent': ''}, {'InstanceId': identifier, 'CommandId': command})
        result = target._invoke(client, identifier, platform, target.clock() + 90)
        assert result['hostname'] == ('fixture-windows' if platform == 'Windows' else 'fixture-linux')
        stub.assert_no_pending_responses()
