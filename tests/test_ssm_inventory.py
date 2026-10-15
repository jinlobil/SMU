import copy
from datetime import datetime, timedelta, timezone
import json
import threading

import pytest

from backend.services.ssm_inventory import DOCUMENT, PLUGINS, SsmInventoryCollector, parse_inventory
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

    def get_command_invocation(self, **kwargs):
        identifier = kwargs['InstanceId']
        self.plugins.append(kwargs['PluginName'])
        assert kwargs['PluginName'] == PLUGINS[self.information[identifier]['PlatformType']]
        if identifier in self.fail: raise RuntimeError('fixture failure')
        if identifier in self.missing:
            self.missing.remove(identifier); raise MissingInvocation()
        if identifier in self.pending: return {'Status': 'InProgress'}
        output = WINDOWS if kwargs['PluginName'] == 'windowsInventory' else LINUX
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
    assert len(client.sent) == 2 and set(client.plugins) == {'linuxInventory', 'windowsInventory'}
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
def test_failure_preserves_last_good_values_and_retry_only_failed(tmp_path, failure):
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
    assert client.sent == [identifier]


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
    assert 'windowsInventory' in client.plugins
