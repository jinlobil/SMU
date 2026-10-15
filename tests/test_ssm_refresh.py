import copy
import json
import threading

import pytest
from fastapi.testclient import TestClient

from backend.services.aws_assets import AwsCollector
from backend.services.refresh import RefreshService
from backend.services.ssm_inventory import SsmInventoryCollector, cache_lock
from test_ssm_inventory import SsmClient, collector, instances
from test_aws_assets import credentials


def service(root, monkeypatch):
    client = SsmClient(); credentials(root)
    payload = {'metadata': {'region': 'fixture-region', 'counts': {'instances': 2}}, 'instances': instances(), 'vpcs': [{'VpcId': 'vpc-fixture'}]}
    monkeypatch.setattr(AwsCollector, 'collect', lambda *_: copy.deepcopy(payload))
    result = RefreshService(root, ssm_factory=lambda _: client)
    return result, client, payload


def test_aws_atomic_refresh_cache_only_daily_ssm_and_failure_isolation(tmp_path, monkeypatch):
    target, client, payload = service(tmp_path, monkeypatch)
    assert target.refresh_aws(lambda _: None)['ssm'] == 'success'
    path = tmp_path / 'cache/aws.json'
    first = json.loads(path.read_text())
    assert first['vpcs'] == payload['vpcs'] and len(client.sent) == 2
    assert not list(path.parent.glob('*.tmp'))
    client.sent.clear()
    assert target.refresh_aws(lambda _: None)['ssm'] == 'success'
    assert client.sent == []
    # Discovery failure must not turn successful Describe collection into AWS failure.
    from datetime import datetime, timedelta
    for record in first['ssm_inventory']['instances'].values():
        for field in ('last_success_at', 'last_attempt_at'):
            record[field] = (datetime.fromisoformat(record[field]) - timedelta(days=1)).isoformat()
    path.write_text(json.dumps(first))
    monkeypatch.setattr(client, 'describe_instance_information', lambda **_: (_ for _ in ()).throw(RuntimeError('fixture')))
    assert target.refresh_aws(lambda _: None)['ssm'] == 'stale'
    latest = json.loads(path.read_text())
    assert latest['instances'] == payload['instances']
    for identifier in latest['ssm_inventory']['instances']:
        assert latest['ssm_inventory']['instances'][identifier]['hostname'] == first['ssm_inventory']['instances'][identifier]['hostname']


@pytest.mark.parametrize("null_ssm", [False, True])
def test_manual_ssm_and_normal_aws_overlap_preserve_both_updates(tmp_path, monkeypatch, null_ssm):
    target, client, payload = service(tmp_path, monkeypatch)
    target.refresh_aws(lambda _: None)
    if null_ssm:
        cached = target._aws_cache(); cached["ssm_inventory"] = None
        target.save_json_atomic(tmp_path / "cache/aws.json", cached)
    lease = cache_lock(tmp_path)
    assert lease is not None
    try:
        payload['metadata']['fixture_latest'] = True
        client.sent.clear()
        target.refresh_aws(lambda _: None)
        assert client.sent == []
        target.refresh_ssm_inventory(lambda _: None)
        cached = json.loads((tmp_path / 'cache/aws.json').read_text())
        assert cached['metadata']['fixture_latest'] is True and cached['ssm_inventory']['status'] == 'success'
        assert len(client.sent) == 2
    finally: lease.close()


def test_manual_merge_reads_latest_aws_after_command_finishes(tmp_path, monkeypatch):
    target, client, _ = service(tmp_path, monkeypatch)
    target.refresh_aws(lambda _: None)
    actual = SsmInventoryCollector.collect
    def collect_and_simulate_aws_update(self, *args, **kwargs):
        inventory = actual(self, *args, **kwargs)
        cache = target._aws_cache(); cache['metadata']['concurrent_aws'] = 'preserved'
        target.save_json_atomic(tmp_path / 'cache/aws.json', cache)
        return inventory
    monkeypatch.setattr(SsmInventoryCollector, 'collect', collect_and_simulate_aws_update)
    target.refresh_ssm_inventory(lambda _: None)
    assert target._aws_cache()['metadata']['concurrent_aws'] == 'preserved'


def test_force_job_uses_cache_and_rejects_duplicate_requests(tmp_path, monkeypatch):
    import backend.app as app_module
    target, client, _ = service(tmp_path, monkeypatch)
    target.refresh_aws(lambda _: None)
    entered, release = threading.Event(), threading.Event()
    actual = target.refresh_ssm_inventory
    def blocked(progress):
        entered.set()
        assert release.wait(timeout=5)
        return actual(progress)
    monkeypatch.setattr(target, 'refresh_ssm_inventory', blocked)
    monkeypatch.setattr(app_module, 'PROJECT_ROOT', tmp_path)
    monkeypatch.setattr(app_module, 'refresh_service', target)
    http = TestClient(app_module.app)
    job = http.post('/api/jobs/aws/ssm-inventory')
    try:
        assert job.status_code == 202 and entered.wait(timeout=2)
        assert http.get('/api/aws/ssm-inventory').json()['data']['running'] is True
        assert http.post('/api/jobs/aws/ssm-inventory').status_code == 409
        # Reservation also prevents auto SSM from running duplicate commands.
        previous = len(client.sent); target.refresh_aws(lambda _: None)
        assert len(client.sent) == previous
    finally: release.set()
    # Wait for lease release deterministically, without assuming thread scheduling.
    for _ in range(100):
        lease = cache_lock(tmp_path)
        if lease is not None:
            lease.close(); break
        threading.Event().wait(0.01)
    assert http.get('/api/aws/ssm-inventory').json()['data']['running'] is False
    state = http.get('/api/jobs/' + job.json()['data']['id']).json()['data']
    assert state['status'] == 'completed'


@pytest.mark.parametrize('interval', [30, 60, 120])
def test_scheduler_interval_remains_user_controlled_and_now_is_not_force(tmp_path, monkeypatch, interval):
    from backend.services.settings import SchedulerService
    target, client, _ = service(tmp_path, monkeypatch)
    from system_monitor.fetcher import FetcherAgent
    class Dispatcher:
        def start_fetch_job(self, targets, start, end, chain_index):
            assert targets == ['aws'] and chain_index is True
            return {'id': 'fixture-fetch-job'}
        def wait_for_fetch_job(self, job, progress, wait_for_index):
            collected = FetcherAgent._collect(None, target, 'aws', None, None, progress)
            return {'aws': {'status': 'SUCCESS', 'result': collected}}
    scheduler = SchedulerService(tmp_path, target, Dispatcher())
    scheduler.save({'enabled': True, 'interval': interval, 'targets': ['aws']})
    scheduler._run_cycle()
    assert scheduler.get()['interval'] == interval and len(client.sent) == 2
    client.sent.clear()
    scheduler._run_cycle()
    assert client.sent == [] and scheduler.get()['interval'] == interval


def test_aws_refresh_recovers_legacy_invalid_cache(tmp_path, monkeypatch):
    target, client, _ = service(tmp_path, monkeypatch)
    path = tmp_path / 'cache/aws.json'; path.parent.mkdir(parents=True); path.write_text('{broken-json')
    assert target.refresh_aws(lambda _: None)['ssm'] == 'success'
    assert json.loads(path.read_text())['ssm_inventory']['status'] == 'success'
