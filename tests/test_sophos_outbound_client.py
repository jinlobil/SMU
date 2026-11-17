import json
from datetime import date
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse

import pytest

from backend.clients.sophos import SophosClient

DAY = date(2026, 11, 16)


class Clock:
    def __init__(self): self.value = 0; self.sleeps = []
    def now(self): return self.value
    def sleep(self, delay): self.value += delay; self.sleeps.append(delay)


def fake_client(tmp_path, monkeypatch, responses):
    env = tmp_path / 'Sophos_env.txt'
    env.write_text('SOPHOS_CLIENT_ID=fixture-id\nSOPHOS_CLIENT_SECRET=fixture-secret\n')
    client = SophosClient(env)
    requests = []
    responses = [{'access_token': 'fixture-token'}, {'id': 'tenant-fixture', 'apiHosts': {'dataRegion': 'https://api.example.test'}}] + responses
    def request(request, **kwargs):
        requests.append(request)
        value = responses.pop(0)
        if isinstance(value, Exception): raise value
        return value
    monkeypatch.setattr(client, 'request_json', request)
    return client, requests, Clock()


def run(client, clock, progress=lambda _: None, **kwargs):
    return client.fetch_outbound_emails(DAY, progress, sleep=clock.sleep, clock=clock.now, **kwargs)


def error(code, headers=None):
    return HTTPError('https://api.example.test', code, 'PRIVATE response', headers or {}, None)


def test_auth_kst_milliseconds_single_run_poll_and_three_cursor_pages(tmp_path, monkeypatch):
    rows = [[{'n': n} for n in range(start, end)] for start, end in [(0, 2000), (2000, 4000), (4000, 4745)]]
    client, requests, clock = fake_client(tmp_path, monkeypatch, [
        {'id': 'run-id'}, {'status': 'pending'}, {'status': 'started'}, {'status': 'finished', 'result': 'succeeded'},
        {'items': rows[0], 'pages': {'nextKey': 'AAAH0A==', 'items': 4745, 'total': 3}},
        {'items': rows[1], 'pages': {'nextKey': 'cursor+/==', 'items': 4745, 'total': 3}},
        {'items': rows[2], 'pages': {'items': 4745, 'total': 3}},
    ])
    result = run(client, clock)
    assert result == {'items': sum(rows, []), 'pages': 3}
    assert client.client_id == 'fixture-id' and client.client_secret == 'fixture-secret'
    assert client.tenant_id == 'tenant-fixture' and client.base_url == 'https://api.example.test'
    posts = [r for r in requests if r.get_method() == 'POST' and '/queries/runs' in r.full_url]
    assert len(posts) == 1
    body = json.loads(posts[0].data)
    assert body['from'] == '2026-11-15T15:00:00.000Z' and body['to'] == '2026-11-16T14:59:59.999Z'
    assert body['adHocQuery']['name'] == 'SMU Sophos Outbound 2026-11-16'
    sql = body['adHocQuery']['template']
    assert 'LIMIT' not in sql and "direction = 'OUTBOUND'" in sql
    for field in ['timestamp', 'event_time', 'client_ip', 'header_from', 'header_to', 'mime_message_id', 'reason_list', 'message_size_kb']:
        assert field in sql
    gets = [r for r in requests if '/results?' in r.full_url]
    assert len(gets) == 3
    assert parse_qs(urlparse(gets[0].full_url).query) == {'pageSize': ['2000']}
    assert parse_qs(urlparse(gets[1].full_url).query)['pageFromKey'] == ['AAAH0A==']
    assert parse_qs(urlparse(gets[2].full_url).query)['pageFromKey'] == ['cursor+/==']
    assert all(r.get_header('X-tenant-id') == 'tenant-fixture' for r in requests[2:])
    assert clock.sleeps == [2, 3, 3]


@pytest.mark.parametrize('state', [
    {'status': 'finished', 'result': 'failed'}, {'status': 'timedOut'}, {'status': 'canceled'},
    {'status': 'failed'}, {'status': 'finished', 'result': 'timedOut'},
])
def test_unsuccessful_terminal_never_requests_results(tmp_path, monkeypatch, state):
    client, requests, clock = fake_client(tmp_path, monkeypatch, [{'id': 'run-id'}, state])
    with pytest.raises(RuntimeError, match='did not succeed'): run(client, clock)
    assert not any('/results?' in r.full_url for r in requests)


@pytest.mark.parametrize('transient,delay', [(error(429, {'Retry-After': '7'}), 7), (error(503), 1), (URLError('PRIVATE'), 1)])
@pytest.mark.parametrize('stage', ['post', 'poll', 'results'])
def test_transient_retry_is_scoped_to_same_operation(tmp_path, monkeypatch, transient, delay, stage):
    responses = [{'id': 'run-id'}, {'status': 'finished', 'result': 'succeeded'}, {'items': [], 'pages': {}}]
    offset = {'post': 0, 'poll': 1, 'results': 2}[stage]
    responses.insert(offset, transient)
    client, requests, clock = fake_client(tmp_path, monkeypatch, responses)
    assert run(client, clock) == {'items': [], 'pages': 1}
    operations = requests[2:]
    assert operations[offset].full_url == operations[offset + 1].full_url
    assert sum(r.get_method() == 'POST' for r in operations) == (2 if stage == 'post' else 1)
    assert delay in clock.sleeps


def test_poll_retries_exhaust_without_reposting_or_secret_errors(tmp_path, monkeypatch):
    client, requests, clock = fake_client(tmp_path, monkeypatch, [{'id': 'run-id'}] + [error(500)] * 4)
    with pytest.raises(RuntimeError, match='retry exhausted') as caught: run(client, clock)
    assert 'PRIVATE' not in str(caught.value)
    assert sum('/queries/runs' in r.full_url and r.get_method() == 'POST' for r in requests) == 1
    assert clock.sleeps == [2, 1, 2, 4]


def test_pending_polling_has_bounded_timeout(tmp_path, monkeypatch):
    client, requests, clock = fake_client(tmp_path, monkeypatch, [{'id': 'run-id'}] + [{'status': 'pending'}] * 50)
    with pytest.raises(RuntimeError, match='timeout'): run(client, clock, timeout=11)
    assert clock.value == 11
    assert sum('/queries/runs' in r.full_url and r.get_method() == 'POST' for r in requests) == 1


@pytest.mark.parametrize('pages', [
    [{'items': [], 'pages': {'items': 99}}],
    [{'items': [], 'pages': {'nextKey': 'same'}}, {'items': [], 'pages': {'nextKey': 'same'}}],
    [{'items': 'invalid'}],
])
def test_incomplete_invalid_or_repeated_pagination_fails(tmp_path, monkeypatch, pages):
    client, requests, clock = fake_client(tmp_path, monkeypatch, [{'id': 'run-id'}, {'status': 'finished', 'result': 'succeeded'}] + pages)
    with pytest.raises(RuntimeError): run(client, clock)


def test_authentication_errors_do_not_expose_response_or_credentials(tmp_path, monkeypatch):
    client, requests, clock = fake_client(tmp_path, monkeypatch, [])
    monkeypatch.setattr(client, 'authenticate', lambda: (_ for _ in ()).throw(RuntimeError('PRIVATE fixture-secret fixture-token')))
    progress = []
    with pytest.raises(RuntimeError) as caught: run(client, clock, progress.append)
    assert all(value not in str(caught.value) + '\n'.join(progress) for value in ['PRIVATE', 'fixture-secret', 'fixture-token'])
    assert not requests


def test_retry_after_http_date_and_429_default_backoff(tmp_path, monkeypatch):
    import backend.clients.sophos as module
    monkeypatch.setattr(module.time, 'time', lambda: 0)
    client, requests, clock = fake_client(tmp_path, monkeypatch, [
        {'id': 'run-id'}, error(429, {'Retry-After': 'Thu, 01 Jan 1970 00:00:09 GMT'}),
        error(429), {'status': 'finished', 'result': 'succeeded'}, {'items': []},
    ])
    assert run(client, clock)['pages'] == 1
    assert clock.sleeps == [2, 9, 2]
