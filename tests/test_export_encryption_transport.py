from contextlib import contextmanager
from http.server import ThreadingHTTPServer
import json
import threading
import urllib.request

from fastapi.testclient import TestClient
import pytest

import backend.app as app_module
from backend.services.watchdog_client import WatchdogManager
from system_monitor.watchdog import HardwareWatchdog, handler_for as watchdog_handler
from system_monitor.laborer import LaborerAgent, handler_for as laborer_handler

PASSWORD = 'Only-in-memory-fixture-암호'
API_REQUESTS = [('/api/jobs/export', {'kind': 'detections', 'start': '2026-01-01', 'end': '2026-01-02'}),
    ('/api/jobs/export/firewall-rules', {'firewalls': ['Cloud']}), ('/api/jobs/export/endpoints', {}),
    ('/api/jobs/export/aws', {'kind': 'aws_ec2'}), ('/api/jobs/export/aws', {'kind': 'aws_sg'}),
    ('/api/jobs/export/timeline', {'user': 'fixture', 'sources': ['Detection']})]


@pytest.mark.parametrize('url,payload', API_REQUESTS)
@pytest.mark.parametrize('password', [None, '', '   '])
def test_every_api_rejects_empty_encryption_password_without_job(monkeypatch, url, payload, password):
    calls = []
    monkeypatch.setattr(app_module.watchdog_manager, 'start_laborer_job', lambda *args, **kwargs: calls.append((args, kwargs)))
    monkeypatch.setattr(app_module.firewall_service, 'selected_for_export', lambda _: [{'name': 'Cloud'}])
    response = TestClient(app_module.app).post(url, json={**payload, 'encrypt': True, 'password': password})
    assert response.status_code == 400 and calls == []
    assert response.json()['error']['code'] == 'INVALID_EXPORT_ENCRYPTION'


@pytest.mark.parametrize('url,payload', API_REQUESTS)
def test_api_off_strips_password_on_forwards_in_memory(monkeypatch, url, payload):
    calls = []
    monkeypatch.setattr(app_module.watchdog_manager, 'start_laborer_job', lambda *args, **kwargs: calls.append(kwargs) or {'id': 'fixture'})
    monkeypatch.setattr(app_module.firewall_service, 'selected_for_export', lambda _: [{'name': 'Cloud'}])
    client = TestClient(app_module.app)
    assert client.post(url, json={**payload, 'encrypt': False, 'password': PASSWORD}).status_code == 202
    assert 'password' not in calls[-1]
    assert client.post(url, json={**payload, 'encrypt': True, 'password': PASSWORD}).status_code == 202
    assert calls[-1]['password'] == PASSWORD and calls[-1]['encrypt'] is True


@contextmanager
def serve(handler):
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try: yield f'http://127.0.0.1:{server.server_port}'
    finally: server.shutdown(); server.server_close(); thread.join()


def test_real_json_transport_manager_watchdog_laborer_never_uses_secret_url(tmp_path, monkeypatch, caplog):
    agent = LaborerAgent(tmp_path)
    watchdog = HardwareWatchdog(tmp_path)
    monkeypatch.setattr(watchdog, 'ensure_laborer', lambda: {})
    with serve(laborer_handler(agent)) as laborer_url:
        paths = []
        def worker_request(path, method='GET', timeout=3, body=None):
            paths.append(path)
            request = urllib.request.Request(laborer_url + path, method=method,
                data=json.dumps(body).encode() if body is not None else None,
                headers={'Content-Type': 'application/json'} if body is not None else {})
            with urllib.request.urlopen(request, timeout=timeout) as response: return json.loads(response.read())
        monkeypatch.setattr(watchdog, '_laborer_request', worker_request)
        with serve(watchdog_handler(watchdog)) as url:
            manager = WatchdogManager(tmp_path); manager.url = url
            monkeypatch.setattr(manager, 'ensure', lambda: True)
            job = manager.start_laborer_job('endpoint_export', encrypt=True, password=PASSWORD)
    assert paths == ['/jobs']
    assert job['status'] == 'queued'
    assert agent._export_passwords == {job['id']: PASSWORD}
    assert PASSWORD not in caplog.text and PASSWORD not in json.dumps(job, ensure_ascii=False)
    assert PASSWORD.encode() not in agent.database.read_bytes()


def test_existing_download_api_returns_encrypted_bytes(tmp_path, monkeypatch):
    from backend.services.office_encryption import encrypted_xlsx_export
    from backend.services.endpoint_export import EndpointExportService
    monkeypatch.setattr(app_module, 'PROJECT_ROOT', tmp_path)
    result = encrypted_xlsx_export(tmp_path, PASSWORD, lambda: EndpointExportService(tmp_path).build(), lambda _: None)
    client = TestClient(app_module.app)
    response = client.get('/api/config/export/file/' + result['filename'])
    assert response.status_code == 200
    assert response.content == __import__('pathlib').Path(result['path']).read_bytes()
    assert response.content[:8] == bytes.fromhex('d0cf11e0a1b11ae1')
    assert client.get('/api/config/export/file/0.xlsx').status_code == 404


def test_manager_off_keeps_legacy_transport_and_removes_secret(tmp_path, monkeypatch):
    manager = WatchdogManager(tmp_path)
    monkeypatch.setattr(manager, 'ensure', lambda: True)
    calls = []
    monkeypatch.setattr(manager, 'request', lambda path, method='GET', timeout=2: calls.append(path) or {'id': 'fixture'})
    manager.start_laborer_job('endpoint_export', encrypt=False, password=PASSWORD)
    assert calls == ['/laborer/jobs?type=endpoint_export']
