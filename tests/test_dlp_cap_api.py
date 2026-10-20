import copy
from datetime import date
import json
from types import SimpleNamespace

import pytest

from backend.clients import legacy_collectors as module
from backend.services.dlp_fields import normalize_dlp_row
from backend.services.transfers import TransferService
from backend.services.indexing import IndexService
from backend.services.refresh import RefreshService


DAY = '2026-10-20'
ROW = {'_id': 'fixture-cap-id', 'loc_log_id': 42, 'event_id': 7, 'event_name': 'Content Threat Blocked',
       'event_time_local': DAY + ' 23:58:12', 'client_time_utc': DAY + ' 14:58:12',
       'timestamp': DAY + ' 15:00:00', 'machine_name': 'fixture-pc', 'client_name': 'fixture-user',
       'file_name': 'fixture.pdf', 'file_size': 16352, 'file_hash': 'fixture-hash',
       'destination': 'USB', 'destination_type': 'Removable Storage', 'destination_details': 'fixture device',
       'email_sender': 'sender@example.com', 'email_subject': 'fixture subject', 'serial_no': 'fixture-serial',
       'shadow_exists': False, 'shadow_is_deleted': False, 'repository_type': 'fixture-repository',
       'os_type': 'Windows', 'department_name': 'fixture department', 'epp_client_version': 'fixture-version'}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(module, 'load_dlp_env', lambda _: {'DLP_BASE_URL': 'https://dlp.example.invalid',
        'DLP_USERNAME': 'fixture', 'DLP_PASSWORD': 'fixture'})
    result = module.DlpClient()
    monkeypatch.setattr(result.session, 'request', lambda *a, **k: pytest.fail('Unexpected network call'))
    return result


def response(data):
    return SimpleNamespace(headers={'Content-Type': 'application/json'}, text=json.dumps(data),
        status_code=200, url='https://dlp.example.invalid/index.php/cap_logs_crate/list',
        raise_for_status=lambda: None, json=lambda: data)


def test_cap_columns_explicit_client_local_dates_and_route(client, monkeypatch):
    calls = []
    monkeypatch.setattr(client.session, 'post', lambda url, **kw: calls.append((url, kw)) or response({
        'draw': 3, 'recordsTotal': '9', 'recordsFiltered': '1', 'data': [copy.deepcopy(ROW)]}))
    result = client.fetch_daily_logs_window(DAY, DAY + ' 01:02:03', DAY + ' 23:59:00', start=500, length=500, draw=3)
    url, request = calls[0]; data = request['data']
    assert url.endswith('/index.php/cap_logs_crate/list')
    assert data['startDate'] == DAY + ' 01:02:03' and data['endDate'] == DAY + ' 23:59:00'
    assert data['start'] == '500' and data['length'] == '500'
    assert data['order[0][column]'] == '2' and data['order[0][dir]'] == 'desc'
    assert [data[f'columns[{i}][data]'] for i in range(23)] == [
        'has_details', 'event_name', 'event_time_local', 'client_time_utc', 'machine_name', 'client_name',
        'file_name', 'destination', 'destination_type', 'file_size', 'justification', 'formatted_timestamp',
        'ip', 'destination_details', 'email_sender', 'email_subject', 'file_hash', 'os_type', 'vid', 'pid',
        'serial_no', 'epp_client_version', 'shadow_exists']
    assert not any(key in data for key in ('startServerDate', 'endServerDate', 'startClientUtcDate', 'endClientUtcDate', 'columns[30][search][value]'))
    assert all(not value for key, value in data.items() if key.endswith('[search][value]'))
    assert result['records_total'] == 9 and result['records_filtered'] == 1
    row = result['rows'][0]
    for key, value in ROW.items(): assert row[key] == value
    for current, legacy in [('file_name', 'filename'), ('file_size', 'filesize'), ('file_hash', 'filehash'),
        ('event_time_local', 'eventtimelocal'), ('serial_no', 'serialno'), ('email_sender', 'emailSender'),
        ('email_subject', 'emailSubject'), ('destination_details', 'destinationDetails'),
        ('shadow_exists', 'shadowExists'), ('repository_type', 'repositoryType'), ('loc_log_id', 'loclogid')]:
        assert row[legacy] == ROW[current]


@pytest.mark.parametrize('size', [16352, 15450, 229864, 78363, 0])
def test_real_file_sizes_and_false_values_override_obsolete_aliases(size):
    raw = {**ROW, 'file_size': size, 'filesize': 0, 'shadowExists': True}
    original = copy.deepcopy(raw); row = normalize_dlp_row(raw)
    assert row['filesize'] == size and row['shadowExists'] is False and raw == original


def test_explicit_legacy_mode_only_and_no_automatic_fallback(client, monkeypatch):
    client.log_module = 'cf_log'
    assert client.cf_log_list_url.endswith('/cf_log/list')
    assert client.build_cf_log_payload(DAY)['columns[10][data]'] == 'filename'
    client.log_module = 'cap_logs_crate'; calls = []
    def failed(url, **kw): calls.append(url); raise RuntimeError('fixture API failure')
    monkeypatch.setattr(client.session, 'post', failed)
    with pytest.raises(RuntimeError, match='fixture API failure'): client.fetch_daily_logs(DAY)
    assert len(calls) == 1 and calls[0].endswith('/cap_logs_crate/list')


def test_module_setting_legacy_and_invalid(monkeypatch):
    base = {'DLP_BASE_URL': 'https://dlp.example.invalid', 'DLP_USERNAME': 'fixture', 'DLP_PASSWORD': 'fixture'}
    monkeypatch.setattr(module, 'load_dlp_env', lambda _: {**base, 'DLP_LOG_MODULE': 'cf_log'})
    assert module.DlpClient().log_module == 'cf_log'
    monkeypatch.setattr(module, 'load_dlp_env', lambda _: {**base, 'DLP_LOG_MODULE': 'invalid'})
    with pytest.raises(ValueError): module.DlpClient()


def test_partial_full_day_response_uses_start_length_pagination(client, monkeypatch):
    calls = []
    def post(url, **kwargs):
        data = kwargs['data']; calls.append(copy.deepcopy(data))
        start = int(data['start'])
        count = 500 if start == 0 else 2
        rows = [{**ROW, '_id': f'fixture-{i}', 'file_size': i + 1} for i in range(start, start + count)]
        return response({'recordsTotal': 700, 'recordsFiltered': 502, 'data': rows})
    monkeypatch.setattr(client.session, 'post', post)
    rows = client.fetch_daily_logs(DAY)
    assert len(rows) == 502 and rows[-1]['filesize'] == 502
    assert [call['start'] for call in calls] == ['0', '0', '500']
    assert [call['length'] for call in calls] == ['-1', '500', '500']
    assert all(call['startDate'] == DAY + ' 00:00:00' and call['endDate'] == DAY + ' 23:59:59' for call in calls)


def test_incomplete_pagination_fails_instead_of_saving_partial(client, monkeypatch):
    def post(url, **kwargs):
        start = int(kwargs['data']['start'])
        rows = [{**ROW, '_id': f'fixture-{i}'} for i in range(500)] if start == 0 else []
        return response({'recordsTotal': 501, 'recordsFiltered': 501, 'data': rows})
    monkeypatch.setattr(client.session, 'post', post)
    with pytest.raises(RuntimeError, match='empty page'): client.fetch_daily_logs(DAY)


@pytest.mark.parametrize('body', [[], {'data': None}, {'data': [None]}, {'error': 'fixture'}])
def test_new_api_malformed_response_is_not_hidden(client, monkeypatch, body):
    monkeypatch.setattr(client.session, 'post', lambda *a, **k: response(body))
    with pytest.raises(RuntimeError): client.fetch_daily_logs(DAY)


def test_refresh_stores_raw_new_fields_and_aliases_atomically(client, monkeypatch, tmp_path):
    monkeypatch.setattr(client, 'login', lambda: None)
    monkeypatch.setattr(client.session, 'post', lambda *a, **kw: response({'recordsTotal': 1, 'recordsFiltered': 1, 'data': [ROW]}))
    monkeypatch.setattr(module, 'DLP_DAY_DIR', str(tmp_path / 'cache/dlp'))
    result = client.refresh_dlp_day(DAY)
    row = json.loads((tmp_path / 'cache/dlp' / (DAY + '.jsonl')).read_text())
    assert result['count'] == 1 and row['filesize'] == row['file_size'] == 16352
    assert row['eventtimelocal'] == ROW['event_time_local'] and not list(tmp_path.rglob('*.tmp'))


def test_new_raw_cache_and_legacy_cache_views_search_and_statistics(tmp_path):
    directory = tmp_path / 'cache/dlp'; directory.mkdir(parents=True)
    legacy = {'event_id': 'Content Threat Blocked', 'eventtimelocal': DAY + ' 12:00:00',
              'machine_name': 'legacy-pc', 'client_name': 'legacy-user', 'filename': 'legacy.txt', 'filesize': 12}
    zero = {**ROW, '_id': 'zero-id', 'file_size': 0, 'file_name': 'zero.txt'}
    (directory / (DAY + '.jsonl')).write_text('\n'.join(json.dumps(row) for row in [ROW, legacy, zero]) + '\n')
    service = TransferService(tmp_path); day = date.fromisoformat(DAY)
    collected, _ = service._collect_dlp(day, day)
    assert [item[2]['fileSize'] for item in collected] == ['16352', '12', '0']
    new = collected[0][2]
    assert new['time'] == ROW['event_time_local'] and new['source'] == 'fixture.pdf'
    assert new['computer'] == ROW['machine_name'] and new['username'] == ROW['client_name']
    assert new['destinationDetail'] == ROW['destination_details'] and new['fileHash'] == ROW['file_hash']
    assert new['event'] == '차단'
    IndexService(tmp_path).rebuild_scope('events', lambda _: None)
    result = service.list_records('dlp', day, day, [{'field': 'source', 'mode': 'include', 'query': 'fixture.pdf'}], 1, 50, 'time', 'desc')
    assert result['pagination']['total'] == 1 and result['items'][0]['fileSize'] == '16352'
    assert service.event_index.count_by_kind(day, day, ['dlp'])['dlp'] == 3


def test_existing_range_refresh_visits_every_client_local_date(tmp_path, monkeypatch):
    service = RefreshService(tmp_path); seen = []
    monkeypatch.setattr(service, 'refresh_dlp', lambda day, progress: seen.append(day.isoformat()) or {'date': day.isoformat()})
    service.refresh_dlp_range(date(2026, 10, 19), date(2026, 10, 21), lambda _: None)
    assert seen == ['2026-10-19', '2026-10-20', '2026-10-21']


def test_dlp_xlsx_export_and_report_raw_loader_use_new_fields(tmp_path, monkeypatch):
    from zipfile import ZipFile
    from xml.etree import ElementTree as ET
    from system_monitor.laborer import LaborerAgent
    from backend.services.report import ReportService
    from backend.services import legacy_report
    directory = tmp_path / 'cache/dlp'; directory.mkdir(parents=True)
    (directory / (DAY + '.jsonl')).write_text(json.dumps(ROW) + '\n')
    result = LaborerAgent._export(SimpleNamespace(root=tmp_path), {'kind': 'dlp', 'start': DAY, 'end': DAY}, lambda _: None)
    assert result['rows'] == 1
    with ZipFile(result['path']) as archive:
        sheet = ET.fromstring(archive.read('xl/worksheets/sheet1.xml'))
        text = ' '.join(sheet.itertext())
        assert '16352' in text and 'fixture.pdf' in text and ROW['event_time_local'] in text
    monkeypatch.setattr(legacy_report, 'load_dlp_by_range', legacy_report.load_dlp_by_range)
    ReportService(tmp_path)._configure_legacy_data(['dlp'])
    raw = legacy_report.load_dlp_by_range(DAY, DAY)[0]
    assert raw['filename'] == ROW['file_name'] and raw['filesize'] == 16352
    assert raw['eventtimelocal'] == ROW['event_time_local'] and raw['event_name'] == ROW['event_name']


def test_server_short_pages_advance_by_actual_rows(client, monkeypatch):
    starts = []
    def post(url, **kwargs):
        start = int(kwargs['data']['start']); starts.append(start)
        rows = [{**ROW, '_id': f'fixture-{i}'} for i in range(start, min(start + 2, 5))]
        return response({'recordsTotal': 5, 'recordsFiltered': 5, 'data': rows})
    monkeypatch.setattr(client.session, 'post', post)
    assert len(client.fetch_daily_logs(DAY)) == 5
    assert starts == [0, 0, 2, 4]


def test_explicit_legacy_module_survives_existing_integration_settings_save(tmp_path):
    from backend.services.integrations import IntegrationService
    service = IntegrationService(tmp_path)
    service.save({'type': 'dlp', 'values': {'baseUrl': 'https://dlp.example.invalid', 'username': 'fixture', 'password': 'fixture'}})
    path = tmp_path / 'env/DLP_env.txt'
    path.write_text(path.read_text() + '\nDLP_LOG_MODULE=cf_log\n')
    service.save({'type': 'dlp', 'values': {'timeout': '45'}}, 'dlp')
    assert 'DLP_LOG_MODULE=cf_log' in path.read_text() and 'DLP_TIMEOUT=45' in path.read_text()
