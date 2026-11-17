import copy
import json
import sqlite3
from datetime import date
from pathlib import Path
from unittest.mock import Mock

import pytest

from backend.services.refresh import RefreshService
from backend.services.sophos_outbound import normalize_outbound
from backend.services.transfers import TransferService
from backend.services.indexing import IndexService
from backend.services.timeline import TimelineService
from backend.services.sensitive import SensitiveService
from backend.services.event_list_index import EventListIndex
from backend.services.report import ReportService

DAY = date(2026, 11, 16)


def event(identifier='mail-a', kind='ACCEPTED', details=None, **fields):
    return {'x_sophos_email_id': identifier, 'mime_message_id': 'mime-a', 'event_type': kind,
        'event_details': details, 'event_time': '2026-11-16T01:00:00.000Z', 'timestamp': '2026-11-16T02:00:00Z',
        'subject': 'fixture subject', 'envelope_sender': 'sender@example.test',
        'envelope_recipient': 'one@example.net', 'message_size_kb': 0, **fields}


def events():
    return [event(), event(kind='DELIVERY_ATTEMPT', details='Delivery Successful', message_size_kb=42.5,
                           event_time='2026-11-16T01:01:00Z'),
            event(kind='DELIVERY_ATTEMPT', details='Delivery Failed', envelope_recipient='two@example.net',
                  event_time='2026-11-16T01:02:00Z', reason='DATA_CONTROL', reason_list=['Rule A', 'Rule B'])]


def test_normalization_groups_messages_not_mime_or_rows_and_preserves_all_details():
    raw = events() + [event('mail-b', mime_message_id='mime-a')]
    before = copy.deepcopy(raw)
    rows = normalize_outbound(raw)
    assert len(rows) == 2 and raw == before
    row = rows[0]
    assert row['date'] == '2026-11-16 10:00:00'
    assert row['mailProcess'] == 'DELIVERY_ATTEMPT' and row['sendResult'] == 'Partial Failed'
    assert row['receiver'] == 'one@example.net, two@example.net'
    assert row['size'] == '42.5 KB' and row['attachment'] is None
    assert row['policyReasons'] == ['DATA_CONTROL', 'Rule A', 'Rule B']
    assert row['policy'] == 'DATA_CONTROL; Rule A; Rule B'
    assert row['_rawIndexes'] == [0, 1, 2] and len(row['recipientResults']) == 2
    assert row['x_sophos_email_id'] == 'mail-a' and row['mime_message_id'] == 'mime-a'


@pytest.mark.parametrize('details,expected', [
    (['Delivery Successful', 'Delivery Successful'], 'Success'),
    (['Delivery Successful', 'Delivery Failed'], 'Partial Failed'),
    (['Delivery Failed', 'Delivery Failed'], 'Failed'),
    ([], 'Accepted'),
])
def test_delivery_aggregation(details, expected):
    raw = [event()] + [event(kind='DELIVERY_ATTEMPT', details=value, envelope_recipient=f'fixture-{i}@example.net') for i, value in enumerate(details)]
    assert normalize_outbound(raw)[0]['sendResult'] == expected


def test_header_fallback_first_valid_subject_size_and_date_priorities():
    raw = [event(kind='DELIVERY_ATTEMPT', details='Delivery Successful', envelope_sender=None, subject='', message_size_kb=12,
                 event_time='2026-11-16T00:00:00Z', header_from={'local_address': 'fallback', 'domain_address': 'example.test'}),
           event(envelope_sender=None, event_time='2026-11-16T01:00:00Z', message_size_kb=8)]
    row = normalize_outbound(raw)[0]
    assert row['date'] == '2026-11-16 10:00:00' and row['senderEmail'] == 'fallback@example.test'
    assert row['subject'] == 'fixture subject' and row['size'] == '12 KB'
    raw = [event(kind='QUARANTINED', details='Held', envelope_sender=None, event_time=None)]
    row = normalize_outbound(raw)[0]
    assert row['date'] == '2026-11-16 11:00:00' and row['senderEmail'] is None and row['sendResult'] == 'Held'
    assert row['attachment'] is None
    raw = [event(kind='QUEUED', event_time='2026-11-16T01:00:00Z'), event(kind='BLOCKED', event_time='2026-11-16T00:00:00Z')]
    assert normalize_outbound(raw)[0]['date'] == '2026-11-16 09:00:00'


def test_missing_ids_do_not_coalesce_unrelated_messages():
    rows = normalize_outbound([event(None), event(None), event('mail-a')])
    assert len(rows) == 3 and len({r['_messageKey'] for r in rows}) == 3
    with pytest.raises(ValueError): normalize_outbound([event(event_time=None, timestamp=None)])


def refresh(tmp_path, raw=None):
    client = Mock()
    client.fetch_outbound_emails.return_value = {'items': events() if raw is None else raw, 'pages': 1}
    factory = Mock(return_value=client)
    return RefreshService(tmp_path, client_factory=factory), client, factory


def test_refresh_reuses_env_rebuilds_date_and_preserves_legacy(tmp_path):
    legacy = tmp_path / 'cache/mailscreen/mailscreen_mail_2026-11-16.json'
    legacy.parent.mkdir(parents=True); legacy.write_text('{"items": [{"sender": "legacy@example.test"}]}')
    before = legacy.read_bytes()
    service, client, factory = refresh(tmp_path)
    messages = []
    result = service.refresh_outbound(DAY, messages.append)
    assert result['rows'] == result['count'] == result['normalizedRows'] == 1
    assert result['rawRows'] == 3 and result['pages'] == 1
    assert Path(result['path']).parent.name == 'sophos_outbound'
    assert Path(result['rawPath']).parent.name == 'sophos_outbound_raw'
    assert json.loads(Path(result['rawPath']).read_text()) == events()
    factory.assert_called_with(tmp_path / 'env/Sophos_env.txt')
    client.fetch_outbound_emails.assert_called_once_with(DAY, messages.append)
    client.fetch_outbound_emails.return_value = {'items': [event('new')], 'pages': 1}
    again = service.refresh_outbound(DAY, messages.append)
    assert again['rows'] == 1
    assert json.loads(Path(again['path']).read_text())[0]['x_sophos_email_id'] == 'new'
    assert legacy.read_bytes() == before and not list((tmp_path / 'cache').rglob('*.tmp'))


@pytest.mark.parametrize('failure', ['api', 'normalization', 'serialization', 'replace'])
def test_failed_collection_never_replaces_previous_pair_or_leaks_secrets(tmp_path, monkeypatch, failure):
    service, client, _factory = refresh(tmp_path)
    original = service.refresh_outbound(DAY, lambda _: None)
    previous = {key: Path(original[key]).read_bytes() for key in ('path', 'rawPath')}
    if failure == 'api': client.fetch_outbound_emails.side_effect = RuntimeError('PRIVATE fixture-secret fixture-token')
    elif failure == 'normalization': client.fetch_outbound_emails.return_value = {'items': [event(event_time=None, timestamp=None)], 'pages': 1}
    elif failure == 'serialization': client.fetch_outbound_emails.return_value = {'items': [event(extra=set())], 'pages': 1}
    else:
        import backend.services.refresh as module
        replace = module.os.replace
        def fail_once(src, target):
            if Path(target) == Path(original['path']):
                raise OSError('PRIVATE fixture-secret fixture-token')
            return replace(src, target)
        monkeypatch.setattr(module.os, 'replace', fail_once)
    messages = []
    with pytest.raises(RuntimeError) as caught: service.refresh_outbound(DAY, messages.append)
    assert not any(secret in str(caught.value) + '\n'.join(messages) for secret in ['PRIVATE', 'fixture-secret', 'fixture-token'])
    assert all(Path(original[key]).read_bytes() == value for key, value in previous.items())
    assert not list((tmp_path / 'cache').rglob('*.tmp'))


def test_same_date_concurrent_refresh_is_rejected(tmp_path):
    from system_monitor.collector import acquire_singleton
    service, client, _factory = refresh(tmp_path)
    lease = acquire_singleton(tmp_path / 'runtime' / f'sophos-outbound-{DAY}.lock')
    try:
        with pytest.raises(RuntimeError, match='already running'): service.refresh_outbound(DAY, lambda _: None)
        client.fetch_outbound_emails.assert_not_called()
    finally: lease.close()


def test_current_consumers_index_raw_detail_report_timeline_and_legacy_separation(tmp_path, monkeypatch):
    service, client, _factory = refresh(tmp_path)
    users = tmp_path / 'cache/users.json'; users.parent.mkdir(parents=True)
    users.write_text(json.dumps([{'email': 'sender@example.test', 'name': 'Fixture User', 'department': 'Fixture Dept', 'exchangeLogin': 'fixture-user'}]))
    result = service.refresh_outbound(DAY, lambda _: None)
    legacy = tmp_path / 'cache/mailscreen/mailscreen_mail_2026-11-16.json'; legacy.parent.mkdir()
    legacy.write_text(json.dumps({'items': [{'date': '2026-11-16 10:00:00', 'sender_email': 'legacy@example.test', 'subject': 'legacy-only'}]}))
    transfers = TransferService(tmp_path)
    record_id, raw, row = transfers._collect_outbound(DAY, DAY)[0][0]
    assert row['senderName'] == 'Fixture User' and row['dept'] == 'Fixture Dept'
    assert raw['events'] == events() and raw['recipientResults'][1]['event_details'] == 'Delivery Failed'
    assert transfers.get_record('outbound', record_id, DAY, DAY)['raw'] == raw
    assert transfers._collect_outbound_legacy(DAY, DAY)[0][0][2]['subject'] == 'legacy-only'
    index = IndexService(tmp_path)
    assert index._infer_source_meta(Path(result['path'])) == {'source': 'sophos_outbound', 'date': DAY.isoformat()}
    assert index._infer_source_meta(legacy)['source'] == 'mailscreen'
    assert index._source_files_from_fetch_result({'outbound': result}) == [str(Path(result['path']).resolve())]
    monkeypatch.setattr(index.dashboard, 'warm_default', lambda: None)
    index.rebuild_all(lambda _: None)
    listing = transfers.list_records('outbound', DAY, DAY, [], 1, 50, 'date', 'desc')
    assert listing['pagination']['total'] == 1 and listing['items'][0]['senderEmail'] == 'sender@example.test'
    assert EventListIndex(tmp_path)._source_paths('outbound', DAY, DAY) == [Path(result['path'])]
    assert EventListIndex(tmp_path).count_by_kind(DAY, DAY, ['outbound']) == {'outbound': 1}
    assert EventListIndex(tmp_path).daily_counts(DAY, DAY, ['outbound']) == {'outbound': {str(DAY): 1}}
    timeline = TimelineService(tmp_path).events_between(DAY, DAY, {'Outbound Mail'})
    assert len(timeline) == 1 and timeline[0]['raw']['events'] == events()
    assert SensitiveService(tmp_path).file_records({'Outbound Mail'}, DAY, DAY) == []  # No invented attachment.
    report = ReportService(tmp_path); report._configure_legacy_data(['outbound'])
    from backend.services import legacy_report
    report_rows = legacy_report.load_mailscreen_by_range(str(DAY), str(DAY))
    assert len(report_rows) == 1 and report_rows[0]['send_result'] == 'Partial Failed'
    assert report_rows[0]['sender_email'] == 'sender@example.test'
    assert json.loads(Path(result['rawPath']).read_text()) == events()


def test_smart_and_fetch_incremental_indexes_follow_current_cache_without_duplicates(tmp_path, monkeypatch):
    service, client, _factory = refresh(tmp_path)
    service.refresh_outbound(DAY, lambda _: None)
    index = IndexService(tmp_path)
    monkeypatch.setattr(index.dashboard, 'warm_default', lambda: None)
    index.rebuild_all(lambda _: None)
    client.fetch_outbound_emails.return_value = {'items': [event('mail-b'), event('mail-c')], 'pages': 1}
    result = service.refresh_outbound(DAY, lambda _: None)
    changed = index.rebuild_smart(lambda _: None)
    assert changed['changed'] == 1
    assert EventListIndex(tmp_path).count_by_kind(DAY, DAY, ['outbound']) == {'outbound': 2}
    client.fetch_outbound_emails.return_value = {'items': [event('mail-d')], 'pages': 1}
    result = service.refresh_outbound(DAY, lambda _: None)
    monkeypatch.setattr(index, '_load_fetch_job', lambda _: {'status': 'completed', 'result': {'outbound': result}})
    indexed = index.rebuild_from_fetch_job('fixture-job', lambda _: None)
    assert indexed['events'] == 1
    for _ in range(2): index.rebuild_from_fetch_job('fixture-job', lambda _: None)
    assert EventListIndex(tmp_path).count_by_kind(DAY, DAY, ['outbound']) == {'outbound': 1}
    with sqlite3.connect(tmp_path / 'cache/index/timeline_index.db') as db:
        assert db.execute("SELECT COUNT(*) FROM timeline_events WHERE source='Outbound Mail'").fetchone()[0] == 1
    Path(result['path']).unlink()
    index.rebuild_smart(lambda _: None)
    assert EventListIndex(tmp_path).count_by_kind(DAY, DAY, ['outbound']) == {'outbound': 0}
    assert Path(result['rawPath']).exists()


def test_legacy_manifest_migration_removes_only_derived_current_index_rows(tmp_path, monkeypatch):
    legacy = tmp_path / 'cache/mailscreen/mailscreen_mail_2026-11-16.json'
    legacy.parent.mkdir(parents=True)
    legacy.write_text(json.dumps({'items': [{'date': str(DAY), 'sender': 'legacy@example.test'}]}))
    before = legacy.read_bytes()
    index = IndexService(tmp_path)
    monkeypatch.setattr(index.dashboard, 'warm_default', lambda: None)
    index.rebuild_all(lambda _: None)
    legacy_key = str(legacy.resolve())
    index._build_events_index([{'kind': 'outbound', 'recordId': 'legacy', 'eventTime': str(DAY),
        'rowJson': json.dumps({'senderEmail': 'legacy@example.test'}), 'searchText': 'legacy', 'sourceFile': legacy_key}])
    old_manifest = index._source_snapshot()
    old_manifest[legacy_key].pop('mode')
    index._save_manifest(old_manifest)
    assert index.rebuild_smart(lambda _: None)['changed'] == 1
    assert EventListIndex(tmp_path).count_by_kind(DAY, DAY, ['outbound']) == {'outbound': 0}
    assert legacy.read_bytes() == before
    assert TransferService(tmp_path)._collect_outbound_legacy(DAY, DAY)[0]


def test_refresh_stores_existing_directory_identity_and_exception_mapping(tmp_path):
    users = tmp_path / 'cache/users.json'; users.parent.mkdir(parents=True)
    users.write_text(json.dumps([{'email': 'sender@example.test', 'name': 'Fixture Name', 'department': 'Fixture Department'}]))
    service, client, _factory = refresh(tmp_path)
    result = service.refresh_outbound(DAY, lambda _: None)
    row = json.loads(Path(result['path']).read_text())[0]
    assert row['senderName'] == 'Fixture Name' and row['dept'] == 'Fixture Department'
    # Canonical UI, normalization cache and Report all reuse the same resolver.
    assert TransferService(tmp_path)._collect_outbound(DAY, DAY)[0][0][2]['senderName'] == 'Fixture Name'


def test_legacy_collector_remains_explicitly_callable(tmp_path, monkeypatch):
    from backend.clients import legacy_collectors
    legacy_client = Mock()
    legacy_client.refresh_mail_day.return_value = {'count': 7}
    monkeypatch.setattr(legacy_collectors, 'MailScreenClient', Mock(return_value=legacy_client))
    result = RefreshService(tmp_path).refresh_outbound_legacy(DAY, lambda _: None)
    assert result == {'count': 7}
    legacy_client.refresh_mail_day.assert_called_once_with(str(DAY))


def test_fetcher_first_upgrade_cleans_legacy_index_before_saving_manifest(tmp_path, monkeypatch):
    service, _client, _factory = refresh(tmp_path)
    result = service.refresh_outbound(DAY, lambda _: None)
    legacy = tmp_path / 'cache/mailscreen/mailscreen_mail_2026-11-16.json'; legacy.parent.mkdir()
    legacy.write_text('{"items": []}')
    index = IndexService(tmp_path)
    monkeypatch.setattr(index.dashboard, 'warm_default', lambda: None)
    index.rebuild_all(lambda _: None)
    legacy_key = str(legacy.resolve())
    index._replace_event_file(legacy_key, [{'kind': 'outbound', 'recordId': 'legacy', 'eventTime': str(DAY),
        'rowJson': json.dumps({'senderEmail': 'legacy@example.test'}), 'searchText': 'legacy', 'sourceFile': legacy_key}], lambda _: None)
    # The Current read path already hides old derived MailScreen rows.
    assert EventListIndex(tmp_path).count_by_kind(DAY, DAY, ['outbound']) == {'outbound': 1}
    old = index._source_snapshot(); old[legacy_key].pop('mode'); index._save_manifest(old)
    monkeypatch.setattr(index, '_load_fetch_job', lambda _: {'status': 'completed', 'result': {'outbound': result}})
    index.rebuild_from_fetch_job('fixture', lambda _: None)
    with sqlite3.connect(tmp_path / 'cache/index/events_index.db') as db:
        assert db.execute('SELECT COUNT(*) FROM event_list_rows WHERE source_file=?', (legacy_key,)).fetchone()[0] == 0
    assert legacy.read_text() == '{"items": []}'
    assert index._load_manifest()[legacy_key]['mode'] == 'legacy-preserved'


def test_current_outbound_report_renders_pdf_and_keeps_canonical_results(tmp_path):
    service, _client, _factory = refresh(tmp_path)
    service.refresh_outbound(DAY, lambda _: None)
    report = ReportService(tmp_path)
    result = report.build(DAY, DAY, lambda _: None)
    output = Path(result['path'])
    payload = output.read_bytes()
    assert payload.startswith(b'%PDF') and payload.rstrip().endswith(b'%%EOF')
    assert b'/Type /Page' in payload


def test_raw_detail_joins_message_key_instead_of_stale_row_offsets(tmp_path):
    service, client, _factory = refresh(tmp_path)
    result = service.refresh_outbound(DAY, lambda _: None)
    # A reader between the two atomic file replacements must never associate a
    # different message solely because it occupies the old Raw offset.
    raw_path = Path(result['rawPath'])
    raw_path.write_text(json.dumps([event('other')] + events()))
    related = TransferService(tmp_path)._collect_outbound(DAY, DAY)[0][0][1]['events']
    assert related == events()


def test_current_normalized_message_drives_dashboard_export_and_learner(tmp_path, monkeypatch):
    from backend.services.dashboard import DashboardService
    from backend.services.learner.service import LearnerService
    from system_monitor.laborer import LaborerAgent
    from zipfile import ZipFile
    service, _client, _factory = refresh(tmp_path)
    service.refresh_outbound(DAY, lambda _: None)
    index = IndexService(tmp_path); monkeypatch.setattr(index.dashboard, 'warm_default', lambda: None)
    index.rebuild_scope('events', lambda _: None)
    trend = DashboardService(tmp_path).mix_trend(DAY, DAY)
    assert trend['totals']['Outbound Mail'] == 1
    assert trend['trend']['series']['Outbound Mail'] == [1]
    assert LearnerService(tmp_path).run('full', ['outbound'])['processedEvents'] == 1
    laborer = LaborerAgent.__new__(LaborerAgent); laborer.root = tmp_path
    exported = laborer._export({'kind': 'outbound', 'start': str(DAY), 'end': str(DAY)}, lambda _: None)
    assert exported['rows'] == 1
    with ZipFile(exported['path']) as archive:
        assert archive.testzip() is None
        xml = archive.read('xl/worksheets/sheet1.xml').decode()
        assert 'Partial Failed' in xml and 'sender@example.test' in xml and 'fixture subject' in xml
