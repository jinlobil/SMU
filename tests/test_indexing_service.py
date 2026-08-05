import sqlite3
from datetime import date
import pytest
from backend.services.indexing import IndexService


def test_rebuild_all_creates_search_indexes(tmp_path):
    database = tmp_path/"cache/index/app_cache.db"
    database.parent.mkdir(parents=True)
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE legacy_data (value TEXT)")
        db.execute("INSERT INTO legacy_data VALUES ('keep-me')")
    reader = sqlite3.connect(database)  # Simulates the web/desktop process holding the DB open on Windows.
    service = IndexService(tmp_path)
    service.sensitive.file_records = lambda _sources: [{"id":"file-1","source":"DLP","category":"계약","time":"2026-07-24 10:00:00","name":"계약서.pdf","raw":{"x":1}}]
    service.sensitive.site_records = lambda: []
    service.timeline.all_events = lambda _sources: [{"time":"2026-07-24 10:00:00","source":"File","user":"kim","userId":"kim","dept":"IT","asset":"PC1","event":"upload","direction":"out","peer":"example.com","summary":"계약서","indicator":"hash","raw":{"filename":"계약서.pdf"}}]
    messages=[]
    result=service.rebuild_all(messages.append)
    assert result["sensitive"] == 1 and result["timeline"] == 1
    with sqlite3.connect(tmp_path/"cache/index/app_cache.db") as db:
        assert db.execute("SELECT COUNT(*) FROM sensitive_files_index").fetchone()[0] == 1
        assert db.execute("SELECT value FROM legacy_data").fetchone()[0] == "keep-me"
    with sqlite3.connect(tmp_path/"cache/index/timeline_index.db") as db:
        assert db.execute("SELECT COUNT(*) FROM timeline_events").fetchone()[0] == 1
        assert "계약서.pdf" in db.execute("SELECT raw_json FROM timeline_events").fetchone()[0]
    assert "완료" in messages[-1]
    reader.close()


def test_rebuild_removes_abandoned_legacy_temp_database(tmp_path):
    stale = tmp_path / "cache/index/app_cache.db.tmp"
    stale.parent.mkdir(parents=True)
    stale.write_bytes(b"stale")
    service = IndexService(tmp_path)
    service.sensitive.file_records = lambda _sources: []
    service.sensitive.site_records = lambda: []
    service.timeline.all_events = lambda _sources: []

    messages = []
    service.rebuild_all(messages.append)

    assert not stale.exists()
    assert any("임시 파일 정리" in message for message in messages)


def test_sensitive_index_defensively_deduplicates_semantic_site_key(tmp_path):
    service = IndexService(tmp_path)
    records = [
        {"id": "site-new", "source": "DLP", "category": "SNS", "time": "2026-07-28", "site": "instagram.com", "dept": " 마케팅 ", "user": "kim", "raw": {}},
        {"id": "site-old", "source": "DLP", "category": "SNS", "time": "2026-07-27", "site": "instagram.com", "dept": "마케팅", "user": "kim", "raw": {}},
    ]

    service._build_sensitive([], records)

    with sqlite3.connect(tmp_path / "cache/index/app_cache.db") as db:
        row = db.execute("SELECT COUNT(*), MAX(event_time) FROM sensitive_sites_index").fetchone()
    assert row == (1, "2026-07-28")


def test_incremental_update_preserves_older_timeline_rows(tmp_path):
    service = IndexService(tmp_path)
    old = {"time":"2026-07-20 10:00:00","source":"File","user":"old","raw":{}}
    replaced = {"time":"2026-07-30 10:00:00","source":"File","user":"before","raw":{}}
    service._build_timeline([old, replaced])
    current = {"time":"2026-07-30 11:00:00","source":"File","user":"after","raw":{}}

    messages = []
    service._update_timeline_range([current], date(2026, 7, 30), date(2026, 7, 31), messages.append)

    with sqlite3.connect(tmp_path/"cache/index/timeline_index.db") as db:
        rows = db.execute("SELECT time,user FROM timeline_events ORDER BY time").fetchall()
    assert rows == [("2026-07-20 10:00:00", "old"), ("2026-07-30 11:00:00", "after")]
    assert any("1/1건" in message for message in messages)


def test_smart_rebuild_skips_unchanged_files_and_indexes_only_changed_file(tmp_path):
    first = tmp_path/"cache/dlp/2026-07-30.jsonl"
    second = tmp_path/"cache/dlp/2026-07-31.jsonl"
    first.parent.mkdir(parents=True)
    first.write_text("{}\n", encoding="utf-8")
    second.write_text("{}\n", encoding="utf-8")
    service = IndexService(tmp_path)
    service._build_sensitive([], [])
    service._build_timeline([])
    service._save_manifest(service._source_snapshot())
    second.write_text('{"changed":true}\n', encoding="utf-8")
    service.timeline.events_between = lambda start,end,sources,progress: []
    service.sensitive.file_records = lambda sources,start,end,progress: []
    service.sensitive.site_records = lambda start,end,progress: []
    service.dashboard.warm_default = lambda: None

    messages = []
    result = service.rebuild_smart(messages.append)

    assert result["mode"] == "smart"
    assert result["changed"] == 1
    assert result["skipped"] == 3
    assert any("변경 1개" in message and "유지 3개" in message for message in messages)


def test_smart_rebuild_does_no_parsing_when_manifest_is_current(tmp_path):
    source = tmp_path/"cache/dlp/2026-07-31.jsonl"
    source.parent.mkdir(parents=True)
    source.write_text("{}\n", encoding="utf-8")
    service = IndexService(tmp_path)
    service._build_sensitive([], [])
    service._build_timeline([])
    service._save_manifest(service._source_snapshot())
    service.timeline.events_between = lambda *_args: (_ for _ in ()).throw(AssertionError("must skip"))

    result = service.rebuild_smart(lambda _message: None)

    assert result == {"mode": "smart", "changed": 0, "removed": 0, "skipped": 3, "dashboard": False}


def test_smart_rebuild_never_automatically_runs_full_without_manifest(tmp_path):
    service = IndexService(tmp_path)
    service.rebuild_all = lambda _progress: (_ for _ in ()).throw(AssertionError("must not auto rebuild"))
    messages = []

    with pytest.raises(RuntimeError, match="수동 실행"):
        service.rebuild_smart(messages.append)

    assert any("manifest" in message for message in messages)


def test_smart_rebuild_does_not_fail_or_run_full_for_rule_changes(tmp_path):
    source = tmp_path/"cache/dlp/2026-07-31.jsonl"
    rule = tmp_path/"env/exceptions/user_exceptions.json"
    source.parent.mkdir(parents=True); rule.parent.mkdir(parents=True)
    source.write_text("{}\n", encoding="utf-8"); rule.write_text('{"version":1,"items":[]}', encoding="utf-8")
    service = IndexService(tmp_path)
    service._build_sensitive([], []); service._build_timeline([]); service._save_manifest(service._source_snapshot())
    rule.write_text('{"version":1,"items":[{}]}', encoding="utf-8")
    service.rebuild_all = lambda _progress: (_ for _ in ()).throw(AssertionError("must not auto rebuild"))
    messages = []

    result = service.rebuild_smart(messages.append)

    assert result["mode"] == "smart"
    assert result["changed"] == 0
    assert any("자동 전체 인덱싱 없이" in message for message in messages)
    assert service._load_manifest() == service._source_snapshot()


def test_detection_list_scope_builds_real_list_index_without_raw_payload(tmp_path):
    source = tmp_path / "cache/detections/2026-08-04.json"
    source.parent.mkdir(parents=True)
    source.write_text("[]", encoding="utf-8")
    service = IndexService(tmp_path)
    service.detections._events = lambda start, end, progress=None: ([
        ("det-1", {"raw": "large"}, {"id": "det-1", "time": "2026-08-04 09:00:00", "hostname": "PC1", "dept": "SOC", "username": "kim", "_sourceFile": str(source.resolve())})
    ], [source.name])
    service.email._collect_xdr = lambda start, end, progress=None: ([], [])
    service.email._collect_inbound = lambda start, end, progress=None: ([], [])
    service.transfers._collect_outbound = lambda start, end, progress=None: ([], [])
    service.transfers._collect_dlp = lambda start, end, progress=None: ([], [])
    messages = []

    result = service.rebuild_scope("events", messages.append)

    assert result["events"] == 1
    with sqlite3.connect(tmp_path / "cache/index/events_index.db") as db:
        row = db.execute("SELECT kind, record_id, row_json, search_text, source_file FROM event_list_rows").fetchone()
    assert row[0:2] == ("detections", "det-1")
    assert "hostname" in row[2]
    assert "large" not in row[2]
    assert str(source.resolve()) == row[4]
    assert any("Detection 리스트 인덱스 SQLite 기록" in message for message in messages)
