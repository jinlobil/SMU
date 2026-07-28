import sqlite3
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
    service.timeline.all_events = lambda _sources: [{"time":"2026-07-24 10:00:00","source":"File","user":"kim","userId":"kim","dept":"IT","asset":"PC1","event":"upload","direction":"out","peer":"example.com","summary":"계약서","indicator":"hash"}]
    messages=[]
    result=service.rebuild_all(messages.append)
    assert result["sensitive"] == 1 and result["timeline"] == 1
    with sqlite3.connect(tmp_path/"cache/index/app_cache.db") as db:
        assert db.execute("SELECT COUNT(*) FROM sensitive_files_index").fetchone()[0] == 1
        assert db.execute("SELECT value FROM legacy_data").fetchone()[0] == "keep-me"
    with sqlite3.connect(tmp_path/"cache/index/timeline_index.db") as db:
        assert db.execute("SELECT COUNT(*) FROM timeline_events").fetchone()[0] == 1
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
