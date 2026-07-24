import sqlite3
from backend.services.indexing import IndexService


def test_rebuild_all_creates_search_indexes(tmp_path):
    service = IndexService(tmp_path)
    service.sensitive.file_records = lambda _sources: [{"id":"file-1","source":"DLP","category":"계약","time":"2026-07-24 10:00:00","name":"계약서.pdf","raw":{"x":1}}]
    service.sensitive.site_records = lambda: []
    service.timeline.all_events = lambda _sources: [{"time":"2026-07-24 10:00:00","source":"File","user":"kim","userId":"kim","dept":"IT","asset":"PC1","event":"upload","direction":"out","peer":"example.com","summary":"계약서","indicator":"hash"}]
    messages=[]
    result=service.rebuild_all(messages.append)
    assert result["sensitive"] == 1 and result["timeline"] == 1
    with sqlite3.connect(tmp_path/"cache/index/app_cache.db") as db:
        assert db.execute("SELECT COUNT(*) FROM sensitive_files_index").fetchone()[0] == 1
    with sqlite3.connect(tmp_path/"cache/index/timeline_index.db") as db:
        assert db.execute("SELECT COUNT(*) FROM timeline_events").fetchone()[0] == 1
    assert "완료" in messages[-1]
