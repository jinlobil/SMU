import json
import sqlite3
from pathlib import Path

from backend.services.timeline import TimelineService


def test_timeline_search_groups_sources_and_filters_identity(tmp_path: Path):
    path = tmp_path / "cache/detections/2026-07-22.json"; path.parent.mkdir(parents=True); path.write_text(json.dumps([{"time": "2026-07-22T01:01:10Z", "sensor": {"type": "endpoint"}, "detectionDescription": {"createdReasonId": "Rule"}, "rawData": {"meta_hostname": "PC-1", "process_name": "bad.exe"}}, {"time": "2026-07-22T01:01:30Z", "sensor": {"type": "endpoint"}, "detectionDescription": {"createdReasonId": "Rule"}, "rawData": {"meta_hostname": "PC-1", "process_name": "bad.exe"}}]), encoding="utf-8")
    result = TimelineService(tmp_path).search("PC-1", "bad.exe", {"Detection"})
    assert result["pagination"]["totalEvents"] == 2
    assert result["pagination"]["totalGroups"] == 1
    assert result["groups"][0]["count"] == 2
    assert result["source"] == "cache-scan"


def test_timeline_search_uses_existing_sqlite_index(tmp_path: Path):
    database = tmp_path / "cache/index/timeline_index.db"
    database.parent.mkdir(parents=True)
    with sqlite3.connect(database) as connection:
        connection.execute("""CREATE TABLE timeline_events (
            event_key TEXT, source TEXT, time TEXT, bucket TEXT, user TEXT, user_id TEXT,
            dept TEXT, asset TEXT, event TEXT, direction TEXT, peer TEXT, summary TEXT,
            indicator TEXT, cache_file TEXT, row_index INTEGER)""")
        connection.execute(
            "INSERT INTO timeline_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("key", "Detection", "2026-07-22 10:00:00", "2026-07-22 10:00", "홍길동", "hong", "보안팀", "PC-1", "Rule", "Host", "10.0.0.1", "bad.exe", "hash", "cache.json", 0),
        )

    result = TimelineService(tmp_path).search("hong", "bad.exe", {"Detection"})

    assert result["source"] == "sqlite-index"
    assert result["pagination"]["totalEvents"] == 1
