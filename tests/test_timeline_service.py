import json
import sqlite3
from datetime import date
from pathlib import Path

import pytest

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


def test_timeline_korean_name_search_finds_outbound_login_alias(tmp_path: Path):
    endpoint_path = tmp_path / "cache/endpoints.json"
    endpoint_path.parent.mkdir(parents=True)
    endpoint_path.write_text(json.dumps([{"associatedPerson": {"name": "김범수", "viaLogin": "LOCKNLOCK\\bskim"}}]), encoding="utf-8")
    database = tmp_path / "cache/index/timeline_index.db"
    database.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE timeline_events (time TEXT, source TEXT, user TEXT, user_id TEXT, dept TEXT, asset TEXT, event TEXT, direction TEXT, peer TEXT, summary TEXT, indicator TEXT)")
        connection.execute("INSERT INTO timeline_events VALUES (?,?,?,?,?,?,?,?,?,?,?)", (
            "2026-07-24 14:28:35", "Outbound Mail", "None", "bskim", "미분류", "bskim@locknlock.com",
            "성공", "bskim@locknlock.com → receiver@example.com", "receiver@example.com", "출장 항공권 견적", "None",
        ))

    result = TimelineService(tmp_path).search("김범수", "", {"Outbound Mail"})

    assert result["pagination"]["totalEvents"] == 1
    assert result["groups"][0]["items"][0]["user"] == "김범수"


def test_timeline_index_returns_raw_payload_when_available(tmp_path: Path):
    database = tmp_path / "cache/index/timeline_index.db"
    database.parent.mkdir(parents=True)
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE timeline_events (time TEXT, source TEXT, user TEXT, user_id TEXT, dept TEXT, asset TEXT, event TEXT, direction TEXT, peer TEXT, summary TEXT, indicator TEXT, raw_json TEXT)")
        connection.execute("INSERT INTO timeline_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (
            "2026-07-24", "File", "김범수", "bskim", "IT", "PC1", "탐지", "Host", "10.0.0.1", "계약서", "hash", json.dumps({"filename":"계약서.pdf"}),
        ))

    result = TimelineService(tmp_path).search("김범수", "", {"File"})

    assert result["groups"][0]["items"][0]["raw"]["filename"] == "계약서.pdf"


def test_timeline_sql_paginates_groups_before_loading_items(tmp_path: Path):
    database = tmp_path / "cache/index/timeline_index.db"
    database.parent.mkdir(parents=True)
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE timeline_events (time TEXT, source TEXT, user TEXT, user_id TEXT, dept TEXT, asset TEXT, event TEXT, direction TEXT, peer TEXT, summary TEXT, indicator TEXT, raw_json TEXT)")
        rows = []
        for minute in range(3):
            for second in range(120):
                rows.append((f"2026-07-24 14:0{minute}:{second % 60:02d}", "Detection", "kim", "kim", "IT", "PC1", f"Rule-{minute}", "Host", "10.0.0.1", "needle", "hash", "{}"))
        connection.executemany("INSERT INTO timeline_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)

    result = TimelineService(tmp_path).search("kim", "needle", {"Detection"}, offset=1, limit=1)

    assert result["pagination"] == {"offset": 1, "limit": 1, "totalGroups": 3, "totalEvents": 360}
    assert len(result["groups"]) == 1
    assert result["groups"][0]["count"] == 120
    assert len(result["groups"][0]["items"]) == 100
    assert result["source"] == "sqlite-index"


def test_timeline_index_uses_read_only_query_connection(tmp_path: Path):
    database = tmp_path / "cache/index/timeline_index.db"
    database.parent.mkdir(parents=True)
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE timeline_events (time TEXT, source TEXT, user TEXT, user_id TEXT, dept TEXT, asset TEXT, event TEXT, direction TEXT, peer TEXT, summary TEXT, indicator TEXT)")
    service = TimelineService(tmp_path)
    with service._read_connection() as connection:
        assert connection.execute("PRAGMA query_only").fetchone()[0] == 1
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("DELETE FROM timeline_events")


def test_timeline_hydrates_raw_payload_from_cache_for_legacy_index(tmp_path: Path):
    cache = tmp_path / "cache/mailscreen/mailscreen_mail_2026-07-24.json"
    cache.parent.mkdir(parents=True)
    original = {"date": "2026-07-24 14:28:35", "send_result": "성공", "subject": "출장 견적",
                "sender_email": "bskim@locknlock.com", "sender_name": "김범수",
                "sender_dept": "IT", "receiver": "receiver@example.com", "attach": "quote.pdf"}
    cache.write_text(json.dumps({"items": [original]}, ensure_ascii=False), encoding="utf-8")
    database = tmp_path / "cache/index/timeline_index.db"
    database.parent.mkdir(parents=True)
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE timeline_events (time TEXT, source TEXT, user TEXT, user_id TEXT, dept TEXT, asset TEXT, event TEXT, direction TEXT, peer TEXT, summary TEXT, indicator TEXT)")
        connection.execute("INSERT INTO timeline_events VALUES (?,?,?,?,?,?,?,?,?,?,?)", (
            "2026-07-24 14:28:35", "Outbound Mail", "김범수", "bskim", "IT",
            "bskim@locknlock.com", "성공", "bskim@locknlock.com → receiver@example.com",
            "receiver@example.com", "출장 견적", "quote.pdf",
        ))

    result = TimelineService(tmp_path).search("김범수", "", {"Outbound Mail"})

    assert result["groups"][0]["items"][0]["raw"] == original


def test_timeline_all_events_includes_outbound_and_dlp(tmp_path: Path):
    service = TimelineService(tmp_path)
    service.date_bounds = lambda: (date(2026, 7, 22), date(2026, 7, 28))
    service.transfers._collect_outbound = lambda _start, _end: ([
        (
        "out-1", {}, {"date":"2026-07-24", "senderName":"kim", "senderEmail":"kim@example.com", "dept":"IT", "sendResult":"성공", "receiver":"r@example.com", "subject":"메일", "attachment":"None"}
        )
    ], [])
    service.transfers._collect_dlp = lambda _start, _end: ([
        (
        "dlp-1", {}, {"time":"2026-07-24", "username":"kim", "dept":"IT", "computer":"PC1", "event":"탐지", "source":"a.txt", "destination":"USB", "sourceIp":"10.0.0.1", "destinationDetail":"복사", "fileHash":"hash"}
        )
    ], [])

    events = service.all_events({"Outbound Mail", "File"})

    assert {event["source"] for event in events} == {"Outbound Mail", "File"}
