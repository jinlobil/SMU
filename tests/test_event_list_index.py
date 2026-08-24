import json
import sqlite3
from datetime import date

import pytest

from backend.services.event_list_index import EventListIndex
from backend.services.event_list_schema import DISPLAY_COLUMNS, FIELD_COLUMNS, SCHEMA_VERSION
from backend.services.indexing import IndexService


def _make_index(tmp_path):
    path = tmp_path / "cache" / "index" / "events_index.db"
    path.parent.mkdir(parents=True)
    with sqlite3.connect(path) as db:
        db.execute("""CREATE TABLE event_list_rows (
            kind TEXT, record_id TEXT, event_time TEXT, search_text TEXT,
            row_json TEXT, source_file TEXT, PRIMARY KEY(kind, record_id)
        )""")
        db.execute("CREATE INDEX idx_web_event_list_kind_time ON event_list_rows(kind, event_time DESC)")
        rows = [
            ("detections", "a", "2026-08-01 10:00:00", "alpha host one", {"id": "a", "time": "2026-08-01 10:00:00", "hostname": "Alpha", "rule": "One"}, "/cache/01.json"),
            ("detections", "b", "2026-08-02 10:00:00", "beta host two", {"id": "b", "time": "2026-08-02 10:00:00", "hostname": "beta", "rule": "Two"}, "/cache/02.json"),
            ("detections", "c", "2026-08-02 11:00:00", "beta host blocked", {"id": "c", "time": "2026-08-02 11:00:00", "hostname": "beta", "rule": "Blocked"}, "/cache/02.json"),
            ("detections", "z", "2026-08-03 00:00:00", "outside", {"id": "z", "time": "2026-08-03 00:00:00", "hostname": "z", "rule": "Outside"}, "/cache/03.json"),
        ]
        db.executemany(
            "INSERT INTO event_list_rows VALUES (?,?,?,?,?,?)",
            [(kind, record_id, event_time, search, json.dumps(row), source) for kind, record_id, event_time, search, row, source in rows],
        )
    return EventListIndex(tmp_path)


def test_sql_filter_sort_count_pagination_and_source_semantics(tmp_path):
    index = _make_index(tmp_path)
    result = index.require_records(
        "detections", date(2026, 8, 1), date(2026, 8, 2),
        [{"field": "hostname", "query": "BETA", "mode": "include"}, {"field": "rule", "query": "blocked", "mode": "exclude"}],
        page=1, page_size=1, sort="time", direction="desc", fields={"time", "hostname", "rule"},
    )
    assert [row["id"] for row in result["items"]] == ["b"]
    assert result["pagination"] == {"page": 1, "pageSize": 1, "total": 1, "totalPages": 1}
    # source.files historically describes every indexed source in the selected range,
    # not only files represented by the current filtered page.
    assert result["source"]["files"] == ["01.json", "02.json"]


def test_sql_sort_has_stable_record_id_tie_breaker_and_raw_data_uses_search_text(tmp_path):
    index = _make_index(tmp_path)
    result = index.require_records(
        "detections", date(2026, 8, 2), date(2026, 8, 2),
        [{"field": "rawData", "query": "host", "mode": "include"}],
        page=1, page_size=10, sort="hostname", direction="asc", fields={"time", "hostname", "rule"},
    )
    assert [row["id"] for row in result["items"]] == ["b", "c"]


def test_sql_field_and_direction_are_allowlisted(tmp_path):
    index = _make_index(tmp_path)
    with pytest.raises(ValueError, match="Unsupported sort"):
        index.require_records("detections", date(2026, 8, 1), date(2026, 8, 2), [], 1, 10, "hostname; DROP TABLE event_list_rows", "asc", {"hostname"})
    with pytest.raises(ValueError, match="Unsupported direction"):
        index.require_records("detections", date(2026, 8, 1), date(2026, 8, 2), [], 1, 10, "hostname", "desc; DROP", {"hostname"})


def test_date_range_query_uses_kind_event_time_index(tmp_path):
    index = _make_index(tmp_path)
    with index._read_connection() as db:
        plan = db.execute(
            "EXPLAIN QUERY PLAN SELECT record_id FROM event_list_rows WHERE kind=? AND event_time>=? AND event_time<?",
            ("detections", "2026-08-01", "2026-08-03"),
        ).fetchall()
    assert any("idx_web_event_list_kind_time" in str(row[3]) for row in plan)


@pytest.mark.parametrize(
    ("kind", "sort_field"),
    [("detections", "time"), ("xdr", "time"), ("inbound", "received"), ("outbound", "date"), ("dlp", "time")],
)
def test_all_event_list_kinds_keep_search_sort_and_pagination_contract(tmp_path, kind, sort_field):
    index = _make_index(tmp_path)
    with sqlite3.connect(index.path) as db:
        db.execute("DELETE FROM event_list_rows")
        rows = []
        for number in range(3):
            value = f"2026-08-0{number + 1} 10:00:00"
            row = {"id": f"{kind}-{number}", sort_field: value, "subject": "needle" if number else "other"}
            rows.append((kind, row["id"], value, json.dumps(row).lower(), json.dumps(row), f"/{kind}-{number}.json"))
        db.executemany("INSERT INTO event_list_rows VALUES (?,?,?,?,?,?)", rows)
    result = index.require_records(
        kind, date(2026, 8, 1), date(2026, 8, 3), [{"field": "subject", "query": "needle"}],
        page=1, page_size=1, sort=sort_field, direction="desc", fields={sort_field, "subject"},
    )
    assert result["pagination"]["total"] == 2
    assert result["pagination"]["totalPages"] == 2
    assert result["items"][0]["id"] == f"{kind}-2"


def test_full_build_creates_versioned_structured_display_columns(tmp_path):
    service = IndexService(tmp_path)
    service._build_events_index([{
        "kind": "detections", "recordId": "one", "eventTime": "2026-08-01 01:00:00",
        "searchText": "alpha", "rowJson": json.dumps({"id": "one", "hostname": "Alpha", "time": "2026-08-01 01:00:00"}),
        "sourceFile": "/cache/01.json",
    }])
    with sqlite3.connect(tmp_path / "cache/index/events_index.db") as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(event_list_rows)")}
        version = db.execute("SELECT value FROM index_metadata WHERE key='event_list_schema_version'").fetchone()[0]
        hostname = db.execute(f"SELECT {FIELD_COLUMNS['hostname']} FROM event_list_rows").fetchone()[0]
    assert set(DISPLAY_COLUMNS) <= columns
    assert version == SCHEMA_VERSION
    assert hostname == "Alpha"


def test_incremental_indexing_migrates_legacy_database_without_raw_reindex(tmp_path):
    index = _make_index(tmp_path)
    service = IndexService(tmp_path)
    service._ensure_events_index(lambda _message: None)
    with sqlite3.connect(index.path) as db:
        version = db.execute("SELECT value FROM index_metadata WHERE key='event_list_schema_version'").fetchone()[0]
        hostname = db.execute(f"SELECT {FIELD_COLUMNS['hostname']} FROM event_list_rows WHERE record_id='b'").fetchone()[0]
    assert version == SCHEMA_VERSION
    assert hostname == "beta"
