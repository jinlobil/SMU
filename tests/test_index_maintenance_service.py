import sqlite3

import pytest

from backend.services.index_maintenance import IndexMaintenanceService


def test_index_maintenance_reports_three_friendly_databases(tmp_path):
    service = IndexMaintenanceService(tmp_path)
    data = service.databases()

    assert set(data) == {"app", "timeline", "events"}
    assert data["app"]["label"] == "민감 콘텐츠 인덱스 DB"
    assert data["timeline"]["label"] == "타임라인 인덱스 DB"
    assert data["events"]["label"] == "Detection 리스트 인덱스 DB"
    assert all(not item["exists"] for item in data.values())


def test_vacuum_optimizes_existing_database_and_skips_missing(tmp_path):
    index_dir = tmp_path / "cache/index"
    index_dir.mkdir(parents=True)
    app_db = index_dir / "app_cache.db"
    with sqlite3.connect(app_db) as connection:
        connection.execute("CREATE TABLE sample (id INTEGER PRIMARY KEY, value TEXT)")
        connection.executemany("INSERT INTO sample(value) VALUES (?)", [("x" * 200,) for _ in range(50)])
        connection.execute("DELETE FROM sample")

    messages = []
    result = IndexMaintenanceService(tmp_path).vacuum("all", messages.append)
    statuses = {item["target"]: item["status"] for item in result["databases"]}

    assert statuses == {"app": "optimized", "timeline": "missing", "events": "missing"}
    assert any("민감 콘텐츠 인덱스 DB 최적화 완료" in message for message in messages)
    assert any("타임라인 인덱스 DB 최적화 건너뜀" in message for message in messages)


def test_vacuum_rejects_unknown_database(tmp_path):
    with pytest.raises(ValueError, match="지원하지 않는 인덱스 DB"):
        IndexMaintenanceService(tmp_path).vacuum("raw", lambda _message: None)
