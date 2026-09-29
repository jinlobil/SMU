import json
import sqlite3
from pathlib import Path
from zipfile import ZipFile

from backend.services.timeline import TimelineService
from backend.services.timeline_export import SHEET_ORDER, TimelineExportService


def _database(root: Path, rows: list[tuple]) -> None:
    path = root / "cache/index/timeline_index.db"
    path.parent.mkdir(parents=True)
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE timeline_events (time TEXT, source TEXT, user TEXT, user_id TEXT, dept TEXT, asset TEXT, event TEXT, direction TEXT, peer TEXT, summary TEXT, indicator TEXT, raw_json TEXT)")
        connection.executemany("INSERT INTO timeline_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)


def test_search_all_is_not_limited_by_timeline_group_item_cap(tmp_path: Path) -> None:
    rows = [(f"2026-09-28 12:00:{index % 60:02d}", "Detection", "tester", "tester", "IT", "PC1", "Rule", "Host", "10.0.0.1", "needle", str(index), "{}") for index in range(150)]
    _database(tmp_path, rows)
    events = TimelineService(tmp_path).search_all("tester", "needle", {"Detection"})
    assert len(events) == 150


def test_timeline_export_always_has_seven_sheets_and_actual_summary_bounds(tmp_path: Path) -> None:
    rows = [
        ("2026-08-12 09:14:21", "Detection", "tester", "tester", "IT", "PC1", "Rule A", "Host", "10.0.0.1", "alpha", "hash", json.dumps({"severity": "high", "action": "blocked"})),
        ("2026-09-28 17:35:42", "Firewall", "tester", "tester", "IT", "FW", "Rule B", "10.0.0.1:10 → 192.0.2.2:443", "192.0.2.2", "example", "none", json.dumps({"sourceIp": "10.0.0.1", "destinationIp": "192.0.2.2", "protocol": "TCP", "destinationPort": 443, "action": "allow"})),
    ]
    _database(tmp_path, rows)
    path = tmp_path / "timeline.xlsx"
    result = TimelineExportService(tmp_path).export("tester", "", set(SHEET_ORDER), path)
    assert result["sheets"] == ["Summary", *SHEET_ORDER]
    assert result["events"] == sum(result["counts"].values()) == 2
    assert result["start"] == "2026-08-12 09:14:21"
    assert result["end"] == "2026-09-28 17:35:42"
    with ZipFile(path) as workbook:
        xml = workbook.read("xl/workbook.xml").decode()
        assert xml.count("<sheet ") == 7
        assert "검색 결과가 없습니다." in workbook.read("xl/worksheets/sheet3.xml").decode()


def test_zero_result_export_still_creates_summary_and_six_source_sheets(tmp_path: Path) -> None:
    _database(tmp_path, [])
    path = tmp_path / "empty.xlsx"
    result = TimelineExportService(tmp_path).export("nobody", "", set(SHEET_ORDER), path)
    assert result["events"] == 0 and result["start"] is result["end"] is None
    assert result["sheets"] == ["Summary", *SHEET_ORDER]


def test_timeline_page_requests_backend_export_with_current_filters() -> None:
    page = (Path(__file__).resolve().parents[1] / "frontend/src/pages/TimelinePage.tsx").read_text(encoding="utf-8")
    assert 'fetch("/api/timeline/export"' in page
    assert "JSON.stringify(lastQuery)" in page
    assert "Excel 다운로드" in page
    assert "groups" not in page[page.index('fetch("/api/timeline/export"'):page.index('fetch("/api/timeline/export"') + 350]
