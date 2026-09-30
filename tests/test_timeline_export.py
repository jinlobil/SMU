import json
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path
from zipfile import ZipFile

from backend.services.timeline import TimelineService
from backend.services.timeline_export import SHEET_ORDER, TimelineExportService
from system_monitor.laborer import LaborerAgent


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
        summary = workbook.read("xl/worksheets/sheet1.xml").decode()
        assert "TIMELINE" in summary and 'ref="A1:B1"' in summary
        root = ET.fromstring(summary)
        namespace = {"x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
        row_numbers = [int(row.attrib["r"]) for row in root.findall("x:sheetData/x:row", namespace)]
        assert row_numbers == sorted(row_numbers)
        for row in root.findall("x:sheetData/x:row", namespace):
            columns = [cell.attrib["r"].rstrip("0123456789") for cell in row.findall("x:c", namespace)]
            assert columns == sorted(columns)
        assert "autoFilter" not in summary
        assert "검색 키워드" not in summary and "선택 Source" not in summary
        assert "데이터 시작일" in summary and "데이터 종료일" in summary
        assert "autoFilter" in workbook.read("xl/worksheets/sheet2.xml").decode()
        assert "검색 결과가 없습니다." in workbook.read("xl/worksheets/sheet3.xml").decode()


def test_zero_result_export_still_creates_summary_and_six_source_sheets(tmp_path: Path) -> None:
    _database(tmp_path, [])
    path = tmp_path / "empty.xlsx"
    result = TimelineExportService(tmp_path).export("nobody", "", set(SHEET_ORDER), path)
    assert result["events"] == 0 and result["start"] is result["end"] is None
    assert result["sheets"] == ["Summary", *SHEET_ORDER]


def test_timeline_page_requests_backend_export_with_current_filters() -> None:
    page = (Path(__file__).resolve().parents[1] / "frontend/src/pages/TimelinePage.tsx").read_text(encoding="utf-8")
    assert 'fetch("/api/jobs/export/timeline"' in page
    assert 'fetch(`/api/jobs/${job.id}`)' in page
    assert "/api/config/export/file/" in page
    assert "JSON.stringify(lastQuery)" in page
    assert "Excel 다운로드" in page
    assert 'className="refresh-button"' in page


def test_summary_resolves_user_and_all_endpoint_values(tmp_path: Path) -> None:
    cache = tmp_path / "cache"; cache.mkdir()
    (cache / "users.json").write_text(json.dumps([{"id": "user-1", "name": "Example User", "email": "user@example.com", "exchangeLogin": "example"}]), encoding="utf-8")
    (cache / "endpoints.json").write_text(json.dumps([
        {"hostname": "PC-001", "ipv4Addresses": ["192.0.2.10", "192.0.2.11"], "associatedPerson": {"id": "user-1", "name": "Example User"}},
        {"hostname": "PC-002", "ipv4Addresses": ["198.51.100.20"], "associatedPerson": {"id": "user-1", "name": "Example User"}},
    ]), encoding="utf-8")
    _database(tmp_path, [])
    path = tmp_path / "identity.xlsx"
    TimelineExportService(tmp_path).export("example", "", set(SHEET_ORDER), path)
    with ZipFile(path) as workbook:
        summary = workbook.read("xl/worksheets/sheet1.xml").decode()
    for value in ("Example User", "user@example.com", "PC-001", "PC-002", "192.0.2.10", "192.0.2.11", "198.51.100.20"):
        assert value in summary


def test_duplicate_users_resolve_endpoints_by_nonempty_exact_id_only(tmp_path: Path) -> None:
    cache = tmp_path / "cache"; cache.mkdir()
    (cache / "users.json").write_text(json.dumps([
        {"id": "custom-user", "name": "황현준", "email": "hj.hwang4@locknlock.com", "exchangeLogin": ""},
        {"id": "44af55de-09be-404f-a322-ab4aaaa79fb5", "name": "황현준(sk쉴더스)", "email": "hj.hwang4@locknlock.com", "exchangeLogin": "hj.hwang4"},
    ], ensure_ascii=False), encoding="utf-8")
    (cache / "endpoints.json").write_text(json.dumps([
        {"hostname": "HWANGHYEONJUN", "ipv4Addresses": ["100.64.0.1", "101.1.3.50"], "associatedPerson": {"id": "44af55de-09be-404f-a322-ab4aaaa79fb5"}},
        {"hostname": "UNRELATED-SERVER", "ipv4Addresses": ["203.0.113.99"], "associatedPerson": {"id": "unrelated-user"}},
        {"hostname": "EMPTY-ID-SERVER", "ipv4Addresses": ["198.51.100.99"], "associatedPerson": {"id": "", "name": ""}},
    ], ensure_ascii=False), encoding="utf-8")
    _database(tmp_path, [])
    path = tmp_path / "identity-exact.xlsx"

    TimelineExportService(tmp_path).export("황현준", "", set(SHEET_ORDER), path)

    with ZipFile(path) as workbook:
        summary = workbook.read("xl/worksheets/sheet1.xml").decode()
    for value in ("황현준", "hj.hwang4@locknlock.com", "HWANGHYEONJUN", "100.64.0.1", "101.1.3.50"):
        assert value in summary
    for unrelated in ("UNRELATED-SERVER", "203.0.113.99", "EMPTY-ID-SERVER", "198.51.100.99"):
        assert unrelated not in summary


def test_name_without_department_suffix_resolves_user_and_endpoint_by_exact_id(tmp_path: Path) -> None:
    cache = tmp_path / "cache"; cache.mkdir()
    user_id = "04e91905-324a-487a-b74d-bd631221f50e"
    (cache / "users.json").write_text(json.dumps([
        {"id": user_id, "name": "서소리[ERP파트]", "email": "sori.seo@locknlock.com", "exchangeLogin": "sori.seo"},
    ], ensure_ascii=False), encoding="utf-8")
    (cache / "endpoints.json").write_text(json.dumps([
        {"hostname": "SEOSORI1", "ipv4Addresses": ["100.64.0.1", "101.1.4.82", "101.1.2.59"], "associatedPerson": {"id": user_id}},
        {"hostname": "OTHER-PC", "ipv4Addresses": ["203.0.113.5"], "associatedPerson": {"id": "different-id"}},
    ], ensure_ascii=False), encoding="utf-8")
    _database(tmp_path, [])
    path = tmp_path / "department-suffix.xlsx"

    TimelineExportService(tmp_path).export("서소리", "", set(SHEET_ORDER), path)

    with ZipFile(path) as workbook:
        summary = workbook.read("xl/worksheets/sheet1.xml").decode()
    for value in ("서소리", "sori.seo@locknlock.com", "SEOSORI1", "100.64.0.1", "101.1.4.82", "101.1.2.59"):
        assert value in summary
    assert "서소리[ERP파트]" not in summary
    assert "OTHER-PC" not in summary and "203.0.113.5" not in summary


def test_summary_uses_real_two_column_cells_with_complete_border_styles(tmp_path: Path) -> None:
    _database(tmp_path, [])
    path = tmp_path / "compact.xlsx"
    TimelineExportService(tmp_path).export("nobody", "", set(SHEET_ORDER), path)
    with ZipFile(path) as workbook:
        summary = workbook.read("xl/worksheets/sheet1.xml").decode()
    root = ET.fromstring(summary)
    namespace = {"x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    merges = [node.attrib["ref"] for node in root.findall("x:mergeCells/x:mergeCell", namespace)]
    assert merges == ["A1:B1"]
    row = root.find("x:sheetData/x:row[@r='13']", namespace)
    assert [(cell.attrib["r"], cell.attrib["s"]) for cell in row.findall("x:c", namespace)] == [("A13", "6"), ("B13", "9")]


def test_xlsx_generation_is_dispatched_to_laborer_not_fastapi() -> None:
    root = Path(__file__).resolve().parents[1]
    app = (root / "backend/app.py").read_text(encoding="utf-8")
    laborer = (root / "system_monitor/laborer.py").read_text(encoding="utf-8")
    assert 'start_laborer_job(\n        "timeline_export"' in app
    assert "TimelineExportService(self.root).export" in laborer
    assert "timeline_export_service.export" not in app


def test_laborer_completes_timeline_export_job(tmp_path: Path, monkeypatch) -> None:
    agent = LaborerAgent(tmp_path)
    monkeypatch.setattr(TimelineExportService, "export", lambda self, user, keyword, sources, path: (
        path.parent.mkdir(parents=True, exist_ok=True), path.write_bytes(b"xlsx"),
        {"events": 12, "sheets": ["Summary", *SHEET_ORDER]},
    )[-1])
    job = agent.submit("timeline_export", {"user": "tester", "keyword": "", "sources": ["Detection"]})
    monkeypatch.setattr(agent.wake, "wait", lambda _timeout: agent.stop.set())

    agent.worker_loop()

    completed = agent.get(job["id"])
    assert completed["status"] == "completed"
    assert completed["result"]["rows"] == 12
    assert completed["result"]["sheets"] == ["Summary", *SHEET_ORDER]
