from pathlib import Path
from zipfile import ZipFile
from datetime import date

from fastapi.responses import FileResponse, JSONResponse

import backend.app as app_module
from backend.services.spreadsheet import write_xlsx


def test_write_xlsx_creates_excel_workbook_with_headers_and_rows(tmp_path: Path) -> None:
    path = tmp_path / "export.xlsx"

    columns = write_xlsx(path, [{"name": "테스트", "count": 3, "details": {"ok": True}}])

    assert columns == ["name", "count", "details"]
    assert path.read_bytes().startswith(b"PK")
    with ZipFile(path) as workbook:
        assert "xl/workbook.xml" in workbook.namelist()
        sheet = workbook.read("xl/worksheets/sheet1.xml").decode("utf-8")
    assert "name" in sheet
    assert "테스트" in sheet
    assert '{"ok": true}' in sheet


def test_write_xlsx_handles_empty_export(tmp_path: Path) -> None:
    path = tmp_path / "empty.xlsx"

    assert write_xlsx(path, []) == []
    assert path.exists()


def test_config_export_returns_xlsx_download(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(app_module, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(app_module.detection_service, "_events", lambda _start, _end: ([("1", {}, {"host": "PC-1"})], {}))

    response = app_module.export_config_data("detections", date(2026, 7, 29), date(2026, 7, 30))

    assert isinstance(response, FileResponse)
    assert Path(response.path).suffix == ".xlsx"
    assert response.media_type == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    assert Path(response.path).exists()


def test_config_export_rejects_reversed_range() -> None:
    response = app_module.export_config_data("detections", date(2026, 7, 30), date(2026, 7, 29))

    assert isinstance(response, JSONResponse)
    assert response.status_code == 400


def test_write_xlsx_respects_selected_columns_and_friendly_headers(tmp_path: Path) -> None:
    path = tmp_path / "selected.xlsx"

    columns = write_xlsx(path, [{"time": "2026-08-05", "hostname": "PC-1", "sha256": "abc"}], columns=["hostname", "time"], headers={"hostname": "Hostname", "time": "Time"})

    assert columns == ["hostname", "time"]
    with ZipFile(path) as workbook:
        sheet = workbook.read("xl/worksheets/sheet1.xml").decode("utf-8")
    assert "Hostname" in sheet
    assert "Time" in sheet
    assert "PC-1" in sheet
    assert "abc" not in sheet


def test_export_schema_and_job_payload_include_selected_columns(monkeypatch) -> None:
    captured = {}
    monkeypatch.setattr(app_module.watchdog_manager, "start_laborer_job", lambda job_type, **payload: captured.setdefault("value", {"job_type": job_type, **payload}))

    schema = app_module.export_schema()
    response = app_module.start_export({"kind": "detections", "start": "2026-08-01", "end": "2026-08-05", "columns": ["hostname", "time", "notReal"]})

    assert schema["data"]["exports"]["detections"]["label"] == "Detection XLSX"
    assert response["data"]["job_type"] == "export"
    assert captured["value"]["columns"] == ["hostname", "time"]


def test_report_job_payload_includes_selected_sections(monkeypatch) -> None:
    captured = {}
    monkeypatch.setattr(app_module.watchdog_manager, "start_laborer_job", lambda job_type, **payload: captured.setdefault("value", {"job_type": job_type, **payload}))

    response = app_module.start_report({"start": "2026-08-01", "end": "2026-08-05", "sections": ["detections", "dlp", "bad"]})

    assert response["data"]["job_type"] == "report"
    assert captured["value"]["sections"] == ["detections", "dlp"]
