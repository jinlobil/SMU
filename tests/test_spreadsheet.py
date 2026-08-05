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
