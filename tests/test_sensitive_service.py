import json
import sqlite3
from pathlib import Path

from backend.services.sensitive import SensitiveService


def test_sensitive_files_and_sites_are_classified(tmp_path: Path):
    dlp = tmp_path / "cache/dlp/2026-07-22.jsonl"; dlp.parent.mkdir(parents=True); dlp.write_text("\n".join([json.dumps({"eventtimelocal": "2026-07-22 10:00:00", "filename": "C:/docs/resume.pdf", "destination": "https://drive.google.com/upload", "machine_name": "PC"})]) + "\n", encoding="utf-8")
    service = SensitiveService(tmp_path)
    files = service.query("files", "전체", "", {"DLP"}, 0, 500)
    sites = service.query("sites", "전체", "", {"DLP"}, 0, 500)
    assert files["items"][0]["category"] == "이직 / 취업"
    assert files["items"][0]["name"] == "resume.pdf"
    assert sites["items"][0]["category"] == "개인 클라우드 / 파일전송"


def test_sensitive_service_loads_complete_legacy_category_specs(tmp_path: Path):
    (tmp_path / "uimain_window.py").write_text("SENSITIVE_FILE_CATEGORY_SPECS = [('Custom', ['needle'])]\nSENSITIVE_SITE_CATEGORY_SPECS = [('Site', ['example.com'])]\n", encoding="utf-8")
    service = SensitiveService(tmp_path)
    assert service.file_categories == {"Custom": ["needle"]}
    assert service.site_categories == {"Site": ["example.com"]}


def test_sensitive_service_uses_existing_sqlite_index(tmp_path: Path):
    database = tmp_path / "cache/index/app_cache.db"
    database.parent.mkdir(parents=True)
    with sqlite3.connect(database) as connection:
        connection.execute("""CREATE TABLE sensitive_files_index (
            dedupe_key TEXT PRIMARY KEY, source TEXT, category TEXT, event_time TEXT,
            search_text TEXT, record_json TEXT)""")
        record = {"row": {"filename": "resume.pdf"}, "source": "DLP", "category": "이직 / 취업", "keywords": ["resume"], "event_time": "2026-07-22 10:00:00", "event": "Upload", "user": "hong", "dept": "보안팀", "filename": "C:/resume.pdf", "display_filename": "resume.pdf"}
        connection.execute(
            "INSERT INTO sensitive_files_index VALUES (?,?,?,?,?,?)",
            ("record-1", "DLP", "이직 / 취업", record["event_time"], "resume.pdf hong", json.dumps(record)),
        )

    result = SensitiveService(tmp_path).query("files", "전체", "resume", {"DLP"}, 0, 500)

    assert result["source"] == "sqlite-index"
    assert result["items"][0]["name"] == "resume.pdf"


def test_sensitive_results_support_100_item_pages(tmp_path: Path):
    service = SensitiveService(tmp_path)
    records = [{"id": f"file-{index}", "source": "DLP", "category": "문서", "time": f"2026-07-24 10:{index % 60:02d}:00", "name": f"file-{index}.pdf", "raw": {}} for index in range(205)]
    service.file_records = lambda _sources: records

    first = service.query("files", "전체", "", {"DLP"}, 0, 100)
    third = service.query("files", "전체", "", {"DLP"}, 200, 100)

    assert first["total"] == 205
    assert len(first["items"]) == 100
    assert len(third["items"]) == 5
