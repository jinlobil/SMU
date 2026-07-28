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


def test_sensitive_results_support_50_item_pages(tmp_path: Path):
    service = SensitiveService(tmp_path)
    records = [{"id": f"file-{index}", "source": "DLP", "category": "문서", "time": f"2026-07-24 10:{index % 60:02d}:00", "name": f"file-{index}.pdf", "raw": {}} for index in range(205)]
    service.file_records = lambda _sources: records

    first = service.query("files", "전체", "", {"DLP"}, 0, 50)
    fifth = service.query("files", "전체", "", {"DLP"}, 200, 50)

    assert first["total"] == 205
    assert len(first["items"]) == 50
    assert len(fifth["items"]) == 5


def test_web_index_schema_preserves_sensitive_file_name_and_detail(tmp_path: Path):
    database = tmp_path / "cache/index/app_cache.db"
    database.parent.mkdir(parents=True)
    record = {"id": "file-web-1", "source": "DLP", "category": "계약", "keywords": ["계약"],
              "time": "2026-07-28 10:00:00", "name": "계약서.pdf", "path": "C:/docs/계약서.pdf",
              "user": "kim", "dept": "법무팀", "event": "탐지", "raw": {"filename": "계약서.pdf"}}
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE sensitive_files_index (dedupe_key TEXT PRIMARY KEY, source TEXT, category TEXT, event_time TEXT, search_text TEXT, record_json TEXT)")
        connection.execute("INSERT INTO sensitive_files_index VALUES (?,?,?,?,?,?)",
                           (record["id"], record["source"], record["category"], record["time"], "계약서.pdf", json.dumps({**record, "row": record["raw"]})))

    service = SensitiveService(tmp_path)
    result = service.query("files", "전체", "", {"DLP"}, 0, 50)

    assert result["items"][0]["id"] == "file-web-1"
    assert result["items"][0]["name"] == "계약서.pdf"
    assert result["items"][0]["path"] == "C:/docs/계약서.pdf"
    assert result["items"][0]["time"] == "2026-07-28 10:00:00"
    assert service.detail("files", "file-web-1", {"DLP"})["raw"]["filename"] == "계약서.pdf"


def test_sensitive_sites_keep_only_latest_duplicate_for_same_owner(tmp_path: Path):
    service = SensitiveService(tmp_path)
    rows = [
        ("old", {}, {"destination": "https://instagram.com/a", "destinationDetail": "instagram.com", "username": "kim", "dept": "마케팅", "time": "2026-07-27 10:00:00", "computer": "PC1", "event": "탐지"}),
        ("new", {}, {"destination": "https://instagram.com/b", "destinationDetail": "instagram.com", "username": "kim", "dept": "마케팅", "time": "2026-07-28 10:00:00", "computer": "PC1", "event": "탐지"}),
    ]
    service._transfer_records = lambda kind: rows if kind == "dlp" else []

    records = service.site_records()

    assert len(records) == 1
    assert records[0]["id"].startswith("site-new-")
    assert records[0]["time"] == "2026-07-28 10:00:00"


def test_outbound_without_attachment_is_not_a_sensitive_file(tmp_path: Path):
    service = SensitiveService(tmp_path)
    service._transfer_records = lambda kind: [("mail-1", {"attach": "", "subject": "채권 안내"}, {
        "attachment": "None", "subject": "채권 안내", "senderName": "kim", "dept": "법무팀",
        "date": "2026-07-28 10:00:00", "sendResult": "성공",
    })] if kind == "outbound" else []

    assert service.file_records({"Outbound Mail"}) == []


def test_outbound_attachment_parser_creates_only_actual_files(tmp_path: Path):
    service = SensitiveService(tmp_path)
    service._transfer_records = lambda kind: [("mail-1", {}, {
        "attachment": "계약서.pdf (1.1 MB), resume.docx (20 KB)", "subject": "첨부 송부",
        "senderName": "kim", "dept": "법무팀", "date": "2026-07-28 10:00:00", "sendResult": "성공",
    })] if kind == "outbound" else []

    names = {record["name"] for record in service.file_records({"Outbound Mail"})}

    assert names == {"계약서.pdf", "resume.docx"}


def test_sensitive_records_map_login_ids_to_korean_display_names(tmp_path: Path):
    endpoints = tmp_path / "cache/endpoints.json"
    endpoints.parent.mkdir(parents=True)
    endpoints.write_text(json.dumps([{"associatedPerson": {"name": "이수민", "viaLogin": "LOCKNLOCK\\sumin.lee", "id": "person-1"}}]), encoding="utf-8")
    service = SensitiveService(tmp_path)
    service._transfer_records = lambda kind: [("dlp-1", {"client_name": "sumin.lee"}, {
        "source": "C:/계약서.pdf", "username": "sumin.lee", "dept": "수발주파트", "time": "2026-07-28",
        "event": "탐지", "destination": "None", "destinationDetail": "None", "computer": "PC1",
    })] if kind == "dlp" else []

    records = service.file_records({"DLP"})

    assert records[0]["user"] == "이수민"
