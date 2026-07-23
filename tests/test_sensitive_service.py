import json
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
