import json

import pytest

from backend.services.content import ContentService
from backend.services.sensitive import SensitiveService


def legacy_source(file_keyword="resume", site_keyword="drive.example"):
    return f'SENSITIVE_FILE_CATEGORY_SPECS=[("Legacy Files",["{file_keyword}"])]\nSENSITIVE_SITE_CATEGORY_SPECS=[("Legacy Sites",["{site_keyword}"])]\n'


def test_content_migrates_once_then_stops_depending_on_legacy_python(tmp_path):
    source = tmp_path / "uimain_window.py"
    source.write_text(legacy_source(), encoding="utf-8")

    first = ContentService(tmp_path)
    source.write_text(legacy_source("changed", "changed.example"), encoding="utf-8")
    second = ContentService(tmp_path)

    assert first.specs("files") == {"Legacy Files": ["resume"]}
    assert second.specs("files") == {"Legacy Files": ["resume"]}
    assert (tmp_path / "env/content/sensitive_files.json").exists()


def test_added_category_is_used_by_sensitive_classifier_and_is_ordered_by_priority(tmp_path):
    (tmp_path / "uimain_window.py").write_text(legacy_source(), encoding="utf-8")
    content = ContentService(tmp_path)
    content.save("files", {"name": "Priority Files", "keywords": ["secret-plan", "SECRET-PLAN"], "priority": 1, "enabled": True})
    service = SensitiveService(tmp_path)

    assert list(service.file_categories)[0] == "Priority Files"
    assert service.classify("Secret-Plan.docx", service.file_categories) == ("Priority Files", ["secret-plan"])


def test_content_crud_validates_duplicates_and_broad_site_domains(tmp_path):
    (tmp_path / "uimain_window.py").write_text(legacy_source(), encoding="utf-8")
    service = ContentService(tmp_path)
    item = service.save("sites", {"name": "업무 도구", "keywords": "portal.example\nfiles.example", "priority": 5})

    assert service.list("sites")["keywordCount"] == 3
    with pytest.raises(ValueError, match="동일한 이름"):
        service.save("sites", {"name": "업무 도구", "keywords": ["another.example"]})
    with pytest.raises(ValueError, match="최상위"):
        service.save("sites", {"name": "너무 넓음", "keywords": ["com"]})

    service.delete("sites", item["id"])
    assert all(category["id"] != item["id"] for category in service.list("sites")["categories"])
