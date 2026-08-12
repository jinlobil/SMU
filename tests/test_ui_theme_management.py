import re
from pathlib import Path

from backend.services.settings import DEFAULT_THEME


ROOT = Path(__file__).resolve().parents[1]


def test_ui_management_exposes_all_tokens_preview_and_presets():
    metadata = (ROOT / "frontend/src/theme.ts").read_text(encoding="utf-8")
    page = (ROOT / "frontend/src/pages/UIManagementPage.tsx").read_text(encoding="utf-8")
    keys = set(re.findall(r'd\("([^"]+)"', metadata))
    assert keys == set(DEFAULT_THEME)
    assert len(keys) == 59
    for contract in ("savedTheme", "draftTheme", "defaultTheme", "theme-mini-sidebar", "theme-mini-graph", "theme-mini-modal", "theme-preview-highlight"):
        assert contract in page
    assert "/api/config/theme/presets" in page
    assert "저장 및 전체 적용" in page


def test_theme_literals_only_exist_in_central_default_declarations():
    frontend = ROOT / "frontend/src"
    offenders = []
    for path in frontend.rglob("*"):
        if path.suffix not in {".css", ".ts", ".tsx"}:
            continue
        source = path.read_text(encoding="utf-8")
        if path.name == "styles.css":
            source = source[source.index("}") + 1:]
        if path.name == "theme.ts":
            continue
        if re.search(r"#[0-9a-fA-F]{3,8}\b|(?<![-\w])rgba?\(\s*\d|(?<![-\w])hsla?\(\s*\d", source):
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == []
