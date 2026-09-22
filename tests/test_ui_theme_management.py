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
    preview_targets = set(re.findall(r',\["([^"]+)"\]\),', metadata))
    assert len(preview_targets) == 59
    assert all(target in page for target in preview_targets)
    assert "scrollIntoView" in page
    labels = re.findall(r'd\("[^"]+","[^"]+","([^"]+)"', metadata)
    assert not any(color in label.lower() for label in labels for color in ("pink", "purple", "green", "red", "blue", "amber", "핑크", "퍼플", "초록", "빨강", "파랑", "보라"))


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


def test_theme_references_are_defined_and_property_roles_do_not_cross():
    styles = (ROOT / "frontend/src/styles.css").read_text(encoding="utf-8")
    references = set(re.findall(r"var\((--[\w-]+)", styles))
    definitions = set(re.findall(r"(--[\w-]+)\s*:", styles))
    assert references - definitions == set()

    text = {"--text-primary", "--text-bright", "--text-secondary", "--text-muted", "--text-subtle", "--text-table-accent", "--text-entity", "--text-department", "--card-title", "--table-head-text", "--table-selection-text", "--sidebar-text", "--sidebar-text-muted", "--sidebar-selected-text", "--text"}
    backgrounds = {"--app-bg", "--app-bg-deep", "--app-bg-mid", "--app-bg-glow", "--surface", "--surface-raised", "--surface-secondary", "--surface-toolbar", "--input-bg", "--modal-bg", "--raw-bg", "--table-head-bg", "--table-selection-bg", "--table-row-hover", "--control-hover-bg", "--sidebar-bg-start", "--sidebar-bg-end", "--sidebar-hover-bg", "--sidebar-selected-bg", "--modal-overlay"}
    borders = {"--card-border", "--border-soft", "--border-strong", "--border-action", "--border-danger", "--border-table-row"}
    states = set(re.findall(r"--status-[\w-]+", styles))
    accents = set(re.findall(r"--accent[\w-]*|--focus-color", styles))
    graphs = set(re.findall(r"--trend-[\w-]+|--source-color", styles))
    glows = {"--glow-accent", "--glow-secondary"}
    categories = {**{token: "text" for token in text}, **{token: "background" for token in backgrounds}, **{token: "border" for token in borders}, **{token: "state" for token in states}, **{token: "accent" for token in accents}, **{token: "graph" for token in graphs}, **{token: "glow" for token in glows}}
    expected = {
        "color": {"text", "state", "accent", "graph"}, "fill": {"text", "state", "accent", "graph"},
        "background": {"background", "state", "accent", "graph", "glow"}, "background-color": {"background", "state", "accent", "graph", "glow"}, "background-image": {"background", "state", "accent", "graph", "glow"},
        "box-shadow": {"glow", "background", "state", "accent", "graph"}, "text-shadow": {"glow", "background", "state", "accent", "graph"}, "filter": {"glow", "background", "state", "accent", "graph"},
    }
    offenders = []
    for block in re.finditer(r"([^{}]+)\{([^{}]*)\}", styles):
        selector, body = block.groups()
        for declaration in re.finditer(r"([\w-]+)\s*:\s*([^;]+)", body):
            prop, value = declaration.groups()
            allowed = expected.get(prop)
            if prop.startswith(("border", "outline")):
                allowed = {"border", "state", "accent", "graph", "glow"}
            if not allowed:
                continue
            for token in re.findall(r"var\((--[\w-]+)", value):
                if token in {"--source-color", "--neon-angle"}:
                    continue
                if categories.get(token) not in allowed:
                    offenders.append((selector.strip(), prop, token))
    assert offenders == []
