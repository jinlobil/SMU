from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_response_menu_and_route_include_firewall_path_check() -> None:
    app = (ROOT / "frontend/src/App.tsx").read_text(encoding="utf-8")
    page = (ROOT / "frontend/src/pages/FirewallPathCheckPage.tsx").read_text(encoding="utf-8")
    assert '{ label: "Firewall Path Check", route: "/response/firewall-path-check" }' in app
    assert '<Route path="/response/firewall-path-check" element={<FirewallPathCheckPage />} />' in app
    assert '"/api/firewall/path-check"' in page
    assert "최신 정보 다시 조회" in page


def test_path_check_reuses_existing_ui_classes() -> None:
    page = (ROOT / "frontend/src/pages/FirewallPathCheckPage.tsx").read_text(encoding="utf-8")
    for class_name in ("panel", "firewall-buttons", "primary-action", "error-banner", "table-wrap", "result-pill"):
        assert class_name in page
