from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_command_center_atmosphere_and_heartbeat_are_rendered():
    app = (ROOT / "frontend/src/App.tsx").read_text(encoding="utf-8")

    assert 'className="cyber-atmosphere"' in app
    assert 'className="connection-heartbeat"' in app
    assert "page-stage page-${view}" in app


def test_motion_layer_covers_cards_tables_and_feature_pages():
    styles = (ROOT / "frontend/src/styles.css").read_text(encoding="utf-8")

    for marker in (
        ".panel,.config-card,.dash-card,.summary-grid article",
        "@keyframes command-float",
        "@keyframes heartbeat-line",
        ".firewall-buttons .danger-action::before",
        ".page-timeline .timeline-list::before",
        ".modal-backdrop { position:fixed!important",
        "@media (prefers-reduced-motion:reduce)",
    ):
        assert marker in styles

    assert "radar-sweep" not in styles
    assert "table-scanner" not in styles
    assert "blueprint-scan" not in styles


def test_system_info_uses_hover_tooltips_without_bottom_time_labels():
    page = (ROOT / "frontend/src/pages/SystemInfoPage.tsx").read_text(encoding="utf-8")
    app = (ROOT / "frontend/src/App.tsx").read_text(encoding="utf-8")
    config = (ROOT / "frontend/src/pages/ConfigPage.tsx").read_text(encoding="utf-8")

    assert 'className="day-tooltip system-tooltip"' in page
    assert 'className="hover-guide"' in page
    assert "<title>" not in page
    assert 'textAnchor="middle"' not in page
    assert 'href="#config-general"' in app
    assert 'href="#config-system-info"' in app
    assert ">General</button>" not in app
    assert ">System-Info</button>" not in app
    assert ">General</button>" not in config
    assert ">System-Info</button>" not in config
    styles = (ROOT / "frontend/src/styles.css").read_text(encoding="utf-8")
    assert ".content .config-tabs { display:none!important; }" in styles


def test_config_monitor_tolerates_backend_without_new_status_endpoint():
    config = (ROOT / "frontend/src/pages/ConfigPage.tsx").read_text(encoding="utf-8")

    assert "!response.ok||!payload?.data?.watchdog||!payload?.data?.collector" in config
    assert "setMonitor(unavailableMonitor())" in config
