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

    assert 'className="day-tooltip system-tooltip visible"' in page
    assert 'className="hover-guide visible"' in page
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
    assert 'points.length <= 150' in page
    assert '최대 600포인트' in page
    assert 'type="datetime-local"' in page
    assert 'includes("bucket은 second, minute, hour, day")' in page
    assert "legacyBucket(applied.start, applied.end)" in page


def test_config_monitor_tolerates_backend_without_new_status_endpoint():
    config = (ROOT / "frontend/src/pages/ConfigPage.tsx").read_text(encoding="utf-8")

    assert "!response.ok||!payload?.data?.watchdog||!payload?.data?.collector" in config
    assert "setMonitor(unavailableMonitor())" in config
    styles = (ROOT / "frontend/src/styles.css").read_text(encoding="utf-8")
    assert ".system-chart-area .trend-wave { stroke-dasharray:none; stroke-dashoffset:0; animation:none; }" in styles


def test_config_ranges_exports_and_easy_query_follow_requested_ui_behavior():
    config = (ROOT / "frontend/src/pages/ConfigPage.tsx").read_text(encoding="utf-8")
    app = (ROOT / "frontend/src/App.tsx").read_text(encoding="utf-8")
    styles = (ROOT / "frontend/src/styles.css").read_text(encoding="utf-8")

    for state in ("detectionStart", "detectionEnd", "inboundStart", "inboundEnd", "exportStart", "exportEnd"):
        assert state in config
    assert "Detection CSV" not in config
    assert "DLP File XLSX" not in config  # Generated from the shared label mapping.
    assert "{label} XLSX" in config
    assert "브라우저 다운로드 폴더를 확인하세요" in config
    assert 'type:"COMPLETED"' in config
    assert '"--table-selection-bg"' in app
    assert '"--table-selection-text"' in app
    assert ".query-detail tbody tr:hover td" in styles
    assert "var(--table-selection-bg)" in styles


def test_dashboard_card_titles_have_no_decorative_prefixes():
    dashboard = (ROOT / "frontend/src/pages/DashboardPage.tsx").read_text(encoding="utf-8")

    for title in ("Endpoints", "Organization", "Top File", "Top Hash", "Security Mix", "Threat Trend", "Top Analysis"):
        assert f">{title}</h2>" in dashboard or f'title="{title}"' in dashboard
    for prefix in ("▣ Endpoints", "♧ Organization", "▧ Top File", "# Top Hash", "◉ Security Mix", "⌁ Threat Trend", "▥ Top Analysis"):
        assert prefix not in dashboard


def test_sidebar_opens_only_from_title_region_and_uses_full_width_content():
    app = (ROOT / "frontend/src/App.tsx").read_text(encoding="utf-8")
    styles = (ROOT / "frontend/src/styles.css").read_text(encoding="utf-8")

    assert 'className="sidebar-title-trigger"' in app
    assert 'sidebarOpen ? "open"' in app
    assert "onMouseLeave={scheduleSidebarClose}" in app
    assert "window.setTimeout(() => setSidebarOpen(false), 300)" in app
    assert ".sidebar-title-trigger {" in styles
    assert ".sidebar.open {" in styles
    assert ".content { grid-column:1;" in styles


def test_easy_query_history_layout_variables_and_cursor_cleanup():
    page = (ROOT / "frontend/src/pages/EasyQueryPage.tsx").read_text(encoding="utf-8")
    styles = (ROOT / "frontend/src/styles.css").read_text(encoding="utf-8")

    assert "easy-form ${mode.toLowerCase()}" in page
    assert 'className="easy-history-dates"' in page
    assert 'className="easy-history-variables"' in page
    assert "selectedQuery.variables.map" in page
    assert "variable.description || variable.name" in page
    assert ".easy-form.history {" in styles
    assert 'grid-template-columns:110px 360px 260px 110px' in styles
    assert 'grid-template-areas:"mode query endpoint ." "dates dates variables submit"' in styles
    assert "justify-content:start" in styles
    assert ".page-easyQuery .easy-form::after" not in styles
    assert "terminal-cursor" not in styles


def test_threat_trend_uses_wide_particle_layer():
    dashboard = (ROOT / "frontend/src/pages/DashboardPage.tsx").read_text(encoding="utf-8")
    styles = (ROOT / "frontend/src/styles.css").read_text(encoding="utf-8")

    assert "const width=1400" in dashboard
    assert '<clipPath id={clipId}>' in dashboard
    assert 'className="trend-particles"' in dashboard
    assert '<animate attributeName="cx"' in dashboard
    assert ".trend-particles {" in styles
    assert ".trend-particles { display:none; }" in styles
    assert "trend-flow" not in dashboard
