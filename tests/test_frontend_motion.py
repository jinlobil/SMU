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
    assert 'href="#config-data-management"' in app
    assert 'href="#config-system-management"' in app
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




def test_dashboard_uses_grouped_async_index_api_calls():
    dashboard = (ROOT / "frontend/src/pages/DashboardPage.tsx").read_text(encoding="utf-8")

    for endpoint in (
        "/api/dashboard/assets",
        "/api/dashboard/mix-trend",
        "/api/dashboard/top-detection",
        "/api/dashboard/top-mail",
        "/api/dashboard/top-file",
    ):
        assert endpoint in dashboard
    assert "fetch(`/api/dashboard${params}`)" not in dashboard
    assert "topDetection" in dashboard
    assert "topMail" in dashboard
    assert "topFile" in dashboard
    assert "dashboard-loading-inline" in dashboard

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


def test_integration_management_is_a_config_subpage_with_card_modal_ui():
    app = (ROOT / "frontend/src/App.tsx").read_text(encoding="utf-8")
    page = (ROOT / "frontend/src/pages/IntegrationManagementPage.tsx").read_text(encoding="utf-8")
    styles = (ROOT / "frontend/src/styles.css").read_text(encoding="utf-8")

    assert 'href="#config-integration-management"' in app
    assert "<IntegrationManagementPage />" in app
    assert "＋ 연동 추가" in page
    assert 'className="integration-card"' in page
    assert 'className="integration-modal"' in page
    assert 'className="integration-heartbeat"' in page
    assert "integration-heartbeat-flow" in styles
    assert "clientSecretConfigured" in page or "저장된 인증정보는 표시하지 않습니다" in page
    assert ".integration-grid {" in styles


def test_hardware_monitor_shows_indexer_status_and_manual_restart():
    page = (ROOT / "frontend/src/pages/ConfigPage.tsx").read_text(encoding="utf-8")

    assert "indexer:MonitorProcess" in page
    assert "Indexer 재시작" in page
    assert 'restartMonitor("indexer")' in page
    assert "monitor.indexer.lastHeartbeatAt" in page
    assert "Process Monitor" in page
    assert "process-description" in page
    assert "원본 캐시 수집 작업" in page
    assert "화면 리스트·타임라인·민감 인덱스" in page
    assert "<h2>Hardware Monitor</h2>" not in page
    assert "스마트 캐시 데이터 인덱싱" in page
    assert "전체 캐시 인덱싱" in page
    assert "{force:true}" in page


def test_exception_management_uses_department_and_full_principal_tabs():
    app = (ROOT / "frontend/src/App.tsx").read_text(encoding="utf-8")
    page = (ROOT / "frontend/src/pages/ExceptionManagementPage.tsx").read_text(encoding="utf-8")
    styles = (ROOT / "frontend/src/styles.css").read_text(encoding="utf-8")

    assert 'href="#config-exception-management"' in app
    assert "<ExceptionManagementPage />" in app
    assert "부서 예외처리" in page
    assert "사용자 예외처리" in page
    assert "전체 사용자 식별값" in page
    assert "계정명만 입력할 수 없습니다" in page
    assert 'placeholder="PREFIX\\account"' in page
    assert "HONGJEHEE" not in page
    assert 'className="entity-name"' in page
    assert 'className="dept-name"' in page
    assert 'className="condition-list exception-condition-list"' in page
    assert ".exception-tabs button" in styles
    assert 'Object.values(item as UserRule)' in page
    assert 'JSON.stringify(item)' not in page
    assert "Raw Data는 변경하지 않고 2차 가공 결과에만 최종 적용합니다." not in page


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


def test_threat_trend_uses_wide_slow_bubble_layer():
    dashboard = (ROOT / "frontend/src/pages/DashboardPage.tsx").read_text(encoding="utf-8")
    styles = (ROOT / "frontend/src/styles.css").read_text(encoding="utf-8")

    assert "const width=1400" in dashboard
    assert '<clipPath id={clipId}>' in dashboard
    assert 'className="trend-bubbles"' in dashboard
    assert "<animateMotion" in dashboard
    assert 'dur={`${18+' in dashboard
    assert "radius=.65+(bubbleIndex%3)*.35" in dashboard
    assert "Array.from({length:20}" in dashboard
    assert ".trend-bubbles {" in styles
    assert ".trend-bubbles { display:none; }" in styles
    assert "trend-particles" not in dashboard
    assert "trend-flow" not in dashboard


def test_config_process_monitor_includes_fetcher():
    page = (ROOT / "frontend/src/pages/ConfigPage.tsx").read_text(encoding="utf-8")
    assert "fetcher:MonitorProcess" in page
    assert "laborer:MonitorProcess" in page
    assert "Fetcher 재시작" in page
    assert "Laborer 재시작" in page
    assert 'restartMonitor("fetcher")' in page
    assert 'restartMonitor("laborer")' in page


def test_config_restores_an_active_job_after_page_navigation():
    page = (ROOT / "frontend/src/pages/ConfigPage.tsx").read_text(encoding="utf-8")

    assert 'const activeConfigJobKey="smu.config.activeJob"' in page
    assert "localStorage.setItem(activeConfigJobKey" in page
    assert "localStorage.getItem(activeConfigJobKey)" in page
    assert "진행 중인 작업 상태 확인 중" in page
    assert "jobPollGeneration.current+=1" in page
    assert "void loadMonitor();const response=await fetch" in page


def test_content_management_uses_config_navigation_and_theme_forms():
    app = (ROOT / "frontend/src/App.tsx").read_text(encoding="utf-8")
    page = (ROOT / "frontend/src/pages/ContentManagementPage.tsx").read_text(encoding="utf-8")
    styles = (ROOT / "frontend/src/styles.css").read_text(encoding="utf-8")
    assert "Content Management" in app and "ContentManagementPage" in app
    assert "Sensitive Files" in page and "Sensitive Sites" in page
    assert "/api/config/content/" in page
    assert "실제" not in page
    assert 'className="source-filters exception-tabs"' in page
    assert 'className="condition-list exception-condition-list"' in page
    assert 'className="integration-card content-rule-card"' in page
    assert 'className="integration-actions"' in page
    assert ".content-filter-row input:focus" not in styles


def test_app_starts_on_dashboard_and_config_links_share_subnav_hover():
    app = (ROOT / "frontend/src/App.tsx").read_text(encoding="utf-8")
    styles = (ROOT / "frontend/src/styles.css").read_text(encoding="utf-8")
    launcher = (ROOT / "run_local.py").read_text(encoding="utf-8")
    assert 'useState("Dashboard")' in app
    assert 'useState<View>("dashboard")' in app
    assert ".subnav button:hover,.subnav a:hover" in styles
    assert "import webbrowser" not in launcher
    assert "webbrowser.open" not in launcher



def test_sophos_detection_pages_hide_manual_refresh_and_use_clear_labels() -> None:
    detection = (ROOT / "frontend/src/pages/DetectionPage.tsx").read_text(encoding="utf-8")
    email = (ROOT / "frontend/src/pages/EmailSecurityPage.tsx").read_text(encoding="utf-8")
    transfer = (ROOT / "frontend/src/pages/TransferPage.tsx").read_text(encoding="utf-8")

    assert "RangeRefreshButton" not in detection
    assert "RangeRefreshButton" not in email
    assert "Sophos Detection XDR 탐지 이벤트" in detection
    assert "Endpoint 센서 탐지" not in detection
    assert "조회 기간 내 일별 파일" in transfer
    assert "cache/dlp" not in transfer
    assert "cache/mailscreen" not in transfer

def test_config_exposes_friendly_index_vacuum_controls() -> None:
    page = (ROOT / "frontend/src/pages/ConfigPage.tsx").read_text(encoding="utf-8")
    assert "민감 콘텐츠 인덱스 DB" in page
    assert "타임라인 인덱스 DB" in page
    assert "Detection 리스트 인덱스 DB" in page
    assert "Cache & Index Status" in page
    assert "status.indexes).map" in page
    assert "/api/jobs/index/vacuum" in page
    assert "timeline_index.db VACUUM" not in page
    assert "민감 콘텐츠 전체 캐시 인덱싱" in page
    assert "타임라인 전체 캐시 인덱싱" in page
    assert "Detection 리스트 전체 캐시 인덱싱" in page
    assert "Dashboard 사전 집계 전체 갱신" in page


def test_config_general_and_data_management_cards_are_split() -> None:
    app = (ROOT / "frontend/src/App.tsx").read_text(encoding="utf-8")
    page = (ROOT / "frontend/src/pages/ConfigPage.tsx").read_text(encoding="utf-8")

    assert '<ConfigPage section="general" />' in app
    assert '<ConfigPage section="data" />' in app
    assert '{section==="data"&&<>' in page
    assert '{section==="general"&&<>' in page
    assert page.index('Process Monitor') < page.index('UI Color Settings') < page.index('Runtime & Logs')
    assert '<h1>{section==="data"?"Data Management":"Config"}</h1>' in page
