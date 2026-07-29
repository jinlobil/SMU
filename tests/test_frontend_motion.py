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
