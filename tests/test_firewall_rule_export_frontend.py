from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_export_management_exposes_dynamic_firewall_rule_selection() -> None:
    source = (ROOT / "frontend/src/pages/ExportManagementPage.tsx").read_text(encoding="utf-8")
    assert 'firewallRules: "Firewall Rule XLSX"' in source
    assert 'fetch("/api/firewall/configuration")' in source
    assert '"/api/jobs/export/firewall-rules"' in source
    assert 'disabled={running || (active !== "firewallRules" && rangeInvalid) || selectedCount === 0}' in source
    assert "firewalls.map((firewall)" in source


def test_firewall_rule_export_is_a_laborer_job_with_list_transport() -> None:
    laborer = (ROOT / "system_monitor/laborer.py").read_text(encoding="utf-8")
    app = (ROOT / "backend/app.py").read_text(encoding="utf-8")
    assert 'structured = {"columns", "sections", "firewalls"}' in laborer
    assert '"firewall_rules_export"' in laborer
    assert '@app.post("/api/jobs/export/firewall-rules"' in app
    assert 'start_laborer_job("firewall_rules_export", firewalls=firewalls)' in app
