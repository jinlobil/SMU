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


def test_path_check_supports_any_protocol_optional_port_and_effective_policy_labels() -> None:
    page = (ROOT / "frontend/src/pages/FirewallPathCheckPage.tsx").read_text(encoding="utf-8")
    for option in ("ANY", "TCP", "UDP", "ICMP", "ICMPV6", "IP"):
        assert f'<option value="{option}">' in page
    assert 'value="PING"' not in page
    assert "Destination Port (Optional)" in page
    assert 'protocolNumber: protocol === "IP"' in page
    assert 'disabled={!usesPort && !usesProtocolNumber}' in page
    assert 'no_matching_rule: "매칭 정책 없음 · 기본 Drop"' in page
    assert 'service_varies: "서비스별 정책 상이"' in page


def test_exact_table_filters_full_matches_and_shows_rule_addresses() -> None:
    page = (ROOT / "frontend/src/pages/FirewallPathCheckPage.tsx").read_text(encoding="utf-8")
    assert ".filter(candidate => item.policy.broadQuery || candidate.fullMatch)" in page
    for heading in ("Source Object", "Source Resolved", "Destination Object", "Destination Resolved"):
        assert f"<th>{heading}</th>" in page
    assert "<th>Source Match</th>" not in page
    assert "<th>Destination Match</th>" not in page
    assert 'wildcard ? "Any"' in page
