"""Optional Chromium layout regression: build frontend, install playwright, then run."""
from contextlib import contextmanager
import functools
import http.server
import shutil
import threading
from pathlib import Path

import pytest

from test_aws_security_group_path import payload, path_service, save


@contextmanager
def path_browser(result, width=1440):
    playwright = pytest.importorskip("playwright.sync_api")
    chromium = shutil.which("chromium")
    dist = Path(__file__).resolve().parents[1] / "frontend/dist"
    if not chromium or not (dist / "index.html").exists():
        pytest.skip("Requires Chromium and npm run build")
    class SpaHandler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/response/firewall-path-check":
                self.path = "/index.html"
            super().do_GET()
    handler = functools.partial(SpaHandler, directory=str(dist))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with playwright.sync_playwright() as p:
            browser = p.chromium.launch(executable_path=chromium, args=["--no-sandbox"])
            page = browser.new_page(viewport={"width": width, "height": 600})
            page.set_default_timeout(10000)
            page.route("**/api/**", lambda route: route.fulfill(json={"data": result}) if route.request.url.endswith("/path-check") else route.fulfill(json={"data": {}}))
            page.goto(f"http://127.0.0.1:{server.server_port}/response/firewall-path-check")
            page.add_style_tag(content="*, *::before, *::after { animation: none !important; transition: none !important; }")
            page.get_by_role("button", name="Path Check", exact=True).dispatch_event("click")
            page.locator(".path-diagram article").first.wait_for()
            yield page
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize("width,extra_steps", [(1440, 0), (1024, 6), (390, 6)])
def test_path_cards_use_page_scroll_without_clipping(tmp_path, monkeypatch, width, extra_steps):
    save(tmp_path, payload())
    result = path_service(tmp_path, monkeypatch).check("10.10.0.10", "100.1.2.10", "TCP", 443)
    result["steps"] = [result["steps"][0]] * extra_steps + result["steps"]
    with path_browser(result, width) as page:
        geometry = page.locator(".path-diagram").evaluate("""el => {
            const bounds = el.getBoundingClientRect();
            return {overflow: getComputedStyle(el).overflowY,
                scrollHeight: el.scrollHeight, clientHeight: el.clientHeight,
                cardsVisible: [...el.querySelectorAll('article')].every(card => {
                    const r = card.getBoundingClientRect();
                    return r.left >= bounds.left - 1 && r.right <= bounds.right + 1 &&
                        r.top >= bounds.top - 1 && r.bottom <= bounds.bottom + 1 &&
                        card.scrollWidth <= card.clientWidth + 1 && card.scrollHeight <= card.clientHeight + 1;
                })};
        }""")
        assert geometry["overflow"] == "visible"
        assert geometry["scrollHeight"] <= geometry["clientHeight"] + 1
        assert geometry["cardsVisible"]
        assert page.locator(".path-diagram article").count() == extra_steps + 4
        page.mouse.move(width // 2, 400)
        page.mouse.wheel(0, 500)
        page.wait_for_function("window.scrollY > 0")
        assert page.locator(".path-diagram").evaluate("el => el.scrollTop") == 0


def test_sg_pass_shows_exact_only_fail_hides_mismatches_firewall_drop_remains(tmp_path, monkeypatch):
    from backend.services.aws_security_group_path import firewall_step
    from backend.services.firewall_path_check import match_rules
    import ipaddress
    save(tmp_path, payload())
    result = path_service(tmp_path, monkeypatch).check("10.10.0.10", "100.1.2.10", "TCP", 443)
    outbound, inbound = result["steps"]
    candidate = {**outbound["matches"][0], "ruleId": "hidden-candidate", "description": "hidden SG candidate", "match": "CANDIDATE"}
    outbound["matches"].append(candidate)
    inbound.update(state="FAIL", matches=[], evaluations=[{**candidate, "match": "NO_MATCH"}], reason="일치하는 Allow Rule 없음")
    rule = {"Rule Name": "visible-fw-drop", "Status": "Enable", "Action": "Drop", "Source Object": "Any", "Destination Object": "Any", "Service": "Any"}
    firewall = {"firewall": "Seoul", "available": True, "policy": match_rules([rule], ipaddress.ip_network("10.10.0.10"), ipaddress.ip_network("100.1.2.10"), "TCP", 443), "routing": {"destination": None, "return": None}}
    result["firewalls"] = [firewall]
    result["steps"] = [outbound, firewall_step(firewall), inbound]
    with path_browser(result) as page:
        assert page.get_by_text("Outbound HTTPS", exact=True).count() == 1
        assert page.get_by_text("hidden SG candidate", exact=True).count() == 0
        assert page.get_by_text("일치하는 Allow Rule 없음", exact=True).count() >= 1
        assert page.get_by_text("visible-fw-drop", exact=True).count() == 1
        assert page.get_by_text("Drop", exact=True).count() == 1


def test_fqdn_sg_confirmation_shows_only_port_candidates(tmp_path, monkeypatch):
    import backend.services.firewall_path_check as module
    data = payload()
    data["security_group_rules"].append({"GroupId": "sg-b", "SecurityGroupRuleId": "unrelated-port", "IsEgress": False, "IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "CidrIpv4": "0.0.0.0/0", "Description": "hidden port 80"})
    save(tmp_path, data)
    monkeypatch.setattr(module, "resolve_fqdn", lambda _: ["100.1.2.10"])
    result = path_service(tmp_path, monkeypatch).check("10.10.0.10", "api.example.com", "TCP", 443)
    with path_browser(result) as page:
        assert page.get_by_text("확인 필요", exact=True).count() >= 2
        assert page.get_by_text("hidden port 80", exact=True).count() == 0
        assert page.get_by_text("Inbound HTTPS", exact=True).count() == 1
        assert page.get_by_text("Source/Destination 조건은 FQDN 기준으로 판정하지 않음", exact=False).count() >= 1
        assert page.get_by_text("PASS · 정책 허용", exact=True).count() == 0
