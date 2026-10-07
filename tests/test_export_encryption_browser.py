from contextlib import contextmanager
import functools
import http.server
from pathlib import Path
import shutil
import threading

import pytest

from backend.services.exporting import schema_payload


@contextmanager
def export_page(path="/config/export"):
    playwright = pytest.importorskip('playwright.sync_api')
    chromium = shutil.which('chromium')
    dist = Path(__file__).resolve().parents[1] / 'frontend/dist'
    if not chromium or not (dist / 'index.html').exists(): pytest.skip('Requires Chromium and frontend build')
    class Handler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith(('/config/', '/forensics/')): self.path = '/index.html'
            super().do_GET()
        def log_message(self, *_): pass
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Handler, directory=str(dist)))
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        with playwright.sync_playwright() as p:
            browser = p.chromium.launch(executable_path=chromium, args=['--no-sandbox'])
            page = browser.new_page(); page.set_default_timeout(10000)
            requests = []
            def api(route):
                url = route.request.url
                if route.request.method == 'POST' and '/api/jobs/export' in url:
                    requests.append(route.request.post_data_json); route.fulfill(json={'data': {'id': 'fixture', 'status': 'queued'}})
                elif '/api/timeline?' in url: route.fulfill(json={'data': {'groups': [], 'pagination': {'totalEvents': 0, 'totalGroups': 0}, 'source': 'sqlite-index'}})
                elif '/api/config/export/schema' in url: route.fulfill(json={'data': schema_payload()})
                elif '/api/firewall/configuration' in url: route.fulfill(json={'data': {'firewalls': []}})
                elif '/api/jobs/fixture' in url: route.fulfill(json={'data': {'status': 'failed', 'error': {'message': 'Fixture completion'}}})
                else: route.fulfill(json={'data': {}})
            page.route('**/api/**', api)
            page.goto(f'http://127.0.0.1:{server.server_port}{path}')
            if path == '/config/export': page.get_by_label('파일 암호화').wait_for()
            else: page.get_by_role('heading', name='Timeline', exact=True).wait_for()
            page.add_style_tag(content='* {animation:none !important;transition:none !important}')
            yield page, requests
            browser.close()
    finally: server.shutdown(); server.server_close(); thread.join()


def test_password_validation_blocks_jobs_and_pdf_has_no_encryption_controls():
    with export_page() as (page, requests):
        assert page.get_by_label('비밀번호', exact=True).count() == 0
        page.get_by_role('button', name='Endpoint XLSX', exact=True).dispatch_event('click')
        page.get_by_label('파일 암호화').check()
        page.get_by_role('button', name='Excel 다운로드', exact=True).dispatch_event('click')
        page.get_by_text('Error: 비밀번호와 비밀번호 확인을 입력하세요.', exact=True).wait_for()
        assert requests == []
        page.get_by_label('비밀번호', exact=True).fill('fixture-a')
        page.get_by_label('비밀번호 확인', exact=True).fill('fixture-b')
        page.get_by_role('button', name='Excel 다운로드', exact=True).dispatch_event('click')
        page.get_by_text('Error: 비밀번호가 일치하지 않습니다.', exact=True).wait_for()
        assert requests == []
        page.get_by_role('button', name='Security Report PDF', exact=True).dispatch_event('click')
        assert page.get_by_label('파일 암호화').count() == 0


@pytest.mark.parametrize('enabled', [False, True])
def test_ui_sends_only_required_secret_and_never_stores_it(enabled):
    with export_page() as (page, requests):
        page.get_by_role('button', name='Endpoint XLSX', exact=True).dispatch_event('click')
        if enabled:
            page.get_by_label('파일 암호화').check()
            page.get_by_label('비밀번호', exact=True).fill('browser-only-fixture')
            page.get_by_label('비밀번호 확인', exact=True).fill('browser-only-fixture')
        page.get_by_role('button', name='Excel 다운로드', exact=True).dispatch_event('click')
        page.get_by_text('Error: Fixture completion', exact=True).wait_for()
        assert len(requests) == 1
        assert requests[0] == ({'encrypt': True, 'password': 'browser-only-fixture'} if enabled else {})
        assert 'browser-only-fixture' not in page.evaluate('JSON.stringify(localStorage)')
        if enabled:
            assert page.get_by_label('비밀번호', exact=True).input_value() == ''
            assert page.get_by_label('비밀번호 확인', exact=True).input_value() == ''


def test_timeline_reuses_encryption_validation_and_request_options():
    with export_page('/forensics/timeline') as (page, requests):
        page.get_by_placeholder('사용자명 / User ID / 메일 / Hostname').fill('fixture')
        page.get_by_role('button', name='조회', exact=True).dispatch_event('click')
        page.get_by_label('파일 암호화').check()
        page.get_by_label('비밀번호', exact=True).fill('timeline-fixture')
        page.get_by_label('비밀번호 확인', exact=True).fill('mismatch')
        page.get_by_role('button', name='Excel 다운로드', exact=True).dispatch_event('click')
        page.get_by_text('Timeline 검색 오류: Error: 비밀번호가 일치하지 않습니다.', exact=True).wait_for()
        assert requests == []
        page.get_by_label('비밀번호 확인', exact=True).fill('timeline-fixture')
        page.get_by_role('button', name='Excel 다운로드', exact=True).dispatch_event('click')
        page.get_by_text('Timeline 검색 오류: Error: Fixture completion', exact=True).wait_for()
        assert len(requests) == 1
        assert requests[0]['password'] == 'timeline-fixture' and requests[0]['encrypt'] is True
        assert requests[0]['user'] == 'fixture'
        assert page.get_by_label('비밀번호', exact=True).input_value() == ''
