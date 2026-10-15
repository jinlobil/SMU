import functools
import http.server
import shutil
import threading
from pathlib import Path

import pytest


def test_aws_ssm_status_and_existing_refresh_button(tmp_path):
    playwright = pytest.importorskip('playwright.sync_api')
    chromium = shutil.which('chromium')
    dist = Path(__file__).resolve().parents[1] / 'frontend/dist'
    if not chromium or not (dist / 'index.html').exists(): pytest.skip('Requires Chromium and frontend build')
    class Handler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/assets/aws': self.path = '/index.html'
            super().do_GET()
        def log_message(self, *_): pass
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Handler, directory=str(dist)))
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        with playwright.sync_playwright() as p:
            browser = p.chromium.launch(executable_path=chromium, args=['--no-sandbox'])
            page = browser.new_page(); page.set_default_timeout(10000)
            state = {'posts': 0, 'polls': 0}
            def api(route):
                path = route.request.url
                if '/api/jobs/aws/ssm-inventory' in path:
                    state['posts'] += 1
                    route.fulfill(json={'data': {'id': 'fixture-ssm-job', 'status': 'queued'}})
                elif '/api/jobs/fixture-ssm-job' in path:
                    state['polls'] += 1
                    route.fulfill(json={'data': {'id': 'fixture-ssm-job', 'status': 'completed' if state['polls'] > 1 else 'running', 'message': 'Fixture inventory'}})
                elif '/api/aws/ssm-inventory' in path:
                    route.fulfill(json={'data': {'snapshot_date': '2026-10-15' if state['polls'] > 1 else '2026-10-14', 'collected_at': '2026-10-15T09:00:00+09:00', 'status': 'success', 'running': False}})
                elif '/api/aws/instances?' in path:
                    route.fulfill(json={'data': {'items': [], 'summary': {'total': 0, 'running': 0, 'stopped': 0, 'other': 0}, 'pagination': {'page': 1, 'total': 0, 'totalPages': 1}, 'metadata': {'region': 'fixture-region'}, 'source': {'exists': True}}})
                else: route.fulfill(json={'data': {}})
            page.route('**/api/**', api)
            page.goto(f'http://127.0.0.1:{server.server_port}/assets/aws')
            page.add_style_tag(content='* {animation:none!important;transition:none!important}')
            page.get_by_role('heading', name='Server Inventory (SSM)', exact=True).wait_for()
            page.get_by_text('기준일 2026-10-14', exact=False).wait_for()
            assert page.get_by_role('button', name='AWS 새로고침', exact=True).count() == 1
            page.get_by_role('button', name='지금 갱신', exact=True).dispatch_event('click')
            page.get_by_role('button', name='새로고침 중...', exact=True).wait_for()
            assert page.get_by_role('button', name='새로고침 중...', exact=True).is_disabled()
            page.get_by_text('기준일 2026-10-15', exact=False).wait_for()
            assert state['posts'] == 1
            browser.close()
    finally: server.shutdown(); server.server_close(); thread.join()
