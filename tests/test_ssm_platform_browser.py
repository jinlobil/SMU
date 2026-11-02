import functools
import http.server
import shutil
import threading
from pathlib import Path
from urllib.parse import urlsplit

import pytest


@pytest.mark.parametrize('modern', [True, False])
def test_instance_detail_platform_values_and_legacy_defaults(modern):
    playwright = pytest.importorskip('playwright.sync_api')
    chromium = shutil.which('chromium')
    dist = Path(__file__).parents[1] / 'frontend/dist'
    if not chromium or not (dist / 'index.html').exists(): pytest.skip('Requires Chromium and frontend build')
    class Handler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            if urlsplit(self.path).path == '/assets/aws': self.path = '/index.html'
            super().do_GET()
        def log_message(self, *_): pass
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Handler, directory=str(dist)))
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    inventory = {'hostname': 'fixture-server', 'os': 'Example OS', 'status': 'stale',
                 'was': [{'product': 'WebLogic', 'version': '12.2.1.1.0', 'path': '/srv/wls', 'status': 'running'},
                         {'product': 'Tomcat', 'version': '7.0.68', 'path': '/srv/tomcat', 'status': 'running'}],
                 'web': [], 'db': [{'product': 'Sybase', 'version': '16.0.03.03', 'path': '/srv/sybase', 'status': 'running'}]}
    values = {'was_platform': 'Java 1.8.0_131; Java 17.0.12', 'web_platform': None, 'db_platform': 'ASE 16.0.03.03'}
    if modern: inventory.update(values)
    try:
        with playwright.sync_playwright() as p:
            browser = p.chromium.launch(executable_path=chromium, args=['--no-sandbox'])
            page = browser.new_page(viewport={'width': 1280, 'height': 480}); page.set_default_timeout(10000)
            def api(route):
                path = urlsplit(route.request.url).path
                if path == '/api/aws/instances/i-fixture':
                    route.fulfill(json={'data': {'instance': {'InstanceId': 'i-fixture'}, 'attachedSecurityGroups': [], 'ssmInventory': inventory}})
                elif path == '/api/aws/instances':
                    route.fulfill(json={'data': {'items': [], 'summary': {'total': 0, 'running': 0, 'stopped': 0, 'other': 0},
                                                'pagination': {'page': 1, 'total': 0, 'totalPages': 1}, 'metadata': {}, 'source': {'exists': True}}})
                else: route.fulfill(json={'data': {}})
            page.route('**/api/**', api)
            page.goto(f'http://127.0.0.1:{server.server_port}/assets/aws?instanceId=i-fixture')
            page.add_style_tag(content='* {animation:none!important;transition:none!important}')
            modal = page.locator('.detail-modal'); modal.wait_for()
            for label, field in [('WAS Platform', 'was_platform'), ('WEB Platform', 'web_platform'), ('DB Platform', 'db_platform')]:
                row = modal.get_by_role('row').filter(has=page.get_by_role('rowheader', name=label, exact=True))
                assert row.locator('td').inner_text() == ((values[field] or '-') if modern else '-')
            assert modal.get_by_text('WebLogic', exact=True).count() == 1
            assert modal.get_by_text('Tomcat', exact=True).count() == 1
            assert modal.get_by_text('Sybase', exact=True).count() == 1
            assert modal.get_by_text('16.0.03.03', exact=True).count() == 1
            assert modal.get_by_text('이전 정상 수집 데이터', exact=True).count() == 1
            assert modal.get_by_role('columnheader', name='SG Name', exact=True).count() == 1
            assert 'i-fixture' in modal.locator('pre').inner_text()
            modal.hover()
            page.mouse.wheel(0, 2000)
            page.wait_for_function("document.querySelector('.detail-modal').scrollTop > 0")
            browser.close()
    finally:
        server.shutdown(); server.server_close(); thread.join()
