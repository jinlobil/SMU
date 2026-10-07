import json
import zipfile
from pathlib import Path
from xml.etree import ElementTree

from backend.services.endpoint_export import EndpointExportService
from backend.services.endpoints import EndpointService, classify_endpoint_ips


def test_ip_classification_boundaries_duplicates_invalid_and_source_preservation():
    source = ["101.1.0.0", "101.1.3.255", "101.1.4.0", "101.1.7.255", "106.1.0.0", "106.1.255.255", "100.64.0.1", "100.64.0.2", "bad-ip", "101.1.0.0"]
    original = list(source)
    assert classify_endpoint_ips(source) == {
        "wired": ["101.1.0.0", "101.1.3.255"],
        "wireless": ["101.1.4.0", "101.1.7.255"],
        "vpn": ["106.1.0.0", "106.1.255.255"],
        "ztna": ["100.64.0.1"],
        "aws": [], "ncp": [], "other": ["100.64.0.2", "bad-ip"],
    }
    assert source == original
    assert classify_endpoint_ips(None) == {"wired": [], "wireless": [], "vpn": [], "ztna": [], "aws": [], "ncp": [], "other": []}


def test_endpoint_search_and_export_share_classification(tmp_path: Path):
    cache = tmp_path / "cache"; cache.mkdir()
    endpoints = [{"hostname": "PC-A", "associatedPerson": {"name": "User A"}, "ipv4Addresses": ["101.1.2.1", "101.1.2.2", "106.1.2.3", "100.64.0.1", "10.0.0.1"], "lastSeenAt": "2026-10-01T00:00:00Z"}, {"hostname": "PC-B", "ipv4Addresses": []}]
    (cache / "endpoints.json").write_text(json.dumps(endpoints), encoding="utf-8")
    result = EndpointService(tmp_path).list_endpoints(query="106.1.2.3", field="ip")
    assert result["pagination"]["total"] == 1
    assert result["items"][0]["ipCategories"]["vpn"] == ["106.1.2.3"]

    exported = EndpointExportService(tmp_path).build()
    assert exported["rows"] == 2 and exported["sheets"] == ["Endpoint List"]
    with zipfile.ZipFile(exported["path"]) as archive:
        workbook = ElementTree.fromstring(archive.read("xl/workbook.xml"))
        sheet = ElementTree.fromstring(archive.read("xl/worksheets/sheet1.xml"))
        assert workbook is not None and sheet is not None
        xml = archive.read("xl/worksheets/sheet1.xml").decode("utf-8")
        for value in ("101.1.2.1", "101.1.2.2", "106.1.2.3", "100.64.0.1", "10.0.0.1", "Last Seen (KST)"):
            assert value in xml


def test_endpoint_export_writes_headers_when_cache_is_empty(tmp_path: Path):
    cache = tmp_path / "cache"; cache.mkdir(); (cache / "endpoints.json").write_text("[]", encoding="utf-8")
    result = EndpointExportService(tmp_path).build()
    with zipfile.ZipFile(result["path"]) as archive:
        xml = archive.read("xl/worksheets/sheet1.xml").decode("utf-8")
        assert "Hostname" in xml and "유선 IP" in xml and "기타 IP" in xml


def test_endpoint_ui_and_laborer_use_backend_classification_and_existing_job_flow():
    root = Path(__file__).resolve().parents[1]
    page = (root / "frontend/src/pages/EndpointPage.tsx").read_text(encoding="utf-8")
    export_page = (root / "frontend/src/pages/ExportManagementPage.tsx").read_text(encoding="utf-8")
    laborer = (root / "system_monitor/laborer.py").read_text(encoding="utf-8")
    assert "ipCategories" in page and all(label in page for label in ("유선", "무선", "VPN", "ZTNA", "기타"))
    assert "classify_endpoint_ips" not in page
    assert "Endpoint XLSX" in export_page and '"/api/jobs/export/endpoints"' in export_page
    assert 'row["type"] == "endpoint_export"' in laborer


def test_seven_categories_cover_ranges_boundaries_and_preserve_multiple_ips():
    groups = {
        'wired': ['101.3.0.0', '101.3.0.255', '101.3.1.1', '101.3.1.4', '101.2.1.1', '101.2.1.149'],
        'wireless': ['101.3.1.5', '101.3.1.254', '101.2.1.150', '101.2.1.250'],
        'vpn': ['106.1.0.0', '106.1.255.255'], 'ztna': ['100.64.0.1'],
        'aws': ['100.1.0.0', '100.1.3.255', '10.10.0.0', '10.10.255.255', '10.20.0.0', '10.20.255.255'],
        'ncp': ['10.0.0.0', '10.0.255.255'],
        'other': ['101.3.1.0', '101.3.1.255', '101.2.1.0', '101.2.1.251', '100.1.4.0', '10.100.0.1', '10.200.0.1', '10.1.0.1', '100.64.0.2', '2001:db8::1', 'invalid'],
    }
    values = [ip for group in groups.values() for ip in group]
    original = list(values)
    assert classify_endpoint_ips(values) == groups
    assert values == original


def test_new_categories_are_identical_in_endpoint_screen_and_export_cells(tmp_path):
    values = ['101.3.1.1', '101.3.1.4', '101.3.1.5', '101.2.1.150', '106.1.1.1', '100.64.0.1', '100.1.1.1', '10.10.1.1', '10.20.1.1', '10.0.1.1', '192.0.2.1']
    cache = tmp_path / 'cache'; cache.mkdir()
    raw = json.dumps([{'hostname': 'fixture-server', 'ipv4Addresses': values}])
    (cache / 'endpoints.json').write_text(raw)
    endpoint = EndpointService(tmp_path).list_endpoints()['items'][0]
    result = EndpointExportService(tmp_path).build()
    ns = {'m': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
    with zipfile.ZipFile(result['path']) as archive:
        sheet = ElementTree.fromstring(archive.read('xl/worksheets/sheet1.xml'))
    cells = {cell.attrib['r']: ''.join(cell.itertext()) for cell in sheet.findall('m:sheetData/m:row/m:c', ns)}
    for column, category in [('E', 'wired'), ('F', 'wireless'), ('G', 'vpn'), ('H', 'ztna'), ('I', 'aws'), ('J', 'ncp'), ('K', 'other')]:
        assert cells[column + '2'] == '\n'.join(endpoint['ipCategories'][category])
    assert (cache / 'endpoints.json').read_text() == raw
