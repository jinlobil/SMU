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
        "other": ["100.64.0.2", "bad-ip"],
    }
    assert source == original
    assert classify_endpoint_ips(None) == {"wired": [], "wireless": [], "vpn": [], "ztna": [], "other": []}


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
