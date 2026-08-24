import json
from datetime import date
from pathlib import Path

from backend.services.detections import DetectionService
from backend.services.email_security import EmailSecurityService
from backend.services.firewall_detections import FirewallDetectionService
from backend.services.indexing import IndexService


def write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def fixture_events():
    return [
        {"time":"2026-08-12T06:07:38Z","sensor":{"type":"endpoint"},"rawData":{"meta_hostname":"PC-1"}},
        {"time":"2026-08-12T06:08:38Z","sensor":{"type":"email"},"detectionRule":"XDR-sophos-email-virus","rawData":{"mailbox":"a@example.com"}},
        {"time":"2026-08-12T06:09:38Z","sensor":{"type":"firewall"},"sourceSystem":"Sophos Firewall","detectionRule":"XDR-sophos-firewall-c2generic-a","severity":7,"rawData":{"raw":json.dumps({"src_ip":"10.0.0.5","src_port":53326,"dst_ip":"8.8.8.8","dst_port":53,"protocol":"UDP","app_name":"DNS","url":"disorderstatus.ru","action":"drop destination match","malware":"C2/Generic-A","device_name":"FW-1","src_country":"KR"})}},
    ]


def test_firewall_is_indexed_separately_and_supports_search_sort_pagination_detail(tmp_path: Path):
    write(tmp_path/"cache/detections/2026-08-12.json", fixture_events())
    IndexService(tmp_path).rebuild_scope("events", lambda _message: None)
    service=FirewallDetectionService(tmp_path)
    result=service.list_records(date(2026,8,12),date(2026,8,12),[{"field":"destinationIp","query":"8.8.8.8"}],1,10,"severity","desc")
    assert result["pagination"]["total"] == 1
    row=result["items"][0]
    assert (row["sourceIp"],row["sourcePort"],row["application"],row["threat"]) == ("10.0.0.5","53326","DNS","C2/Generic-A")
    detail=service.get_record(row["id"],date(2026,8,12),date(2026,8,12))
    assert detail["summary"]["deviceName"] == "FW-1"
    assert detail["raw"]["sourceSystem"] == "Sophos Firewall"


def test_detection_raw_sensor_types_are_mutually_exclusive(tmp_path: Path):
    write(tmp_path/"cache/detections/2026-08-12.json", fixture_events())
    IndexService(tmp_path).rebuild_scope("events", lambda _message: None)
    day=date(2026,8,12)
    assert DetectionService(tmp_path).list_detections(day,day,[])["pagination"]["total"] == 1
    assert EmailSecurityService(tmp_path).list_records("xdr",day,day,[],1,50,"time","desc")["pagination"]["total"] == 1
    assert FirewallDetectionService(tmp_path).list_records(day,day,[],1,50,"time","desc")["pagination"]["total"] == 1
