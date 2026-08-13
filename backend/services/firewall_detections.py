import hashlib
import json
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from backend.services.detections import sensor_type
from backend.services.endpoints import EndpointService, kst_time, load_json_list, normalize_key
from backend.services.event_list_index import EventListIndex


FIREWALL_FIELDS = {
    "time", "severity", "rule", "sourceIp", "sourcePort", "destinationIp", "destinationPort",
    "protocol", "application", "url", "action", "threat", "hostname", "user", "dept",
}


def _object(value: object) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def firewall_payload(event: dict[str, Any]) -> dict[str, Any]:
    """Flatten the documented Detection wrappers without altering the original event."""
    raw_data = _object(event.get("rawData"))
    processed = _object(event.get("processedData"))
    nested = _object(raw_data.get("raw"))
    return {**raw_data, **nested, **processed}


class FirewallDetectionService:
    def __init__(self, project_root: Path):
        self.root = project_root
        self.cache_dir = project_root / "cache/detections"
        self.endpoints = EndpointService(project_root)
        self.event_index = EventListIndex(project_root)

    def _identity_by_ip(self) -> dict[str, dict[str, str]]:
        context = self.endpoints._department_context()
        output: dict[str, dict[str, str]] = {}
        for index, endpoint in enumerate(load_json_list(self.endpoints.endpoints_path)):
            row = self.endpoints._row(endpoint, context, f"endpoint-{index}")
            for value in (row.get("privateIp"), row.get("publicIp"), endpoint.get("ipv4Addresses")):
                values = value if isinstance(value, list) else [value]
                for item in values:
                    if item:
                        output[normalize_key(item)] = row
        return output

    @staticmethod
    def _value(data: dict[str, Any], *keys: str, default: str = "") -> str:
        for key in keys:
            value = data.get(key)
            if value not in (None, "", [], {}):
                return ", ".join(map(str, value)) if isinstance(value, list) else str(value)
        return default

    def _row(self, event: dict[str, Any], event_id: str, identities: dict[str, dict[str, str]]) -> dict[str, str]:
        data = firewall_payload(event)
        source_ip = self._value(data, "src_ip", "source_ip", "sourceIp")
        identity = identities.get(normalize_key(source_ip), {})
        description = _object(event.get("detectionDescription"))
        return {
            "id": event_id, "time": kst_time(event.get("time") or data.get("time")),
            "severity": self._value(event, "severity", default=self._value(data, "severity")),
            "rule": self._value(description, "createdReasonId", default=self._value(event, "detectionRule", "rule", default=self._value(data, "detectionRule", "rule"))),
            "sourceIp": source_ip, "sourcePort": self._value(data, "src_port", "source_port", "sourcePort"),
            "destinationIp": self._value(data, "dst_ip", "destination_ip", "destinationIp"),
            "destinationPort": self._value(data, "dst_port", "destination_port", "destinationPort"),
            "protocol": self._value(data, "protocol"), "application": self._value(data, "app_name", "application"),
            "url": self._value(data, "url", "domain"), "action": self._value(data, "action"),
            "threat": self._value(data, "malware", "alertType", "threat", "threat_name"),
            "hostname": str(identity.get("hostname") or ""), "user": str(identity.get("user") or ""), "dept": str(identity.get("dept") or ""),
            "sourceCountry": self._value(data, "src_country", "source_country"), "destinationCountry": self._value(data, "dst_country", "destination_country"),
            "sourceZone": self._value(data, "src_zone", "src_zone_type"), "destinationZone": self._value(data, "dst_zone", "dst_zone_type"),
            "deviceName": self._value(data, "device_name"), "deviceModel": self._value(data, "device_model"), "deviceSerial": self._value(data, "device_serial_id"),
            "logType": self._value(data, "log_type"), "logComponent": self._value(data, "log_component"), "logSubtype": self._value(data, "log_subtype"),
            "eventType": self._value(data, "event_type"), "eventId": self._value(data, "event_id"), "hits": self._value(data, "hits"),
            "processUser": self._value(data, "proc_user"), "filePath": self._value(data, "file_path"), "processId": self._value(data, "proc_id"), "processHash": self._value(data, "proc_hash"),
            "threatFeed": self._value(data, "threatfeed"), "mitreTactic": self._value(data, "mitre_tactic", "mitreTactic"), "mitreTechnique": self._value(data, "mitre_technique", "mitreTechnique"),
        }

    def _collect(self, start: date, end: date):
        identities = self._identity_by_ip(); records = []; files = []; current = start
        while current <= end:
            path = self.cache_dir / f"{current.isoformat()}.json"
            if path.exists():
                files.append(path.name)
                for index, event in enumerate(load_json_list(path)):
                    if sensor_type(event) != "firewall" or not event.get("time"):
                        continue
                    event_id = hashlib.sha256(f"firewall:{path.name}:{index}".encode()).hexdigest()[:24]
                    records.append((event_id, event, {**self._row(event, event_id, identities), "_sourceFile": str(path.resolve())}))
            current += timedelta(days=1)
        return records, files

    def list_records(self, start: date, end: date, conditions: list[dict[str, str]], page: int, page_size: int, sort: str, direction: str) -> dict[str, Any]:
        if start > end or sort not in FIREWALL_FIELDS or direction not in {"asc", "desc"}:
            raise ValueError("Invalid firewall detection query")
        return self.event_index.require_records("firewall", start, end, conditions, page, page_size, sort, direction, FIREWALL_FIELDS)

    def get_record(self, record_id: str, start: date, end: date) -> dict[str, Any] | None:
        for candidate, raw, summary in self._collect(start, end)[0]:
            if candidate == record_id:
                return {"summary": summary, "raw": raw}
        return None
