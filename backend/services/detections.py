import hashlib
import json
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

from backend.services.endpoints import EndpointService, endpoint_principal, kst_time, load_json_list, normalize_key
from backend.services.event_list_index import EventListIndex


SEARCH_FIELDS = {"all", "hostname", "dept", "username", "privateIp", "publicIp", "file", "sha256", "rule", "lineage", "rawData"}
SORT_FIELDS = {"time", "hostname", "dept", "username", "privateIp", "publicIp", "file", "sha256", "rule", "lineage"}


def sensor_type(row: dict[str, Any]) -> str:
    sensor = row.get("sensor") if isinstance(row.get("sensor"), dict) else {}
    return str(sensor.get("type", row.get("sensorType", "")) or "").strip().lower()


def file_and_sha(raw: dict[str, Any]) -> tuple[str, str]:
    files = raw.get("ioc_event_files", [])
    first = files[0] if isinstance(files, list) and files and isinstance(files[0], dict) else {}
    if first.get("file_name"):
        return str(first["file_name"]), str(first.get("sha256") or "None")
    name = raw.get("process_name") or raw.get("meta_process_name") or raw.get("target_process_name") or raw.get("name") or raw.get("file_name") or raw.get("original_filename") or "None"
    sha = raw.get("process_sha256") or raw.get("meta_sha256") or raw.get("target_process_sha256") or raw.get("sha256") or "None"
    return str(name), str(sha)


class DetectionService:
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.cache_dir = project_root / "cache" / "detections"
        self.endpoint_service = EndpointService(project_root)
        self.event_index = EventListIndex(project_root)

    def _identity_map(self) -> dict[str, dict[str, str]]:
        context = self.endpoint_service._department_context()
        identities = {}
        for index, endpoint in enumerate(load_json_list(self.endpoint_service.endpoints_path)):
            row = self.endpoint_service._row(endpoint, context, f"endpoint-{index}")
            person = endpoint.get("associatedPerson") if isinstance(endpoint.get("associatedPerson"), dict) else {}
            identities[normalize_key(endpoint.get("hostname"))] = {**row, "principal": endpoint_principal(person, endpoint.get("hostname"))}
        return identities

    def _files(self, start: date, end: date) -> list[Path]:
        files = []
        current = start
        while current <= end:
            files.append(self.cache_dir / f"{current.isoformat()}.json")
            current += timedelta(days=1)
        return files

    @staticmethod
    def _id(path: Path, index: int) -> str:
        return hashlib.sha256(f"{path.name}:{index}".encode()).hexdigest()[:24]

    def _row(self, raw_event: dict[str, Any], event_id: str, identities: dict[str, dict[str, str]]) -> dict[str, str]:
        raw = raw_event.get("rawData") if isinstance(raw_event.get("rawData"), dict) else {}
        hostname = str(raw.get("meta_hostname", "None") or "None")
        identity = identities.get(normalize_key(hostname), {})
        description = raw_event.get("detectionDescription") if isinstance(raw_event.get("detectionDescription"), dict) else {}
        rule = description.get("createdReasonId") or raw_event.get("rule") or raw_event.get("detectionRule") or "None"
        lineage = "None"
        lineages = raw.get("associated_lineages", [])
        if isinstance(lineages, list):
            for item in lineages:
                nodes = item.get("lineage", []) if isinstance(item, dict) else []
                names = [str(node.get("name")) for node in nodes if isinstance(node, dict) and node.get("name")]
                if names:
                    lineage = " -> ".join(reversed(names))
                    break
        file_name, sha = file_and_sha(raw)
        return {
            "id": event_id, "time": kst_time(raw_event.get("time")), "hostname": hostname,
            "principal": identity.get("principal", ""), "dept": identity.get("dept", "미분류"), "username": identity.get("user", "None"),
            "privateIp": str(raw.get("meta_ip_address") or "None"), "publicIp": str(raw.get("meta_public_ip") or "None"),
            "file": file_name, "sha256": sha, "rule": str(rule), "lineage": lineage,
        }

    def _events(self, start: date, end: date) -> tuple[list[tuple[str, dict[str, Any], dict[str, str]]], list[str]]:
        identities = self._identity_map()
        events = []
        existing_files = []
        for path in self._files(start, end):
            if not path.exists():
                continue
            existing_files.append(path.name)
            for index, event in enumerate(load_json_list(path)):
                if sensor_type(event) != "endpoint" or not event.get("time"):
                    continue
                event_id = self._id(path, index)
                events.append((event_id, event, {**self._row(event, event_id, identities), "_sourceFile": str(path.resolve())}))
        return events, existing_files

    def list_detections(self, start: date, end: date, conditions: list[dict[str, str]], page: int = 1, page_size: int = 50, sort: str = "time", direction: str = "desc") -> dict[str, Any]:
        if start > end:
            raise ValueError("start date must not be after end date")
        if sort not in SORT_FIELDS or direction not in {"asc", "desc"}:
            raise ValueError("Unsupported detection sort")
        for condition in conditions:
            if condition.get("field", "all") not in SEARCH_FIELDS:
                raise ValueError(f"Unsupported detection search field: {condition.get('field')}")

        indexed = self.event_index.require_records("detections", start, end, conditions, page, page_size, sort, direction, SORT_FIELDS)
        return indexed

    def get_detection(self, event_id: str, start: date, end: date) -> dict[str, Any] | None:
        for candidate_id, raw, summary in self._events(start, end)[0]:
            if candidate_id == event_id:
                return {"summary": summary, "raw": raw}
        return None
