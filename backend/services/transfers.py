import hashlib
import json
import re
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Callable

from backend.services.endpoints import EndpointService, load_json_list, normalize_key


EVENT_NAMES = {"Content Threat Detected": "탐지됨", "Content Threat Blocked": "차단"}
EMAIL_PATTERN = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists(): return []
    output = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip(): continue
        value = json.loads(line)
        if isinstance(value, dict): output.append(value)
    return output


class TransferService:
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.endpoint_service = EndpointService(project_root)
        self.dlp_dir = project_root / "cache" / "dlp"
        self.outbound_dir = project_root / "cache" / "mailscreen"

    @staticmethod
    def _id(kind: str, path: Path, index: int) -> str:
        return hashlib.sha256(f"{kind}:{path.name}:{index}".encode()).hexdigest()[:24]

    @staticmethod
    def _dates(start: date, end: date):
        current = start
        while current <= end:
            yield current
            current += timedelta(days=1)

    def _identities(self) -> dict[str, dict[str, str]]:
        context = self.endpoint_service._department_context()
        return {normalize_key(item.get("hostname")): self.endpoint_service._row(item, context, f"endpoint-{index}") for index, item in enumerate(load_json_list(self.endpoint_service.endpoints_path))}

    def _collect_dlp(self, start: date, end: date):
        records = []; files = []; identities = self._identities()
        for day in self._dates(start, end):
            path = self.dlp_dir / f"{day.isoformat()}.jsonl"
            if not path.exists(): continue
            files.append(path.name)
            for index, raw in enumerate(load_jsonl(path)):
                machine = str(raw.get("machine_name") or "None"); identity = identities.get(normalize_key(machine), {})
                record_id = self._id("dlp", path, index)
                row = {"id": record_id, "event": EVENT_NAMES.get(str(raw.get("event_id") or "None"), str(raw.get("event_id") or "None")), "time": str(raw.get("eventtimelocal") or "None"), "computer": machine, "dept": identity.get("dept", "미분류"), "sourceIp": str(raw.get("ip") or "None"), "username": str(raw.get("client_name") or "None"), "source": str(raw.get("filename") or "None"), "destination": str(raw.get("destination") or "None"), "destinationType": str(raw.get("destination_type") or "None"), "destinationDetail": str(raw.get("item_details") or raw.get("destinationDetails") or "None"), "fileSize": str(raw.get("filesize") or "None"), "fileHash": str(raw.get("filehash") or "None")}
                records.append((record_id, raw, row))
        return records, files

    def _collect_outbound(self, start: date, end: date):
        records = []; files = []
        for day in self._dates(start, end):
            path = self.outbound_dir / f"mailscreen_mail_{day.isoformat()}.json"
            if not path.exists(): continue
            files.append(path.name); payload = json.loads(path.read_text(encoding="utf-8")); items = payload.get("items", []) if isinstance(payload, dict) else payload
            if not isinstance(items, list): continue
            for index, raw in enumerate(item for item in items if isinstance(item, dict)):
                sender = str(raw.get("sender_email") or raw.get("sender") or "None"); match = EMAIL_PATTERN.search(" ".join([sender, str(raw.get("sender_detail") or "")]))
                record_id = self._id("outbound", path, index)
                row = {"id": record_id, "date": str(raw.get("date") or "None"), "mailProcess": str(raw.get("mail_process") or "None"), "sendResult": str(raw.get("send_result") or "None"), "subject": str(raw.get("subject") or "None"), "senderEmail": str(raw.get("sender_email") or (match.group(0) if match else sender)), "senderName": str(raw.get("sender_name") or ("None" if "@" in sender else sender)), "dept": str(raw.get("sender_dept") or raw.get("dept") or "None"), "receiver": str(raw.get("receiver") or "None"), "size": str(raw.get("size") or "None"), "policy": str(raw.get("policy") or "None"), "attachment": str(raw.get("attach") or "None")}
                records.append((record_id, raw, row))
        return records, files

    def list_records(self, kind: str, start: date, end: date, conditions: list[dict[str, str]], page: int, page_size: int, sort: str, direction: str) -> dict[str, Any]:
        configs: dict[str, tuple[Callable, set[str]]] = {"dlp": (self._collect_dlp, {"event", "time", "computer", "dept", "sourceIp", "username", "source", "destination", "destinationType", "destinationDetail", "fileSize", "fileHash"}), "outbound": (self._collect_outbound, {"date", "mailProcess", "sendResult", "subject", "senderEmail", "senderName", "dept", "receiver", "size", "policy", "attachment"})}
        if kind not in configs or start > end or direction not in {"asc", "desc"}: raise ValueError("Invalid transfer query")
        collector, fields = configs[kind]
        if sort not in fields: raise ValueError(f"Unsupported sort field: {sort}")
        records, files = collector(start, end); output = []
        for _record_id, raw, row in records:
            matches = True
            for condition in conditions:
                query = str(condition.get("query", "")).strip().lower(); field = condition.get("field", "all"); mode = condition.get("mode", "include")
                if not query: continue
                if field == "rawData": value = json.dumps(raw, ensure_ascii=False).lower()
                elif field == "all": value = " ".join(row[name] for name in fields).lower()
                elif field in fields: value = row[field].lower()
                else: raise ValueError(f"Unsupported search field: {field}")
                found = query in value
                if (mode == "include" and not found) or (mode == "exclude" and found): matches = False; break
            if matches: output.append(row)
        output.sort(key=lambda row: (row[sort].lower(), row["id"]), reverse=direction == "desc")
        total = len(output); offset = (page - 1) * page_size
        return {"items": output[offset:offset + page_size], "pagination": {"page": page, "pageSize": page_size, "total": total, "totalPages": max(1, (total + page_size - 1) // page_size)}, "source": {"files": files}}

    def get_record(self, kind: str, record_id: str, start: date, end: date) -> dict[str, Any] | None:
        collector = self._collect_dlp if kind == "dlp" else self._collect_outbound if kind == "outbound" else None
        if collector is None: return None
        for candidate, raw, summary in collector(start, end)[0]:
            if candidate == record_id: return {"summary": summary, "raw": raw}
        return None
