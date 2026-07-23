import hashlib
import json
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Callable

from backend.services.detections import sensor_type
from backend.services.endpoints import kst_time, load_json_list, normalize_key


XDR_RULES = {"XDR-sophos-email-maliciousurl", "XDR-sophos-email-virus", "XDR-sophos-email-impersonation"}


def addresses(values: object) -> list[str]:
    if not isinstance(values, list):
        return []
    output = []
    for value in values:
        if not isinstance(value, dict):
            continue
        address = f"{value.get('localAddress', '')}@{value.get('domainAddress', '')}".strip("@")
        if address:
            output.append(address)
    return output


def parse_nested_raw(event: dict[str, Any]) -> dict[str, Any]:
    raw_data = event.get("rawData") if isinstance(event.get("rawData"), dict) else {}
    raw = raw_data.get("raw", {})
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


class EmailSecurityService:
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.detection_dir = project_root / "cache" / "detections"
        self.email_dir = project_root / "cache" / "emails"

    @staticmethod
    def _files(directory: Path, start: date, end: date) -> list[Path]:
        result = []
        current = start
        while current <= end:
            result.append(directory / f"{current.isoformat()}.json")
            current += timedelta(days=1)
        return result

    @staticmethod
    def _id(source: str, path: Path, index: int, extra: int = 0) -> str:
        return hashlib.sha256(f"{source}:{path.name}:{index}:{extra}".encode()).hexdigest()[:24]

    def _directory_identity(self) -> dict[str, dict[str, str]]:
        output = {}
        for user in load_json_list(self.project_root / "cache" / "users.json"):
            entry = {"userId": str(user.get("exchangeLogin", "") or "None"), "user": str(user.get("name", "") or "None"), "dept": "미분류"}
            for value in (user.get("email"), user.get("exchangeLogin"), user.get("name")):
                if value:
                    output[normalize_key(value)] = entry
        return output

    def _xdr_row(self, event: dict[str, Any], event_id: str, identities: dict[str, dict[str, str]]) -> dict[str, str]:
        description = event.get("detectionDescription") if isinstance(event.get("detectionDescription"), dict) else {}
        rule = str(description.get("createdReasonId") or event.get("detectionRule") or "None")
        raw = parse_nested_raw(event)
        recipients = raw.get("envelopeRecipients", [])
        mailbox = raw.get("mailboxAddress") or ", ".join(map(str, recipients)) if isinstance(recipients, list) else raw.get("mailboxAddress")
        mailbox = str(mailbox or "None")
        to_value = raw.get("to") or raw.get("mailboxAddress") or recipients or "None"
        to_text = ", ".join(map(str, to_value)) if isinstance(to_value, list) else str(to_value)
        ioc = ioc_sha = detail = "None"
        if rule == "XDR-sophos-email-maliciousurl":
            urls = (raw.get("highRiskUrlData") or {}).get("urls", []) if isinstance(raw.get("highRiskUrlData"), dict) else []
            if urls and isinstance(urls[0], dict): ioc, detail = str(urls[0].get("url") or "None"), str(urls[0].get("urlCategory") or "None")
        elif rule == "XDR-sophos-email-virus":
            attachments = raw.get("attachments", [])
            if attachments and isinstance(attachments[0], dict): ioc, ioc_sha, detail = str(attachments[0].get("name") or "None"), str(attachments[0].get("checksum") or "None"), str(attachments[0].get("intelixThreatVerdict") or "None")
        elif rule == "XDR-sophos-email-impersonation":
            imp = raw.get("impersonationData", {})
            if isinstance(imp, dict): ioc, detail = str(imp.get("categoryDetails") or "None"), f"{imp.get('category') or 'None'} / isImpersonation={imp.get('isImpersonation')}"
        identity = identities.get(normalize_key(mailbox.split(",", 1)[0]), {"userId": "None", "user": "None", "dept": "미분류"})
        return {"id": event_id, "time": kst_time(event.get("time")), "rule": rule, "mailbox": mailbox, **identity, "from": str(raw.get("mailFrom") or raw.get("from") or "None"), "to": to_text, "subject": str(raw.get("subject") or "None"), "senderIp": str(raw.get("clientIp") or "None"), "ioc": ioc, "iocSha256": ioc_sha, "detail": detail}

    def _collect_xdr(self, start: date, end: date):
        identities = self._directory_identity(); records = []; files = []
        for path in self._files(self.detection_dir, start, end):
            if not path.exists(): continue
            files.append(path.name)
            for index, event in enumerate(load_json_list(path)):
                description = event.get("detectionDescription") if isinstance(event.get("detectionDescription"), dict) else {}
                rule = str(description.get("createdReasonId") or event.get("detectionRule") or "")
                if sensor_type(event) != "email" and rule not in XDR_RULES: continue
                event_id = self._id("xdr", path, index); records.append((event_id, event, self._xdr_row(event, event_id, identities)))
        return records, files

    def _collect_inbound(self, start: date, end: date):
        records = []; files = []
        for path in self._files(self.email_dir, start, end):
            if not path.exists(): continue
            files.append(path.name)
            for index, event in enumerate(load_json_list(path)):
                to_list = addresses(event.get("to"))
                for recipient_index, recipient in enumerate(to_list):
                    event_id = self._id("inbound", path, index, recipient_index)
                    row = {"id": event_id, "received": kst_time(event.get("receivedAt")), "from": (addresses([event.get("from")]) or ["None"])[0], "to": recipient, "cc": ", ".join(addresses(event.get("cc"))) or "None", "subject": str(event.get("subject") or "None"), "reason": str(event.get("reason") or "None"), "senderIp": str(event.get("clientIp") or "None")}
                    records.append((event_id, event, row))
        return records, files

    def list_records(self, kind: str, start: date, end: date, conditions: list[dict[str, str]], page: int, page_size: int, sort: str, direction: str) -> dict[str, Any]:
        collectors: dict[str, tuple[Callable, set[str]]] = {"xdr": (self._collect_xdr, {"time", "rule", "mailbox", "userId", "user", "dept", "from", "to", "subject", "senderIp", "ioc", "iocSha256", "detail"}), "inbound": (self._collect_inbound, {"received", "from", "to", "cc", "subject", "reason", "senderIp"})}
        if kind not in collectors or start > end or direction not in {"asc", "desc"}: raise ValueError("Invalid email security query")
        collector, fields = collectors[kind]
        if sort not in fields: raise ValueError(f"Unsupported sort: {sort}")
        records, files = collector(start, end); filtered = []
        for _record_id, raw, row in records:
            matches = True
            for condition in conditions:
                query = str(condition.get("query", "")).strip().lower(); field = condition.get("field", "all")
                if not query: continue
                if field == "rawData": value = json.dumps(raw, ensure_ascii=False).lower()
                elif field == "all": value = " ".join(row[name] for name in fields).lower()
                elif field in fields: value = row[field].lower()
                else: raise ValueError(f"Unsupported search field: {field}")
                if query not in value: matches = False; break
            if matches: filtered.append(row)
        filtered.sort(key=lambda row: (row[sort].lower(), row["id"]), reverse=direction == "desc")
        total = len(filtered); offset = (page - 1) * page_size
        return {"items": filtered[offset:offset + page_size], "pagination": {"page": page, "pageSize": page_size, "total": total, "totalPages": max(1, (total + page_size - 1) // page_size)}, "source": {"files": files}}

    def get_record(self, kind: str, record_id: str, start: date, end: date) -> dict[str, Any] | None:
        collector = self._collect_xdr if kind == "xdr" else self._collect_inbound if kind == "inbound" else None
        if collector is None: return None
        for candidate_id, raw, summary in collector(start, end)[0]:
            if candidate_id == record_id: return {"summary": summary, "raw": raw}
        return None
