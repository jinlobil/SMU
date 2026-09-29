from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any

from backend.services.spreadsheet import write_xlsx_workbook
from backend.services.timeline import ALL_SOURCES, TimelineService


SHEET_ORDER = ("Detection", "XDR", "Firewall", "Email", "Outbound Mail", "File")
SOURCE_COLUMNS: dict[str, list[tuple[str, str, tuple[str, ...]]]] = {
    "Detection": [("time", "Time", ("time",)), ("user", "User", ("user", "username")), ("asset", "Asset", ("asset", "hostname")), ("event", "Detection / Event", ("event", "rule")), ("severity", "Severity", ("severity",)), ("action", "Action", ("action",)), ("summary", "File / Summary", ("summary", "file")), ("indicator", "Indicator", ("indicator", "sha256", "publicIp"))],
    "XDR": [("time", "Time", ("time",)), ("user", "User", ("user",)), ("asset", "Asset / Mailbox", ("asset", "mailbox")), ("event", "Detection / Event", ("event", "rule")), ("severity", "Severity", ("severity",)), ("sender", "Sender", ("from", "sender")), ("recipient", "Recipient", ("to", "recipient")), ("subject", "Subject", ("summary", "subject")), ("indicator", "IOC", ("indicator", "ioc", "iocSha256"))],
    "Firewall": [("time", "Time", ("time",)), ("user", "User", ("user",)), ("sourceIp", "Source IP", ("sourceIp", "srcIp", "src_ip")), ("destinationIp", "Destination IP", ("destinationIp", "dstIp", "dst_ip", "peer")), ("protocol", "Protocol", ("protocol",)), ("sourcePort", "Source Port", ("sourcePort", "srcPort", "src_port")), ("destinationPort", "Destination Port", ("destinationPort", "dstPort", "dst_port")), ("rule", "Rule", ("event", "rule", "ruleName")), ("action", "Action", ("action",)), ("threat", "Threat", ("indicator", "threat")), ("url", "URL / Domain", ("summary", "url"))],
    "Email": [("time", "Time", ("time", "received")), ("user", "User", ("user",)), ("sender", "Sender", ("from", "sender")), ("recipient", "Recipient", ("to", "recipient", "asset")), ("subject", "Subject", ("summary", "subject")), ("direction", "Direction", ("direction",)), ("action", "Action", ("action",)), ("detection", "Detection / Reason", ("event", "reason")), ("senderIp", "Sender IP", ("peer", "senderIp"))],
    "Outbound Mail": [("time", "Time", ("time", "date")), ("user", "User", ("user", "senderName")), ("sender", "Sender", ("senderEmail", "asset")), ("recipient", "Recipient", ("receiver", "peer")), ("subject", "Subject", ("summary", "subject")), ("action", "Action / Result", ("event", "sendResult")), ("attachment", "Attachment", ("indicator", "attachment")), ("policy", "Policy", ("policy",))],
    "File": [("time", "Time", ("time",)), ("user", "User", ("user", "username")), ("asset", "Asset", ("asset", "computer")), ("fileName", "File Name / Source", ("fileName", "filename", "source")), ("filePath", "File Path", ("filePath", "path")), ("extension", "Extension", ("extension", "fileExtension")), ("action", "Action / Event", ("action", "event")), ("destination", "Destination", ("destination", "peer")), ("detail", "Destination Detail", ("summary", "destinationDetail")), ("fileHash", "File Hash", ("indicator", "fileHash"))],
}


def _key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def _source_row(event: dict[str, Any], source: str) -> dict[str, Any]:
    raw = event.get("raw") if isinstance(event.get("raw"), dict) else {}
    values = {_key(str(key)): value for mapping in (raw, event) for key, value in mapping.items()}
    row = {}
    for output, _header, aliases in SOURCE_COLUMNS[source]:
        row[output] = next((values[_key(alias)] for alias in aliases if values.get(_key(alias)) not in (None, "")), "")
    return row


class TimelineExportService:
    def __init__(self, root: Path, timeline: TimelineService | None = None):
        self.root = root
        self.timeline = timeline or TimelineService(root)

    def export(self, user: str, keyword: str, sources: set[str], path: Path) -> dict[str, Any]:
        selected = sources or set(ALL_SOURCES)
        events = self.timeline.search_all(user, keyword, selected)
        counts = Counter(str(event.get("source", "")) for event in events)
        timestamps = sorted(str(event.get("time", "")) for event in events if str(event.get("time", "")).strip() not in {"", "None"})
        summary_rows = [
            {"item": "검색 사용자", "value": user or "-"},
            {"item": "검색 키워드", "value": keyword or "-"},
            {"item": "선택 Source", "value": ", ".join(source for source in SHEET_ORDER if source in selected)},
            {"item": "데이터 시작일", "value": timestamps[0] if timestamps else "-"},
            {"item": "데이터 종료일", "value": timestamps[-1] if timestamps else "-"},
            {"item": "전체 이벤트", "value": len(events)},
            *({"item": source, "value": counts[source]} for source in SHEET_ORDER),
        ]
        sheets = [{"name": "Summary", "rows": summary_rows, "columns": ["item", "value"], "headers": {"item": "Timeline Export Summary", "value": "Value"}}]
        for source in SHEET_ORDER:
            definitions = SOURCE_COLUMNS[source]
            rows = [_source_row(event, source) for event in events if event.get("source") == source]
            if rows:
                sheets.append({"name": source, "rows": rows, "columns": [item[0] for item in definitions], "headers": {item[0]: item[1] for item in definitions}})
            else:
                sheets.append({"name": source, "rows": [{"message": "검색 결과가 없습니다."}], "columns": ["message"], "headers": {"message": source}})
        names = write_xlsx_workbook(path, sheets)
        return {"path": path, "sheets": names, "events": len(events), "counts": dict(counts), "start": timestamps[0] if timestamps else None, "end": timestamps[-1] if timestamps else None}
