import re
from collections import defaultdict
from datetime import date
from pathlib import Path
from typing import Any

from backend.services.detections import DetectionService
from backend.services.email_security import EmailSecurityService
from backend.services.transfers import TransferService


ALL_SOURCES = {"Detection", "XDR", "Email", "Outbound Mail", "File"}
DATE_PATTERN = re.compile(r"(\d{4}-\d{2}-\d{2})")


class TimelineService:
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.detections = DetectionService(project_root)
        self.email = EmailSecurityService(project_root)
        self.transfers = TransferService(project_root)

    def date_bounds(self) -> tuple[date, date] | None:
        dates = []
        for directory in (self.project_root / "cache/detections", self.project_root / "cache/emails", self.project_root / "cache/mailscreen", self.project_root / "cache/dlp"):
            if not directory.exists(): continue
            for path in directory.iterdir():
                match = DATE_PATTERN.search(path.name)
                if match:
                    try: dates.append(date.fromisoformat(match.group(1)))
                    except ValueError: pass
        return (min(dates), max(dates)) if dates else None

    @staticmethod
    def event(source: str, row: dict[str, str]) -> dict[str, str]:
        if source == "Detection": return {"time": row["time"], "source": source, "user": row["username"], "userId": "None", "dept": row["dept"], "asset": row["hostname"], "event": row["rule"], "direction": "Host", "peer": row["privateIp"], "summary": row["file"], "indicator": row["sha256"] if row["sha256"] != "None" else row["publicIp"]}
        if source == "XDR": return {"time": row["time"], "source": source, "user": row["user"], "userId": row["userId"], "dept": row["dept"], "asset": row["mailbox"], "event": row["rule"], "direction": f"{row['from']} → {row['to']}", "peer": row["senderIp"], "summary": row["subject"], "indicator": row["iocSha256"] if row["iocSha256"] != "None" else row["ioc"]}
        if source == "Email": return {"time": row["received"], "source": source, "user": row["to"], "userId": row["to"].split("@", 1)[0], "dept": "미분류", "asset": row["to"], "event": row["reason"], "direction": f"{row['from']} → {row['to']}", "peer": row["senderIp"], "summary": row["subject"], "indicator": row["senderIp"]}
        if source == "Outbound Mail": return {"time": row["date"], "source": source, "user": row["senderName"], "userId": row["senderEmail"].split("@", 1)[0], "dept": row["dept"], "asset": row["senderEmail"], "event": row["sendResult"], "direction": f"{row['senderEmail']} → {row['receiver']}", "peer": row["receiver"], "summary": row["subject"], "indicator": row["attachment"]}
        return {"time": row["time"], "source": source, "user": row["username"], "userId": row["username"], "dept": row["dept"], "asset": row["computer"], "event": row["event"], "direction": f"{row['source']} → {row['destination']}", "peer": row["sourceIp"], "summary": row["destinationDetail"], "indicator": row["fileHash"]}

    def all_events(self, sources: set[str]) -> list[dict[str, str]]:
        bounds = self.date_bounds()
        if bounds is None: return []
        start, end = bounds; output = []
        if "Detection" in sources:
            output.extend(self.event("Detection", row) for _id, _raw, row in self.detections._events(start, end)[0])
        if "XDR" in sources:
            output.extend(self.event("XDR", row) for _id, _raw, row in self.email._collect_xdr(start, end)[0])
        if "Email" in sources:
            output.extend(self.event("Email", row) for _id, _raw, row in self.email._collect_inbound(start, end)[0])
        if "Outbound Mail" in sources:
            output.extend(self.event("Outbound Mail", row) for _id, _raw, row in self.transfers._collect_outbound(start, end)[0])
        if "File" in sources:
            output.extend(self.event("File", row) for _id, _raw, row in self.transfers._collect_dlp(start, end)[0])
        return output

    def search(self, user: str, keyword: str, sources: set[str], offset: int = 0, limit: int = 250) -> dict[str, Any]:
        invalid = sources - ALL_SOURCES
        if invalid: raise ValueError(f"Unsupported timeline source: {sorted(invalid)}")
        user_key = user.strip().lower(); keyword_key = keyword.strip().lower()
        events = []
        for event in self.all_events(sources):
            identity_text = " ".join(event[key] for key in ("user", "userId", "dept", "asset")).lower()
            full_text = " ".join(event.values()).lower()
            if user_key and user_key not in identity_text: continue
            if keyword_key and keyword_key not in full_text: continue
            events.append(event)
        groups: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
        for event in events:
            bucket = event["time"][:16] if len(event["time"]) >= 16 else event["time"]
            groups[(bucket, event["source"], event["event"])].append(event)
        normalized = [{"bucket": key[0], "source": key[1], "event": key[2], "count": len(items), "items": sorted(items, key=lambda item: item["time"], reverse=True)[:100]} for key, items in groups.items()]
        normalized.sort(key=lambda group: group["bucket"], reverse=True)
        return {"groups": normalized[offset:offset + limit], "pagination": {"offset": offset, "limit": limit, "totalGroups": len(normalized), "totalEvents": len(events)}, "bounds": self.date_bounds()}
