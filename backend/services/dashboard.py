from collections import Counter, defaultdict
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from backend.services.detections import DetectionService
from backend.services.email_security import EmailSecurityService
from backend.services.endpoints import load_json_list
from backend.services.timeline import TimelineService
from backend.services.transfers import TransferService


class DashboardService:
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.detections = DetectionService(project_root)
        self.email = EmailSecurityService(project_root)
        self.transfers = TransferService(project_root)
        self.timeline = TimelineService(project_root)

    def summary(self, days: int = 7) -> dict[str, Any]:
        bounds = self.timeline.date_bounds()
        end = bounds[1] if bounds else date.today()
        start = end - timedelta(days=days - 1)
        detections = self.detections._events(start, end)[0]
        xdr = self.email._collect_xdr(start, end)[0]
        inbound = self.email._collect_inbound(start, end)[0]
        outbound = self.transfers._collect_outbound(start, end)[0]
        files = self.transfers._collect_dlp(start, end)[0]

        endpoints = load_json_list(self.project_root / "cache/endpoints.json")
        organizations = load_json_list(self.project_root / "cache/user_groups.json")
        endpoint_counts = Counter(str(item.get("type", "computer") or "computer").lower() for item in endpoints)
        users = {
            str(user.get("name", "") if isinstance(user, dict) else user).strip()
            for organization in organizations
            for user in (organization.get("users", []) if isinstance(organization.get("users"), list) else [])
            if str(user.get("name", "") if isinstance(user, dict) else user).strip()
        }

        series: dict[str, dict[str, int]] = {name: defaultdict(int) for name in ("Detection - XDR", "Email - XDR", "Inbound Mail", "Outbound Mail", "File")}
        for _record_id, _raw, row in detections:
            series["Detection - XDR"][row["time"][:10]] += 1
        for _record_id, _raw, row in xdr:
            series["Email - XDR"][row["time"][:10]] += 1
        for _record_id, _raw, row in inbound:
            series["Inbound Mail"][row["received"][:10]] += 1
        for _record_id, _raw, row in outbound:
            series["Outbound Mail"][row["date"][:10]] += 1
        for _record_id, _raw, row in files:
            series["File"][row["time"][:10]] += 1

        dates = [(start + timedelta(days=index)).isoformat() for index in range(days)]
        file_counter = Counter(row["file"] for _record_id, _raw, row in detections if row["file"] != "None")
        hash_counter = Counter(row["sha256"] for _record_id, _raw, row in detections if row["sha256"] != "None")
        host_counter = Counter(row["hostname"] for _record_id, _raw, row in detections if row["hostname"] != "None")
        rule_counter = Counter(row["rule"] for _record_id, _raw, row in detections if row["rule"] != "None")
        sender_counter = Counter(row["senderIp"] for _record_id, _raw, row in inbound if row["senderIp"] != "None")

        return {
            "range": {"start": start.isoformat(), "end": end.isoformat()},
            "endpoints": {"pc": endpoint_counts["computer"], "server": endpoint_counts["server"], "total": len(endpoints)},
            "organization": {"departments": len(organizations), "users": len(users)},
            "totals": {name: sum(values.values()) for name, values in series.items()},
            "trend": {"dates": dates, "series": {name: [values[day] for day in dates] for name, values in series.items()}},
            "top": {
                "files": file_counter.most_common(6), "hashes": hash_counter.most_common(6),
                "hosts": host_counter.most_common(6), "rules": rule_counter.most_common(6),
                "senders": sender_counter.most_common(6),
            },
        }
