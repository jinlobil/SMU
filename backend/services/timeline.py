import re
import json
import sqlite3
from collections import defaultdict
from datetime import date
from pathlib import Path
from typing import Any

from backend.services.detections import DetectionService
from backend.services.email_security import EmailSecurityService
from backend.services.endpoints import EndpointService, endpoint_principal, load_json_list, normalize_key
from backend.services.exceptions import ExceptionService
from backend.services.transfers import TransferService


ALL_SOURCES = {"Detection", "XDR", "Email", "Outbound Mail", "File"}
DATE_PATTERN = re.compile(r"(\d{4}-\d{2}-\d{2})")


class TimelineService:
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.detections = DetectionService(project_root)
        self.email = EmailSecurityService(project_root)
        self.transfers = TransferService(project_root)
        self.endpoints = EndpointService(project_root)
        self.exception_service = ExceptionService(project_root)

    def _identities(self) -> tuple[dict[str, dict[str, str]], dict[str, set[str]]]:
        by_alias: dict[str, dict[str, str]] = {}
        aliases_by_name: dict[str, set[str]] = defaultdict(set)

        def add(name: Any, dept: Any, *aliases: Any) -> None:
            display = str(name or "").strip()
            if not display or display.lower() == "none":
                return
            entry = {"user": display, "dept": str(dept or "미분류")}
            display_key = normalize_key(display)
            for value in (display, *aliases):
                text = str(value or "").strip()
                for variant in (text, text.split("\\")[-1], text.split("@", 1)[0]):
                    key = normalize_key(variant)
                    if key:
                        by_alias[key] = entry
                        aliases_by_name[display_key].add(key)

        context = self.endpoints._department_context()
        for index, endpoint in enumerate(load_json_list(self.project_root / "cache/endpoints.json")):
            row = self.endpoints._row(endpoint, context, f"timeline-endpoint-{index}")
            person = endpoint.get("associatedPerson") if isinstance(endpoint.get("associatedPerson"), dict) else {}
            add(row.get("user"), row.get("dept"), row.get("userId"), endpoint_principal(person, row.get("hostname")), row.get("hostname"))
        for user in load_json_list(self.project_root / "cache/users.json"):
            add(user.get("name"), user.get("dept") or user.get("department"), user.get("id"), user.get("userId"), user.get("exchangeLogin"), user.get("email"))
        return by_alias, aliases_by_name

    @staticmethod
    def _identity_candidates(event: dict[str, str]) -> list[str]:
        values = [event.get("user", ""), event.get("userId", ""), event.get("asset", "")]
        return [variant for value in values for variant in (value, value.split("\\")[-1], value.split("@", 1)[0])]

    def _apply_identity(self, event: dict[str, str], identities: dict[str, dict[str, str]]) -> dict[str, str]:
        output = event
        for candidate in self._identity_candidates(event):
            identity = identities.get(normalize_key(candidate))
            if identity:
                output = {**event, "user": identity["user"], "dept": event["dept"] if event["dept"] not in {"", "None", "미분류"} else identity["dept"]}
                break
        final = self.exception_service.finalize(principal=output.get("principal"), hostname=output.get("asset"), email=output.get("email"), user_name=output.get("user"), department=output.get("dept"))
        return {**output, "user": final["user"], "dept": final["dept"]}

    @property
    def index_path(self) -> Path:
        return self.project_root / "cache" / "index" / "timeline_index.db"

    def indexed_events(self, user: str, keyword: str, sources: set[str]) -> list[dict[str, str]] | None:
        if not self.index_path.exists():
            return None
        clauses = []
        params: list[str] = []
        if sources:
            clauses.append(f"source IN ({','.join('?' for _ in sources)})")
            params.extend(sorted(sources))
        user_key = normalize_key(user)
        if user_key:
            identities, aliases_by_name = self._identities()
            terms = {user_key, *aliases_by_name.get(user_key, set())}
            identity_sql = "LOWER(COALESCE(user,'') || ' ' || COALESCE(user_id,'') || ' ' || COALESCE(dept,'') || ' ' || COALESCE(asset,''))"
            clauses.append("(" + " OR ".join(f"{identity_sql} LIKE ?" for _ in terms) + ")")
            params.extend(f"%{term}%" for term in sorted(terms))
        keyword_key = keyword.strip().lower()
        if keyword_key:
            clauses.append("LOWER(COALESCE(time,'') || ' ' || COALESCE(source,'') || ' ' || COALESCE(user,'') || ' ' || COALESCE(user_id,'') || ' ' || COALESCE(dept,'') || ' ' || COALESCE(asset,'') || ' ' || COALESCE(event,'') || ' ' || COALESCE(direction,'') || ' ' || COALESCE(peer,'') || ' ' || COALESCE(summary,'') || ' ' || COALESCE(indicator,'')) LIKE ?")
            params.append(f"%{keyword_key}%")
        where = " AND ".join(clauses) if clauses else "1 = 1"
        try:
            with sqlite3.connect(self.index_path) as connection:
                table_exists = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='timeline_events'"
                ).fetchone()
                if not table_exists:
                    return None
                columns = {row[1] for row in connection.execute("PRAGMA table_info(timeline_events)").fetchall()}
                raw_column = "raw_json" if "raw_json" in columns else "'{}'"
                rows = connection.execute(
                    f"""SELECT time, source, user, user_id, dept, asset, event, direction, peer, summary, indicator, {raw_column}
                    FROM timeline_events WHERE {where} ORDER BY time DESC""",
                    params,
                ).fetchall()
        except sqlite3.Error:
            return None
        identities, _aliases = self._identities()
        return [self._apply_identity(event, identities) for event in [
            {
                "time": str(row[0] or "None"), "source": str(row[1] or "None"),
                "user": str(row[2] or "None"), "userId": str(row[3] or "None"),
                "dept": str(row[4] or "미분류"), "asset": str(row[5] or "None"),
                "event": str(row[6] or "None"), "direction": str(row[7] or "None"),
                "peer": str(row[8] or "None"), "summary": str(row[9] or "None"),
                "indicator": str(row[10] or "None"),
                "raw": json.loads(row[11]) if row[11] else {},
            }
            for row in rows
        ]]

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
    def event(source: str, row: dict[str, str], raw: dict[str, Any] | None = None) -> dict[str, Any]:
        if source == "Detection": result = {"time": row["time"], "source": source, "principal": row.get("principal", ""), "user": row["username"], "userId": "None", "dept": row["dept"], "asset": row["hostname"], "event": row["rule"], "direction": "Host", "peer": row["privateIp"], "summary": row["file"], "indicator": row["sha256"] if row["sha256"] != "None" else row["publicIp"]}
        elif source == "XDR": result = {"time": row["time"], "source": source, "principal": row.get("principal", ""), "email": row["mailbox"], "user": row["user"], "userId": row["userId"], "dept": row["dept"], "asset": row["mailbox"], "event": row["rule"], "direction": f"{row['from']} → {row['to']}", "peer": row["senderIp"], "summary": row["subject"], "indicator": row["iocSha256"] if row["iocSha256"] != "None" else row["ioc"]}
        elif source == "Email": result = {"time": row["received"], "source": source, "principal": row.get("principal", ""), "email": row["to"], "user": row.get("user", row["to"]), "userId": row.get("userId", row["to"].split("@", 1)[0]), "dept": row.get("dept", "미분류"), "asset": row["to"], "event": row["reason"], "direction": f"{row['from']} → {row['to']}", "peer": row["senderIp"], "summary": row["subject"], "indicator": row["senderIp"]}
        elif source == "Outbound Mail": result = {"time": row["date"], "source": source, "email": row["senderEmail"], "user": row["senderName"], "userId": row["senderEmail"].split("@", 1)[0], "dept": row["dept"], "asset": row["senderEmail"], "event": row["sendResult"], "direction": f"{row['senderEmail']} → {row['receiver']}", "peer": row["receiver"], "summary": row["subject"], "indicator": row["attachment"]}
        else: result = {"time": row["time"], "source": source, "principal": row.get("principal", ""), "user": row["username"], "userId": row["username"], "dept": row["dept"], "asset": row["computer"], "event": row["event"], "direction": f"{row['source']} → {row['destination']}", "peer": row["sourceIp"], "summary": row["destinationDetail"], "indicator": row["fileHash"]}
        return {**result, "sourceFile": row.get("_sourceFile", ""), "raw": raw or {}}

    def all_events(self, sources: set[str], progress=None) -> list[dict[str, str]]:
        bounds = self.date_bounds()
        if bounds is None: return []
        return self.events_between(bounds[0], bounds[1], sources, progress)

    def events_between(self, start: date, end: date, sources: set[str], progress=None) -> list[dict[str, str]]:
        output = []
        if "Detection" in sources:
            rows = self.detections._events(start, end)[0]; output.extend(self.event("Detection", row, raw) for _id, raw, row in rows)
            if progress: progress(f"통합 타임라인 · Detection {len(rows):,}건 변환 완료")
        if "XDR" in sources:
            rows = self.email._collect_xdr(start, end)[0]; output.extend(self.event("XDR", row, raw) for _id, raw, row in rows)
            if progress: progress(f"통합 타임라인 · Email XDR {len(rows):,}건 변환 완료")
        if "Email" in sources:
            rows = self.email._collect_inbound(start, end)[0]; output.extend(self.event("Email", row, raw) for _id, raw, row in rows)
            if progress: progress(f"통합 타임라인 · Inbound Mail {len(rows):,}건 변환 완료")
        if "Outbound Mail" in sources:
            rows = self.transfers._collect_outbound(start, end)[0]; output.extend(self.event("Outbound Mail", row, raw) for _id, raw, row in rows)
            if progress: progress(f"통합 타임라인 · Outbound Mail {len(rows):,}건 변환 완료")
        if "File" in sources:
            rows = self.transfers._collect_dlp(start, end)[0]; output.extend(self.event("File", row, raw) for _id, raw, row in rows)
            if progress: progress(f"통합 타임라인 · DLP File {len(rows):,}건 변환 완료")
        if progress: progress(f"통합 타임라인 · 사용자/부서 정보 최종 반영 중 · 총 {len(output):,}건")
        identities, _aliases = self._identities()
        finalized = []
        for index, event in enumerate(output, 1):
            finalized.append(self._apply_identity(event, identities))
            if progress and index % 25000 == 0: progress(f"통합 타임라인 · 사용자/부서 반영 {index:,}/{len(output):,}건")
        return finalized

    def search(self, user: str, keyword: str, sources: set[str], offset: int = 0, limit: int = 250) -> dict[str, Any]:
        invalid = sources - ALL_SOURCES
        if invalid: raise ValueError(f"Unsupported timeline source: {sorted(invalid)}")
        indexed = self.indexed_events(user, keyword, sources)
        if indexed is None:
            user_key = user.strip().lower(); keyword_key = keyword.strip().lower()
            events = []
            for event in self.all_events(sources):
                identity_text = " ".join(event[key] for key in ("user", "userId", "dept", "asset")).lower()
                full_text = " ".join(str(value) for key, value in event.items() if key != "raw").lower()
                if user_key and user_key not in identity_text: continue
                if keyword_key and keyword_key not in full_text: continue
                events.append(event)
            data_source = "cache-scan"
        else:
            events = indexed
            data_source = "sqlite-index"
            # Indexes made before raw_json was introduced remain readable.  Do
            # not, however, expose an empty object to the UI: recover the
            # original record from the cache until the next full rebuild.
            if any(not event.get("raw") for event in events):
                raw_events = self.all_events(sources)
                raw_by_key = {self._event_key(event): event.get("raw", {}) for event in raw_events}
                for event in events:
                    if not event.get("raw"):
                        event["raw"] = raw_by_key.get(self._event_key(event), {})
        groups: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
        for event in events:
            bucket = event["time"][:16] if len(event["time"]) >= 16 else event["time"]
            groups[(bucket, event["source"], event["event"])].append(event)
        normalized = [{"bucket": key[0], "source": key[1], "event": key[2], "count": len(items), "items": sorted(items, key=lambda item: item["time"], reverse=True)[:100]} for key, items in groups.items()]
        normalized.sort(key=lambda group: group["bucket"], reverse=True)
        return {"groups": normalized[offset:offset + limit], "pagination": {"offset": offset, "limit": limit, "totalGroups": len(normalized), "totalEvents": len(events)}, "bounds": self.date_bounds(), "source": data_source}

    @staticmethod
    def _event_key(event: dict[str, Any]) -> tuple[str, ...]:
        """Stable cache/index join key used to hydrate legacy index rows."""
        return tuple(str(event.get(field, "")) for field in
                     ("time", "source", "userId", "asset", "event", "direction", "summary", "indicator"))
