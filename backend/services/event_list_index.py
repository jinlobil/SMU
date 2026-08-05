import json
import sqlite3
from datetime import date
from pathlib import Path
from typing import Any


class EventListIndex:
    """Read display-list rows from cache/index/events_index.db without loading Raw cache payloads."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.path = project_root / "cache" / "index" / "events_index.db"

    def available(self) -> bool:
        if not self.path.exists():
            return False
        try:
            with self._read_connection() as db:
                return bool(db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='event_list_rows'").fetchone())
        except sqlite3.Error:
            return False

    def _read_connection(self) -> sqlite3.Connection:
        uri = f"{self.path.resolve().as_uri()}?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA query_only=ON")
        return connection

    def _source_paths(self, kind: str, start: date, end: date) -> list[Path]:
        specs = {
            "detections": (self.project_root / "cache" / "detections", "{day}.json"),
            "xdr": (self.project_root / "cache" / "detections", "{day}.json"),
            "inbound": (self.project_root / "cache" / "emails", "{day}.json"),
            "outbound": (self.project_root / "cache" / "mailscreen", "mailscreen_mail_{day}.json"),
            "dlp": (self.project_root / "cache" / "dlp", "{day}.jsonl"),
        }
        if kind not in specs:
            return []
        directory, template = specs[kind]
        paths = []
        current = start
        while current <= end:
            paths.append(directory / template.format(day=current.isoformat()))
            current = date.fromordinal(current.toordinal() + 1)
        return paths

    def fresh_for(self, kind: str, start: date, end: date) -> bool:
        if not self.path.exists():
            return False
        index_mtime = self.path.stat().st_mtime_ns
        return all(not path.exists() or path.stat().st_mtime_ns <= index_mtime for path in self._source_paths(kind, start, end))

    def date_bounds(self) -> tuple[date, date] | None:
        if not self.available():
            return None
        with self._read_connection() as db:
            row = db.execute("SELECT MIN(substr(event_time,1,10)), MAX(substr(event_time,1,10)) FROM event_list_rows WHERE event_time <> ''").fetchone()
        if not row or not row[0] or not row[1]:
            return None
        return date.fromisoformat(str(row[0])), date.fromisoformat(str(row[1]))

    def count_by_kind(self, start: date, end: date, kinds: list[str]) -> dict[str, int]:
        if not kinds or not self.available():
            return {kind: 0 for kind in kinds}
        placeholders = ",".join("?" for _ in kinds)
        with self._read_connection() as db:
            rows = db.execute(
                f"""
                SELECT kind, COUNT(*) AS total
                FROM event_list_rows
                WHERE kind IN ({placeholders}) AND substr(event_time,1,10) BETWEEN ? AND ?
                GROUP BY kind
                """,
                (*kinds, start.isoformat(), end.isoformat()),
            ).fetchall()
        totals = {kind: 0 for kind in kinds}
        totals.update({str(row["kind"]): int(row["total"] or 0) for row in rows})
        return totals

    def daily_counts(self, start: date, end: date, kinds: list[str]) -> dict[str, dict[str, int]]:
        if not kinds or not self.available():
            return {kind: {} for kind in kinds}
        placeholders = ",".join("?" for _ in kinds)
        with self._read_connection() as db:
            rows = db.execute(
                f"""
                SELECT kind, substr(event_time,1,10) AS day, COUNT(*) AS total
                FROM event_list_rows
                WHERE kind IN ({placeholders}) AND substr(event_time,1,10) BETWEEN ? AND ?
                GROUP BY kind, day
                """,
                (*kinds, start.isoformat(), end.isoformat()),
            ).fetchall()
        output = {kind: {} for kind in kinds}
        for row in rows:
            output[str(row["kind"])][str(row["day"])] = int(row["total"] or 0)
        return output

    def rows_for_kind(self, kind: str, start: date, end: date) -> list[dict[str, str]]:
        if not self.available():
            return []
        with self._read_connection() as db:
            rows = db.execute(
                """
                SELECT row_json
                FROM event_list_rows
                WHERE kind=? AND substr(event_time,1,10) BETWEEN ? AND ?
                """,
                (kind, start.isoformat(), end.isoformat()),
            ).fetchall()
        output: list[dict[str, str]] = []
        for item in rows:
            try:
                row = json.loads(item["row_json"] or "{}")
            except json.JSONDecodeError:
                row = {}
            if isinstance(row, dict):
                output.append({str(key): str(value) for key, value in row.items()})
        return output

    def require_records(
        self,
        kind: str,
        start: date,
        end: date,
        conditions: list[dict[str, str]],
        page: int,
        page_size: int,
        sort: str,
        direction: str,
        fields: set[str],
    ) -> dict[str, Any]:
        if not self.available():
            return {"items": [], "pagination": {"page": page, "pageSize": page_size, "total": 0, "totalPages": 1}, "source": {"directory": str(self.path), "files": [], "index": "events_index.db"}}
        with self._read_connection() as db:
            rows = db.execute(
                """
                SELECT record_id, event_time, row_json, search_text, source_file
                FROM event_list_rows
                WHERE kind=? AND substr(event_time,1,10) BETWEEN ? AND ?
                """,
                (kind, start.isoformat(), end.isoformat()),
            ).fetchall()
        output: list[dict[str, str]] = []
        files = set()
        for item in rows:
            row = json.loads(item["row_json"] or "{}")
            if item["source_file"]:
                files.add(Path(str(item["source_file"])).name)
            matched = True
            for condition in conditions:
                query = str(condition.get("query", "")).strip().lower()
                if not query:
                    continue
                field = condition.get("field", "all")
                mode = condition.get("mode", "include")
                if field == "rawData":
                    value = str(item["search_text"] or "")
                elif field == "all":
                    value = " ".join(str(row.get(name, "")) for name in fields).lower()
                elif field in fields:
                    value = str(row.get(field, "")).lower()
                else:
                    raise ValueError(f"Unsupported search field: {field}")
                found = query in value
                if (mode == "include" and not found) or (mode == "exclude" and found):
                    matched = False
                    break
            if matched:
                output.append(row)
        output.sort(key=lambda row: (str(row.get(sort, "")).lower(), str(row.get("id", ""))), reverse=direction == "desc")
        total = len(output)
        offset = (page - 1) * page_size
        return {
            "items": output[offset:offset + page_size],
            "pagination": {"page": page, "pageSize": page_size, "total": total, "totalPages": max(1, (total + page_size - 1) // page_size)},
            "source": {"directory": str(self.path), "files": sorted(files), "index": "events_index.db"},
        }
