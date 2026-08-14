import json
import sqlite3
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from backend.services.event_list_schema import FIELD_COLUMNS, SCHEMA_VERSION


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

    @staticmethod
    def _range_bounds(start: date, end: date) -> tuple[str, str]:
        return start.isoformat(), (end + timedelta(days=1)).isoformat()

    @staticmethod
    def _field_expression(field: str, allowed_fields: set[str], structured: bool) -> str:
        # JSON paths cannot be bound as identifiers. Only service-owned allowlisted
        # field names may reach this expression; request input is never interpolated.
        if field not in allowed_fields or not field.replace("_", "").isalnum():
            raise ValueError(f"Unsupported search field: {field}")
        return FIELD_COLUMNS[field] if structured and field in FIELD_COLUMNS else f"json_extract(row_json, '$.{field}')"

    @staticmethod
    def _structured_schema(db: sqlite3.Connection) -> bool:
        try:
            row = db.execute("SELECT value FROM index_metadata WHERE key='event_list_schema_version'").fetchone()
            return bool(row and str(row[0]) == SCHEMA_VERSION)
        except sqlite3.Error:
            return False

    def _source_paths(self, kind: str, start: date, end: date) -> list[Path]:
        specs = {
            "detections": (self.project_root / "cache" / "detections", "{day}.json"),
            "xdr": (self.project_root / "cache" / "detections", "{day}.json"),
            "firewall": (self.project_root / "cache" / "detections", "{day}.json"),
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
                WHERE kind IN ({placeholders}) AND event_time >= ? AND event_time < ?
                GROUP BY kind
                """,
                (*kinds, *self._range_bounds(start, end)),
            ).fetchall()
        totals = {kind: 0 for kind in kinds}
        totals.update({str(row["kind"]): int(row["total"] or 0) for row in rows})
        return totals

    def kind_status(self, kinds: list[str]) -> dict[str, dict[str, Any]]:
        output = {kind: {"indexedEvents": 0, "lastIndexed": None, "status": "missing", "indexFileBytes": 0} for kind in kinds}
        if not self.available():
            return output
        size = self.path.stat().st_size
        with self._read_connection() as db:
            placeholders = ",".join("?" for _ in kinds)
            rows = db.execute(f"SELECT kind, COUNT(*), MAX(event_time) FROM event_list_rows WHERE kind IN ({placeholders}) GROUP BY kind", kinds).fetchall()
        for row in rows:
            output[str(row[0])] = {"indexedEvents": int(row[1]), "lastIndexed": row[2], "status": "ready", "indexFileBytes": size}
        return output

    def daily_counts(self, start: date, end: date, kinds: list[str]) -> dict[str, dict[str, int]]:
        if not kinds or not self.available():
            return {kind: {} for kind in kinds}
        placeholders = ",".join("?" for _ in kinds)
        with self._read_connection() as db:
            rows = db.execute(
                f"""
                SELECT kind, substr(event_time,1,10) AS day, COUNT(*) AS total
                FROM event_list_rows
                WHERE kind IN ({placeholders}) AND event_time >= ? AND event_time < ?
                GROUP BY kind, day
                """,
                (*kinds, *self._range_bounds(start, end)),
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
                WHERE kind=? AND event_time >= ? AND event_time < ?
                """,
                (kind, *self._range_bounds(start, end)),
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
        if sort not in fields:
            raise ValueError(f"Unsupported sort: {sort}")
        if direction not in {"asc", "desc"}:
            raise ValueError(f"Unsupported direction: {direction}")

        where = ["kind=?", "event_time >= ?", "event_time < ?"]
        parameters: list[Any] = [kind, *self._range_bounds(start, end)]
        validated_conditions: list[tuple[str, str, str]] = []
        for condition in conditions:
            query = str(condition.get("query", "")).strip().lower()
            if not query:
                continue
            field = str(condition.get("field", "all"))
            mode = str(condition.get("mode", "include"))
            if mode not in {"include", "exclude"}:
                raise ValueError(f"Unsupported search mode: {mode}")
            if field not in {"all", "rawData"} and field not in fields:
                raise ValueError(f"Unsupported search field: {field}")
            validated_conditions.append((field, mode, query))

        with self._read_connection() as db:
            structured = self._structured_schema(db)
            all_expression = " || ' ' || ".join(
                f"COALESCE(CAST({self._field_expression(name, fields, structured)} AS TEXT), '')"
                for name in sorted(fields)
            ) or "''"
            for field, mode, query in validated_conditions:
                if field == "rawData":
                    value_expression = "COALESCE(search_text, '')"
                elif field == "all":
                    value_expression = all_expression
                else:
                    value_expression = f"COALESCE(CAST({self._field_expression(field, fields, structured)} AS TEXT), '')"
                predicate = f"instr(lower({value_expression}), ?) > 0"
                where.append(predicate if mode == "include" else f"NOT ({predicate})")
                parameters.append(query)
            where_sql = " AND ".join(where)
            sort_expression = self._field_expression(sort, fields, structured)
            order = direction.upper()
            offset = (page - 1) * page_size
            total = int(db.execute(f"SELECT COUNT(*) FROM event_list_rows WHERE {where_sql}", parameters).fetchone()[0])
            rows = db.execute(
                f"""
                SELECT row_json
                FROM event_list_rows
                WHERE {where_sql}
                ORDER BY lower(COALESCE(CAST({sort_expression} AS TEXT), '')) {order}, record_id {order}
                LIMIT ? OFFSET ?
                """,
                (*parameters, page_size, offset),
            ).fetchall()
            source_rows = db.execute(
                """
                SELECT DISTINCT source_file FROM event_list_rows
                WHERE kind=? AND event_time >= ? AND event_time < ? AND source_file <> ''
                """,
                (kind, *self._range_bounds(start, end)),
            ).fetchall()
        output = [json.loads(item["row_json"] or "{}") for item in rows]
        files = {Path(str(item["source_file"])).name for item in source_rows}
        return {
            "items": output,
            "pagination": {"page": page, "pageSize": page_size, "total": total, "totalPages": max(1, (total + page_size - 1) // page_size)},
            "source": {"directory": str(self.path), "files": sorted(files), "index": "events_index.db"},
        }
