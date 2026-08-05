import json
import sqlite3
from datetime import date
from pathlib import Path
from typing import Any


class EventListIndexUnavailable(ValueError):
    pass


class EventListIndex:
    """Read display-list rows from cache/index/events_index.db without loading Raw cache payloads."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.path = project_root / "cache" / "index" / "events_index.db"

    def available(self) -> bool:
        if not self.path.exists():
            return False
        try:
            with sqlite3.connect(self.path) as db:
                return bool(db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='event_list_rows'").fetchone())
        except sqlite3.Error:
            return False

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
            raise EventListIndexUnavailable("Detection 리스트 인덱스가 없습니다. Data Management에서 Detection 리스트 전체 캐시 인덱싱을 실행하세요.")
        if not self.fresh_for(kind, start, end):
            raise EventListIndexUnavailable("Detection 리스트 인덱스가 Raw 캐시보다 오래되었습니다. 스케줄러/인덱서 상태를 확인하고 Detection 리스트 인덱싱을 다시 실행하세요.")
        with sqlite3.connect(self.path) as db:
            db.row_factory = sqlite3.Row
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
