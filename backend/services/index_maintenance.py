import sqlite3
from pathlib import Path
from typing import Callable


INDEX_DATABASES = {
    "app": {"label": "민감 콘텐츠 인덱스 DB", "relative": "cache/index/app_cache.db"},
    "timeline": {"label": "타임라인 인덱스 DB", "relative": "cache/index/timeline_index.db"},
    "events": {"label": "Detection 리스트 인덱스 DB", "relative": "cache/index/events_index.db"},
}


class IndexMaintenanceService:
    """Manual SQLite maintenance for operator-managed index databases."""

    def __init__(self, root: Path):
        self.root = root

    def databases(self) -> dict[str, dict[str, str | bool | int]]:
        output = {}
        for key, item in INDEX_DATABASES.items():
            path = self.root / str(item["relative"])
            output[key] = {
                "label": str(item["label"]),
                "path": str(path),
                "exists": path.exists(),
                "bytes": path.stat().st_size if path.exists() else 0,
            }
        return output

    def vacuum(self, target: str, progress: Callable[[str], None]) -> dict:
        targets = list(INDEX_DATABASES) if target == "all" else [target]
        unknown = [name for name in targets if name not in INDEX_DATABASES]
        if unknown:
            raise ValueError(f"지원하지 않는 인덱스 DB입니다: {', '.join(unknown)}")

        results = []
        for name in targets:
            item = INDEX_DATABASES[name]
            label = str(item["label"])
            path = self.root / str(item["relative"])
            if not path.exists():
                progress(f"{label} 최적화 건너뜀 · 인덱스 없음")
                results.append({"target": name, "label": label, "status": "missing", "beforeBytes": 0, "afterBytes": 0, "savedBytes": 0})
                continue

            before = path.stat().st_size
            progress(f"{label} 최적화 시작 · 현재 {self._format_bytes(before)}")
            with sqlite3.connect(path, timeout=60, isolation_level=None) as connection:
                connection.execute("PRAGMA busy_timeout=60000")
                connection.execute("PRAGMA optimize")
                connection.execute("VACUUM")
            after = path.stat().st_size
            saved = max(0, before - after)
            progress(f"{label} 최적화 완료 · {self._format_bytes(before)} → {self._format_bytes(after)}")
            results.append({"target": name, "label": label, "status": "optimized", "beforeBytes": before, "afterBytes": after, "savedBytes": saved})
        return {"databases": results}

    @staticmethod
    def _format_bytes(value: int) -> str:
        units = ("B", "KB", "MB", "GB", "TB")
        size = float(value)
        for unit in units:
            if size < 1024 or unit == units[-1]:
                return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
            size /= 1024
