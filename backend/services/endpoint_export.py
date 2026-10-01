from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from backend.services.endpoints import EndpointService
from backend.services.spreadsheet import write_xlsx_workbook


class EndpointExportService:
    COLUMNS = [
        ("hostname", "Hostname"), ("userId", "User ID"), ("user", "User"), ("dept", "Dept"),
        ("wired", "유선 IP"), ("wireless", "무선 IP"), ("vpn", "VPN IP"),
        ("ztnaIp", "ZTNA IP"), ("other", "기타 IP"), ("ztna", "ZTNA 설치 상태"),
        ("lastSeen", "Last Seen (KST)"),
    ]

    def __init__(self, root: Path):
        self.root = root

    @staticmethod
    def _join(categories: dict[str, list[str]], name: str) -> str:
        return "\n".join(categories.get(name, []))

    def build(self, progress=lambda _message: None) -> dict[str, Any]:
        progress("Endpoint Raw Cache 전체 데이터 준비 중")
        rows = []
        for endpoint in EndpointService(self.root).export_rows():
            categories = endpoint["ipCategories"]
            rows.append({"hostname": endpoint["hostname"], "userId": endpoint["userId"], "user": endpoint["user"], "dept": endpoint["dept"],
                         "wired": self._join(categories, "wired"), "wireless": self._join(categories, "wireless"), "vpn": self._join(categories, "vpn"),
                         "ztnaIp": self._join(categories, "ztna"), "other": self._join(categories, "other"), "ztna": endpoint["ztna"], "lastSeen": endpoint["lastSeen"]})
        directory = self.root / "exports"; directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"endpoint_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.xlsx"
        names = write_xlsx_workbook(path, [{"name": "Endpoint List", "rows": rows, "columns": [key for key, _ in self.COLUMNS], "headers": dict(self.COLUMNS)}])
        progress(f"Endpoint XLSX 생성 완료 · {len(rows):,}건")
        return {"filename": path.name, "path": str(path), "rows": len(rows), "sheets": names}
