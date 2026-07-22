from pathlib import Path
from typing import Any

from backend.services.endpoints import load_json_list, load_key_value_file, normalize_key


SEARCH_FIELDS = {"all", "deptCode", "deptName", "user"}
SORT_FIELDS = {"deptCode", "deptName", "user"}


class OrganizationService:
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.cache_path = project_root / "cache" / "user_groups.json"
        self.department_names_path = project_root / "env" / "User_group_env.txt"

    def _rows(self) -> list[dict[str, str]]:
        department_names = load_key_value_file(self.department_names_path)
        rows: list[dict[str, str]] = []
        for department in load_json_list(self.cache_path):
            code = str(department.get("deptCode", "None") or "None")
            name = department_names.get(normalize_key(code), str(department.get("deptName", "None") or "None"))
            users = department.get("users", [])
            if not isinstance(users, list):
                continue
            for user in users:
                user_name = str(user.get("name", "") if isinstance(user, dict) else user).strip()
                if not user_name or user_name.lower() == "none":
                    continue
                rows.append({"deptCode": code, "deptName": name, "user": user_name})
        return rows

    def list_organizations(
        self,
        query: str = "",
        field: str = "all",
        page: int = 1,
        page_size: int = 50,
        sort: str = "deptCode",
        direction: str = "asc",
    ) -> dict[str, Any]:
        if field not in SEARCH_FIELDS:
            raise ValueError(f"Unsupported search field: {field}")
        if sort not in SORT_FIELDS:
            raise ValueError(f"Unsupported sort field: {sort}")
        if direction not in {"asc", "desc"}:
            raise ValueError(f"Unsupported sort direction: {direction}")

        rows = self._rows()
        keyword = query.strip().lower()
        if keyword:
            fields = ("deptCode", "deptName", "user") if field == "all" else (field,)
            rows = [row for row in rows if any(keyword in row[name].lower() for name in fields)]
        rows.sort(key=lambda row: (row[sort].lower(), row["user"].lower()), reverse=direction == "desc")

        total = len(rows)
        start = (page - 1) * page_size
        unique_departments = len({(row["deptCode"], row["deptName"]) for row in rows})
        return {
            "items": rows[start:start + page_size],
            "pagination": {
                "page": page,
                "pageSize": page_size,
                "total": total,
                "totalPages": max(1, (total + page_size - 1) // page_size),
            },
            "summary": {"departments": unique_departments, "users": total},
            "source": {"path": str(self.cache_path), "exists": self.cache_path.exists()},
        }
