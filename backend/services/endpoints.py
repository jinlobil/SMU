import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


SEARCH_FIELDS = {"all", "hostname", "userId", "user", "dept", "ip", "ztna"}
SORT_FIELDS = {"hostname", "userId", "user", "dept", "ip", "ztna", "lastSeen"}


def load_json_list(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError(f"Expected a JSON list: {path}")
    return [row for row in payload if isinstance(row, dict)]


def load_key_value_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    result: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() and value.strip():
            result[normalize_key(key)] = value.strip()
    return result


def normalize_key(value: object) -> str:
    return re.sub(r"\s+", "", str(value or "")).strip().lower()


def normalize_org_name(value: object) -> str:
    name = str(value or "").strip()
    if "\\" in name:
        left, right = name.split("\\", 1)
        name = left.strip() if right.strip().lower() in {"locknlock", "lnl", "local"} else right.strip()
    return re.sub(r"(?i)_mac$", "", name).strip()


def kst_time(value: object) -> str:
    if not value:
        return "None"
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.astimezone(timezone(timedelta(hours=9))).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return str(value)


def build_org_index(orgs: list[dict[str, Any]], dept_names: dict[str, str]) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for org in orgs:
        dept_code = str(org.get("deptCode", "") or "").strip()
        dept_name = dept_names.get(normalize_key(dept_code), str(org.get("deptName", "") or "").strip()) or "미분류"
        users = org.get("users", [])
        if not isinstance(users, list):
            continue
        for user in users:
            if isinstance(user, dict):
                keys = [user.get("name"), user.get("id"), user.get("userId")]
            else:
                keys = [user]
            for key in keys:
                normalized = normalize_key(key)
                if normalized:
                    result[normalized] = {"dept": dept_name, "deptCode": dept_code}
    return result


def directory_department(user: dict[str, Any], dept_names: dict[str, str]) -> tuple[str, str]:
    source = user.get("source") if isinstance(user.get("source"), dict) else {}
    if source.get("type") not in (None, "", "activeDirectory"):
        return "미분류", ""
    groups = user.get("groups") if isinstance(user.get("groups"), dict) else {}
    items = groups.get("items", [])
    if not isinstance(items, list):
        return "미분류", ""
    for group in reversed(items):
        if not isinstance(group, dict):
            continue
        code = str(group.get("displayName", "") or "").strip()
        if code.isdigit():
            return dept_names.get(normalize_key(code), code) or "미분류", code
    return "미분류", ""


def build_directory_index(users: list[dict[str, Any]], dept_names: dict[str, str]) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for user in users:
        dept, dept_code = directory_department(user, dept_names)
        entry = {"dept": dept, "deptCode": dept_code}
        values = [user.get("name"), user.get("exchangeLogin"), user.get("email")]
        email = str(user.get("email", "") or "")
        if "@" in email:
            values.append(email.split("@", 1)[0])
        for value in values:
            key = normalize_key(value)
            if key:
                result[key] = entry
    return result


class EndpointService:
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.cache_dir = project_root / "cache"
        self.env_dir = project_root / "env"

    @property
    def endpoints_path(self) -> Path:
        return self.cache_dir / "endpoints.json"

    def _department_context(self) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, str]], dict[str, str]]:
        dept_names = load_key_value_file(self.env_dir / "User_group_env.txt")
        exceptions = load_key_value_file(self.env_dir / "Report_exception_List.txt")
        org_index = build_org_index(load_json_list(self.cache_dir / "user_groups.json"), dept_names)
        directory_index = build_directory_index(load_json_list(self.cache_dir / "users.json"), dept_names)
        return org_index, directory_index, exceptions

    def _row(self, endpoint: dict[str, Any], context: tuple[dict[str, dict[str, str]], dict[str, dict[str, str]], dict[str, str]], fallback_id: str = "") -> dict[str, str]:
        org_index, directory_index, exceptions = context
        hostname = str(endpoint.get("hostname", "None") or "None")
        person = endpoint.get("associatedPerson") if isinstance(endpoint.get("associatedPerson"), dict) else {}
        user = str(person.get("name", "None") or "None")
        via_login = str(person.get("viaLogin", "") or "")
        user_id = via_login.split("\\")[-1] if "\\" in via_login else via_login
        ips = endpoint.get("ipv4Addresses", [])
        ip_text = ", ".join(str(ip) for ip in ips) if isinstance(ips, list) and ips else "None"
        products = endpoint.get("assignedProducts", [])
        ztna_product = next(
            (
                product
                for product in products
                if isinstance(product, dict) and str(product.get("code", "")).lower() == "ztna"
            ),
            None,
        ) if isinstance(products, list) else None
        ztna = "설치" if ztna_product and str(ztna_product.get("status", "")).lower() == "installed" else "미설치"

        match_name = normalize_org_name(user)
        dept_info = org_index.get(normalize_key(match_name)) or org_index.get(normalize_key(user_id))
        if not dept_info:
            dept_info = directory_index.get(normalize_key(user_id))
        dept = (dept_info or {}).get("dept", "미분류")
        for exception_key in (match_name, user_id, hostname):
            exception_dept = exceptions.get(normalize_key(exception_key))
            if exception_dept:
                dept = exception_dept
                break

        return {
            "id": str(endpoint.get("id", "") or fallback_id or hostname),
            "hostname": hostname,
            "userId": user_id or "None",
            "user": user,
            "dept": dept,
            "ip": ip_text,
            "ztna": ztna,
            "lastSeen": kst_time(endpoint.get("lastSeenAt")),
        }

    def list_endpoints(
        self,
        query: str = "",
        field: str = "all",
        page: int = 1,
        page_size: int = 50,
        sort: str = "hostname",
        direction: str = "asc",
    ) -> dict[str, Any]:
        if field not in SEARCH_FIELDS:
            raise ValueError(f"Unsupported search field: {field}")
        if sort not in SORT_FIELDS:
            raise ValueError(f"Unsupported sort field: {sort}")
        if direction not in {"asc", "desc"}:
            raise ValueError(f"Unsupported sort direction: {direction}")

        context = self._department_context()
        rows = [self._row(endpoint, context, f"endpoint-{index}") for index, endpoint in enumerate(load_json_list(self.endpoints_path))]
        keyword = query.strip().lower()
        if keyword:
            fields = ("hostname", "userId", "user", "dept", "ip", "ztna") if field == "all" else (field,)
            rows = [row for row in rows if any(keyword in row[name].lower() for name in fields)]

        rows.sort(key=lambda row: (row[sort].lower(), row["hostname"].lower()), reverse=direction == "desc")
        total = len(rows)
        start = (page - 1) * page_size
        return {
            "items": rows[start:start + page_size],
            "pagination": {
                "page": page,
                "pageSize": page_size,
                "total": total,
                "totalPages": max(1, (total + page_size - 1) // page_size),
            },
            "source": {
                "path": str(self.endpoints_path),
                "exists": self.endpoints_path.exists(),
            },
        }

    def get_endpoint(self, endpoint_id: str) -> dict[str, Any] | None:
        endpoints = load_json_list(self.endpoints_path)
        context = self._department_context()
        for index, endpoint in enumerate(endpoints):
            fallback_id = f"endpoint-{index}"
            candidate_id = str(endpoint.get("id", "") or fallback_id or endpoint.get("hostname", ""))
            if candidate_id != endpoint_id:
                continue
            return {"summary": self._row(endpoint, context, fallback_id), "raw": endpoint}
        return None
