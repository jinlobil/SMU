import os
import json
import urllib.parse
import urllib.request
import urllib.error
import time
from pathlib import Path
from typing import Any

from backend.services.endpoints import load_key_value_file


class SophosClient:
    def __init__(self, env_path: Path):
        values = load_key_value_file(env_path)
        self.client_id = values.get("sophos_client_id", os.getenv("SOPHOS_CLIENT_ID", "")).strip()
        self.client_secret = values.get("sophos_client_secret", os.getenv("SOPHOS_CLIENT_SECRET", "")).strip()
        self.token_url = values.get("sophos_token_url", os.getenv("SOPHOS_TOKEN_URL", "https://id.sophos.com/api/v2/oauth2/token")).strip()
        self.whoami_url = values.get("sophos_whoami_url", os.getenv("SOPHOS_WHOAMI_URL", "https://api.central.sophos.com/whoami/v1")).strip()
        if not self.client_id or not self.client_secret:
            raise RuntimeError(f"SOPHOS_CLIENT_ID / SOPHOS_CLIENT_SECRET missing in {env_path}")
        self.token = ""
        self.tenant_id = ""
        self.base_url = ""

    def authenticate(self) -> None:
        token_payload = urllib.parse.urlencode({
            "grant_type": "client_credentials", "client_id": self.client_id,
            "client_secret": self.client_secret, "scope": "token",
        }).encode("utf-8")
        token_request = urllib.request.Request(self.token_url, data=token_payload, method="POST")
        token_request.add_header("Content-Type", "application/x-www-form-urlencoded")
        token_response = self.request_json(token_request)
        self.token = str(token_response.get("access_token", ""))
        if not self.token:
            raise RuntimeError("Sophos access_token missing")

        whoami_request = urllib.request.Request(self.whoami_url, headers={"Authorization": f"Bearer {self.token}"})
        payload = self.request_json(whoami_request)
        self.tenant_id = str(payload.get("id", ""))
        api_hosts = payload.get("apiHosts") if isinstance(payload.get("apiHosts"), dict) else {}
        host = str(api_hosts.get("dataRegion") or payload.get("apiHost") or "").strip()
        if not self.tenant_id or not host:
            raise RuntimeError("Sophos whoami response is missing tenant or API host")
        self.base_url = host if host.startswith(("http://", "https://")) else f"https://{host}"

    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}", "X-Tenant-ID": self.tenant_id, "Accept": "application/json"}

    @staticmethod
    def request_json(request: urllib.request.Request) -> dict[str, Any]:
        with urllib.request.urlopen(request, timeout=45) as response:
            payload = json.loads(response.read().decode("utf-8"))
        if not isinstance(payload, dict):
            raise RuntimeError("Sophos API returned a non-object JSON response")
        return payload

    def paged_items(self, path: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        params: dict[str, Any] = {"pageSize": 100, "pageTotal": "true"}
        page = 1
        while True:
            url = f"{self.base_url}{path}?{urllib.parse.urlencode(params)}"
            payload = self.request_json(urllib.request.Request(url, headers=self.headers()))
            page_items = payload.get("items", [])
            if isinstance(page_items, list):
                items.extend(item for item in page_items if isinstance(item, dict))
            pages = payload.get("pages") if isinstance(payload.get("pages"), dict) else {}
            next_key = pages.get("nextKey")
            if next_key:
                params["pageFromKey"] = next_key
                continue
            total_pages = pages.get("total")
            if isinstance(total_pages, int) and page < total_pages:
                page += 1
                params["page"] = page
                continue
            break
        return items

    def fetch_endpoints(self) -> list[dict[str, Any]]:
        self.authenticate()
        return self.paged_items("/endpoint/v1/endpoints")

    def fetch_users(self) -> list[dict[str, Any]]:
        return self.paged_items("/common/v1/directory/users")

    def fetch_organizations(self, department_names: dict[str, str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        self.authenticate()
        groups = self.paged_items("/common/v1/directory/user-groups")
        output: list[dict[str, Any]] = []
        for group in groups:
            code = str(group.get("displayName") or group.get("name") or "None")
            users_value = group.get("users", {})
            raw_users = users_value.get("items", []) if isinstance(users_value, dict) else users_value
            users = []
            if isinstance(raw_users, list):
                users = [dict(user, name=user.get("name", "None")) if isinstance(user, dict) else {"name": str(user)} for user in raw_users]
            output.append({"deptCode": code, "deptName": department_names.get(code, code), "users": users})
        return output, self.fetch_users()

    def fetch_detections(self, from_timestamp: str, to_timestamp: str, progress=lambda _message: None) -> list[dict[str, Any]]:
        self.authenticate()
        query_url = f"{self.base_url}/detections/v1/queries/detections"
        body = json.dumps({"from": from_timestamp, "to": to_timestamp, "sort": [{"field": "time", "direction": "desc"}]}).encode("utf-8")
        request = urllib.request.Request(query_url, data=body, headers={**self.headers(), "Content-Type": "application/json"}, method="POST")
        query_id = str(self.request_json(request).get("id", ""))
        if not query_id: raise RuntimeError("Sophos detections query id missing")
        results = []; page = 1; total_pages = None
        while total_pages is None or page <= total_pages:
            progress(f"Detection 페이지 {page} 조회 중")
            url = f"{query_url}/{query_id}/results?{urllib.parse.urlencode({'page': page, 'pageSize': 200})}"
            try:
                payload = self.request_json(urllib.request.Request(url, headers=self.headers()))
            except urllib.error.HTTPError as exc:
                if exc.code in {202, 400, 429}:
                    time.sleep(10 if exc.code == 429 else 5); continue
                raise
            pages = payload.get("pages") if isinstance(payload.get("pages"), dict) else {}
            total_pages = int(pages.get("total", 1) or 1)
            items = payload.get("items", [])
            if isinstance(items, list): results.extend(item for item in items if isinstance(item, dict))
            page += 1
        return results

    def fetch_inbound_emails(self, from_timestamp: str, to_timestamp: str, progress=lambda _message: None) -> list[dict[str, Any]]:
        self.authenticate(); url = f"{self.base_url}/email/v1/quarantine/messages/search"; output = []; next_key = ""; page = 1
        while True:
            progress(f"Inbound Mail 페이지 {page} 조회 중")
            payload_body: dict[str, Any] = {"beginDate": from_timestamp, "endDate": to_timestamp, "pageSize": 100}
            if next_key: payload_body["pageFromKey"] = next_key
            request = urllib.request.Request(url, data=json.dumps(payload_body).encode("utf-8"), headers={**self.headers(), "Content-Type": "application/json"}, method="POST")
            payload = self.request_json(request); items = payload.get("items", [])
            if isinstance(items, list): output.extend(item for item in items if isinstance(item, dict))
            next_key = str((payload.get("pages") or {}).get("nextKey") or "")
            if not next_key: break
            page += 1
        return output
