import base64, html, json, logging, math, os, re, secrets, time
from datetime import datetime
from pathlib import Path

import requests
from bs4 import BeautifulSoup

log = logging.getLogger("smu.web.collectors")
PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_DIR = PROJECT_ROOT / "env"
CACHE_DIR = PROJECT_ROOT / "cache"
LOG_DIR = str(PROJECT_ROOT / "runtime" / "logs")
DLP_ENV_PATH = str(ENV_DIR / "DLP_env.txt")
MAILSCREEN_ENV_PATH = str(ENV_DIR / "Mail_Screen_env.txt")
DLP_DAY_DIR = str(CACHE_DIR / "dlp")
MAILSCREEN_DAY_DIR = str(CACHE_DIR / "mailscreen")
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(DLP_DAY_DIR, exist_ok=True)
os.makedirs(MAILSCREEN_DAY_DIR, exist_ok=True)

def save_json(path, payload):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    temp = Path(path).with_suffix(Path(path).suffix + ".tmp")
    temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temp, path)

def save_jsonl(path, rows):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    temp = Path(path).with_suffix(Path(path).suffix + ".tmp")
    temp.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")
    os.replace(temp, path)

def load_dlp_env(path):
    if not os.path.exists(path):
        raise RuntimeError(f"Env file not found: {path}")

    values = {}

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            if "=" in line:
                k, v = line.split("=", 1)
                values[k.strip()] = v.strip()

    return values

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)



# ======================================================
# API clients / MailScreen
# - Uses the existing UI worker/config flow; daily cache is JSON under cache/mailscreen.
# ======================================================
MAILSCREEN_FIELD_NAMES = [
    "seq", "date", "mail_process", "send_result", "send_detail", "attach",
    "subject", "sender", "sender_detail", "dept", "receiver", "receiver_detail",
    "size", "policy", "process_date", "approver",
]


def mailscreen_env_bool(value, default=False):
    value = str(value if value is not None else "").strip().lower()
    if not value:
        return default
    return value in {"1", "true", "yes", "y", "on"}


def mailscreen_key_part_to_int(value):
    cleaned = str(value or "").strip()
    if not cleaned:
        raise RuntimeError("MailScreen RSA key part is empty")
    if re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        return int(cleaned, 16)
    if re.fullmatch(r"\d+", cleaned):
        return int(cleaned, 10)
    try:
        return int.from_bytes(base64.b64decode(cleaned), "big")
    except Exception as e:
        raise RuntimeError("Unsupported MailScreen RSA key format") from e


def mailscreen_rsa_encrypt_hex(plaintext, modulus, exponent):
    n = mailscreen_key_part_to_int(modulus)
    e = mailscreen_key_part_to_int(exponent)
    key_len = (n.bit_length() + 7) // 8
    data = str(plaintext or "").encode("utf-8")
    if len(data) > key_len - 11:
        raise RuntimeError("MailScreen login value is too long for RSA key")

    padding_len = key_len - len(data) - 3
    padding = bytearray()
    while len(padding) < padding_len:
        padding.extend(b for b in secrets.token_bytes(padding_len - len(padding)) if b != 0)

    encoded = b"\x00\x02" + bytes(padding[:padding_len]) + b"\x00" + data
    encrypted = pow(int.from_bytes(encoded, "big"), e, n).to_bytes(key_len, "big")
    return encrypted.hex()


def mailscreen_clean_text(value):
    value = html.unescape(str(value or ""))
    value = re.sub(r"<br\s*/?>", "\n", value, flags=re.IGNORECASE)
    text = BeautifulSoup(value, "html.parser").get_text(" ", strip=True)
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def mailscreen_tooltip_text(cell):
    candidates = []
    for node in [cell, *cell.find_all(True)]:
        value = node.get("onmouseover")
        if value:
            candidates.append(str(value))
    for value in candidates:
        match = re.search(r"tooltip\s*\([^,]+,\s*(['\"])(.*?)\1", value, re.IGNORECASE | re.DOTALL)
        if match:
            return mailscreen_clean_text(match.group(2))
    return ""


def mailscreen_cell_value(cell):
    visible = mailscreen_clean_text(cell.get_text(" ", strip=True))
    tooltip = mailscreen_tooltip_text(cell)
    return visible, tooltip


def mailscreen_parse_total_count(html_text):
    match = re.search(r"Total\s*:?\s*([\d,]+)\s*개", str(html_text or ""), re.IGNORECASE)
    if not match:
        return None
    return int(match.group(1).replace(",", ""))


def mailscreen_response_preview(html_text, limit=500):
    text = mailscreen_clean_text(str(html_text or ""))
    return text[:limit]


def mailscreen_has_main_list(html_text):
    soup = BeautifulSoup(str(html_text or ""), "html.parser")
    return soup.select_one("#main_list") is not None


def mailscreen_save_debug_html(html_text, date_str, page, reason):
    safe_reason = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(reason or "debug"))[:40]
    path = os.path.join(
        LOG_DIR,
        f"mailscreen_{date_str}_page{page}_{safe_reason}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(str(html_text or ""))
    return path


def mailscreen_extract_login_tokens(html_text):
    soup = BeautifulSoup(html_text, "html.parser")

    def find_value(name):
        field = soup.find(attrs={"name": name}) or soup.find(id=name)
        if field:
            value = field.get("value") or field.get("content")
            if value:
                return str(value).strip()
        patterns = [
            rf"{re.escape(name)}\s*[:=]\s*['\"]([^'\"]+)['\"]",
            rf"var\s+{re.escape(name)}\s*=\s*['\"]([^'\"]+)['\"]",
        ]
        for pattern in patterns:
            match = re.search(pattern, html_text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return ""

    tokens = {
        "ct": find_value("ct"),
        "rsa_key1": find_value("rsa_key1"),
        "rsa_key2": find_value("rsa_key2"),
    }
    missing = [k for k, v in tokens.items() if not v]
    if missing:
        raise RuntimeError("MailScreen login token missing: " + ", ".join(missing))
    return tokens


def mailscreen_parse_rows(html_text):
    soup = BeautifulSoup(html_text, "html.parser")
    tables = soup.select("#main_list")
    if not tables:
        raise RuntimeError("MailScreen #main_list table not found")

    rows = []
    for table in tables:
        for tr in table.select("tr")[1:]:
            cells = tr.find_all("td")
            if len(cells) < 13:
                continue
            checkbox = cells[0].find("input", attrs={"name": "chk[]"}) or cells[0].find("input", attrs={"type": "checkbox"})
            seq = mailscreen_clean_text(checkbox.get("value", "")) if checkbox else ""
            if not seq:
                continue

            values = [mailscreen_cell_value(cell) for cell in cells]
            row = {name: "" for name in MAILSCREEN_FIELD_NAMES}
            row["seq"] = seq
            row["date"] = values[1][1] or values[1][0]
            row["mail_process"] = values[2][1] or values[2][0]
            row["send_result"] = values[3][0]
            row["send_detail"] = values[3][1]
            row["attach"] = values[4][1] or values[4][0]
            row["subject"] = values[5][1] or values[5][0]
            row["sender"] = values[6][0]
            row["sender_detail"] = values[6][1]
            row["dept"] = values[7][1] or values[7][0]
            row["receiver"] = values[8][0]
            row["receiver_detail"] = values[8][1]
            row["size"] = values[9][1] or values[9][0]
            row["policy"] = values[10][1] or values[10][0]
            row["process_date"] = values[11][1] or values[11][0]
            row["approver"] = values[12][1] or values[12][0]
            rows.append(row)
    return rows


class MailScreenClient:
    def __init__(self, progress_cb=None):
        env = load_dlp_env(MAILSCREEN_ENV_PATH)
        self.progress_cb = progress_cb
        self.base_url = str(env.get("MS_BASE_URL", "")).strip().rstrip("/")
        self.username = str(env.get("MS_USERNAME", "")).strip()
        self.password = str(env.get("MS_PASSWORD", "")).strip()
        self.verify_ssl = mailscreen_env_bool(env.get("MS_VERIFY_SSL", "false"), default=False)
        self.timeout = int(str(env.get("MS_TIMEOUT", "30")).strip() or "30")
        self.row_num = int(str(env.get("MS_ROW_NUM", "100")).strip() or "100")
        self.sleep_seconds = float(str(env.get("MS_SLEEP", "0.3")).strip() or "0.3")

        if not self.base_url:
            raise RuntimeError("MS_BASE_URL missing")
        if not self.username:
            raise RuntimeError("MS_USERNAME missing")
        if not self.password:
            raise RuntimeError("MS_PASSWORD missing")

        if not self.base_url.startswith(("http://", "https://")):
            self.base_url = "https://" + self.base_url

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
            )
        })

    def _notify_progress(self, message):
        if callable(self.progress_cb):
            try:
                self.progress_cb(str(message))
            except Exception:
                pass

    def _headers(self, referer_path="/", content_type="application/x-www-form-urlencoded"):
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Referer": f"{self.base_url}{referer_path}",
            "Origin": self.base_url,
        }
        if content_type:
            headers["Content-Type"] = content_type
        return headers

    def _response_text(self, response):
        if not response.encoding:
            response.encoding = response.apparent_encoding or "utf-8"
        return response.text

    def load_index_page(self):
        r = self.session.get(
            f"{self.base_url}/index.php",
            headers=self._headers("/member/login_ok.php", content_type=""),
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        r.raise_for_status()
        log.info(
            "MailScreen index.php status=%s final_url=%s body_len=%s",
            r.status_code,
            getattr(r, "url", ""),
            len(self._response_text(r)),
        )

    def load_top_page(self):
        r = self.session.get(
            f"{self.base_url}/top.php",
            headers=self._headers("/index.php", content_type=""),
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        r.raise_for_status()
        log.info(
            "MailScreen top.php status=%s final_url=%s body_len=%s",
            r.status_code,
            getattr(r, "url", ""),
            len(self._response_text(r)),
        )

    def warmup_mail_page(self):
        r = self.session.get(
            f"{self.base_url}/mail/mail.php",
            headers=self._headers("/top.php", content_type=""),
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        r.raise_for_status()
        log.info(
            "MailScreen warmup mail.php status=%s final_url=%s body_len=%s",
            r.status_code,
            getattr(r, "url", ""),
            len(self._response_text(r)),
        )

    def login(self):
        login_url = f"{self.base_url}/member/login.php"
        login_ok_url = f"{self.base_url}/member/login_ok.php"
        r = self.session.get(login_url, headers=self._headers("/member/logout.php", content_type=""), timeout=self.timeout, verify=self.verify_ssl)
        r.raise_for_status()
        tokens = mailscreen_extract_login_tokens(self._response_text(r))

        payload = {
            "targeturl": "",
            "ct": tokens["ct"],
            "lang": "ko",
            "saveemail": "on",
            "login_email": mailscreen_rsa_encrypt_hex(self.username, tokens["rsa_key1"], tokens["rsa_key2"]),
            "login_pwd": mailscreen_rsa_encrypt_hex(self.password, tokens["rsa_key1"], tokens["rsa_key2"]),
        }
        r = self.session.post(
            login_ok_url,
            data=payload,
            headers=self._headers("/member/login.php"),
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        r.raise_for_status()
        if "SID" not in self.session.cookies:
            raise RuntimeError("MailScreen login failed: SID cookie not issued")
        log.info("MailScreen login success: SID cookie issued")
        self._notify_progress("MailScreen 로그인 성공")

    def build_mail_payload(self, date_str, page):
        return {
            "who": "", "range": "", "sortby": "", "sortdir": "", "f_type": "",
            "app_approval_reason": "", "seqs": "", "app_etc_comment": "",
            "ref_approval_reason": "", "ref_etc_comment": "", "search_term": "free",
            "s_date": date_str, "s_hour": "0", "s_min": "0",
            "e_date": date_str, "e_hour": "23", "e_min": "59", "post_del": "0",
            "row_num_slt": str(self.row_num), "row_num": str(self.row_num), "gopage": str(page),
            "o_type": "", "prv": "", "att_act": "", "permit_id": "", "user_domain": "",
            "filter": "", "sender_ip": "", "user_name": "", "sender_email": "",
            "dept": "", "dept_code": "", "receiver_email": "", "header_subject": "",
            "virus_name": "", "oattach": "", "s_state": "",
        }

    def fetch_mail_page(self, date_str, page):
        self._notify_progress(f"MailScreen 조회중 {date_str} page={page}")
        r = self.session.post(
            f"{self.base_url}/mail/mail.php",
            data=self.build_mail_payload(date_str, page),
            headers=self._headers("/mail/mail.php"),
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        r.raise_for_status()
        text = self._response_text(r)
        log.info(
            "MailScreen mail.php status=%s final_url=%s content_type=%s body_len=%s page=%s",
            r.status_code,
            getattr(r, "url", ""),
            r.headers.get("Content-Type", ""),
            len(text),
            page,
        )
        if not mailscreen_has_main_list(text):
            debug_path = mailscreen_save_debug_html(text, date_str, page, "main_list_missing")
            preview = mailscreen_response_preview(text)
            log.error("MailScreen #main_list missing page=%s debug_html=%s preview=%s", page, debug_path, preview)
            raise RuntimeError(
                "MailScreen #main_list table not found. "
                f"Saved response HTML for diagnosis: {debug_path}. Preview: {preview}"
            )
        return text

    def collect_mail_day(self, date_str):
        first_html = self.fetch_mail_page(date_str, 1)
        rows = mailscreen_parse_rows(first_html)
        total = mailscreen_parse_total_count(first_html)
        page_count = math.ceil(total / self.row_num) if total is not None else None
        log.info(f"MailScreen page=1 rows={len(rows)} total={total}")
        self._notify_progress(f"MailScreen 1페이지 수집 {len(rows)}건")

        page = 2
        while page_count is None or page <= page_count:
            time.sleep(self.sleep_seconds)
            page_rows = mailscreen_parse_rows(self.fetch_mail_page(date_str, page))
            log.info(f"MailScreen page={page} rows={len(page_rows)}")
            self._notify_progress(f"MailScreen {page}페이지 수집 {len(page_rows)}건")
            if not page_rows:
                break
            rows.extend(page_rows)
            page += 1

        dedup = {}
        for row in rows:
            seq = str(row.get("seq", "")).strip()
            if seq and seq not in dedup:
                dedup[seq] = row
        return list(dedup.values())

    def refresh_mail_day(self, date_str):
        log.info(f"Refreshing MailScreen mail history ({date_str})")
        self.login()
        self.load_index_page()
        self.load_top_page()
        self.warmup_mail_page()
        items = self.collect_mail_day(date_str)
        payload = {
            "source": "mailscreen",
            "type": "mail_history",
            "date": date_str,
            "collected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "count": len(items),
            "items": items,
        }
        file_path = os.path.join(MAILSCREEN_DAY_DIR, f"mailscreen_mail_{date_str}.json")
        save_json(file_path, payload)
        log.info(f"MailScreen saved: {len(items)} ({file_path})")
        self._notify_progress(f"MailScreen 저장 완료 {len(items)}건")
        return {"date": date_str, "count": len(items), "path": file_path}


# ======================================================
# API clients / DLP
# - Handles DLP login, paged retrieval, retry/fallback, and JSONL cache writes.
# - Later module target: modules/dlp/client.py
# ======================================================
class DlpClient:
    def __init__(self, progress_cb=None):
        env = load_dlp_env(DLP_ENV_PATH)
        self.progress_cb = progress_cb

        self.base_url = str(env.get("DLP_BASE_URL", "")).strip().rstrip("/")
        self.username = str(env.get("DLP_USERNAME", "")).strip()
        self.password = str(env.get("DLP_PASSWORD", "")).strip()

        verify_ssl_raw = str(env.get("DLP_VERIFY_SSL", "false")).strip().lower()
        self.verify_ssl = verify_ssl_raw == "true"

        timeout_raw = str(env.get("DLP_TIMEOUT", "30")).strip()
        try:
            self.timeout = int(timeout_raw)
        except Exception:
            self.timeout = 30

        if not self.base_url:
            raise RuntimeError("DLP_BASE_URL missing")
        if not self.username:
            raise RuntimeError("DLP_USERNAME missing")
        if not self.password:
            raise RuntimeError("DLP_PASSWORD missing")

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/146.0.0.0 Safari/537.36"
            )
        })


    def _notify_progress(self, message: str):
        if callable(self.progress_cb):
            try:
                self.progress_cb(str(message))
            except Exception:
                pass

    @property
    def base_home_url(self):
        return f"{self.base_url}/"

    @property
    def login_url(self):
        return f"{self.base_url}/index.php/login"

    @property
    def cf_log_list_url(self):
        return f"{self.base_url}/index.php/cf_log/list"

    def fetch_login_page(self):
        r = self.session.get(
            self.base_home_url,
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        r.raise_for_status()
        return r.text

    def extract_csrf_token(self, html: str):
        soup = BeautifulSoup(html, "html.parser")
        token_input = soup.find("input", {"name": "csrf_token_anon"})

        if not token_input:
            raise RuntimeError("csrf_token_anon input not found")

        token = str(token_input.get("value", "")).strip()
        if not token:
            raise RuntimeError("csrf_token_anon value is empty")

        return token

    def is_logged_in(self, html: str):
        success_keywords = [
            "로그아웃",
            "환영합니다!",
            "Endpoint Protector",
            "보고 및 분석",
            "/index.php/logout",
        ]
        return any(keyword in html for keyword in success_keywords)

    def login(self):
        html = self.fetch_login_page()
        csrf_token = self.extract_csrf_token(html)

        payload = {
            "csrf_token_anon": csrf_token,
            "username": self.username,
            "password": self.password,
            "useGoogleAuth": "0",
            "code": "",
        }

        headers = {
            "Referer": self.base_home_url,
            "Origin": self.base_url,
        }

        files_payload = {k: (None, str(v)) for k, v in payload.items()}

        r = self.session.post(
            self.login_url,
            files=files_payload,
            headers=headers,
            timeout=self.timeout,
            verify=self.verify_ssl,
            allow_redirects=True,
        )
        r.raise_for_status()

        has_ratool_cookie = any(c.name == "ratool" for c in self.session.cookies)
        final_url = str(getattr(r, "url", "") or "")
        redirected_to_index = "/index.php/" in final_url
        log.info(
            f"DLP login post status={r.status_code} final_url={final_url} "
            f"redirected_to_index={redirected_to_index} ratool_cookie={has_ratool_cookie}"
        )

        if not self.is_logged_in(r.text) and not (redirected_to_index and has_ratool_cookie):
            raise RuntimeError("DLP login failed. Check credentials or login flow.")

    def build_cf_log_payload(self, date_str: str, draw: int = 1, start: int = 0, length: int = -1, start_dt: str = None, end_dt: str = None):
        start_dt = start_dt or f"{date_str} 00:00:00"
        end_dt = end_dt or f"{date_str} 23:30:00"

        columns = [
            ("id", False),
            ("event_id", True),
            ("eventtimelocal", True),
            ("eventtime", True),
            ("timestamp", True),
            ("machine_name", True),
            ("ip", True),
            ("client_name", True),
            ("content_policy", True),
            ("content_policy_type", True),
            ("filename", True),
            ("destination", True),
            ("destination_type", True),
            ("destinationDetails", True),
            ("emailSender", True),
            ("emailSubject", True),
            ("item_type", True),
            ("matched_item", True),
            ("item_details", True),
            ("filesize", True),
            ("filehash", True),
            ("os_value", True),
            ("epp_client_version", True),
            ("vid", True),
            ("pid", True),
            ("serialno", True),
            ("justification_id", True),
            ("justification", True),
            ("justification_export", True),
            ("shadow_id", True),
            ("cap_event_id", True),
            ("startDate", True),
            ("endDate", True),
            ("startServerDate", True),
            ("endServerDate", True),
            ("use_old_logs", True),
            ("real_filesize", True),
            ("repositoryType", True),
            ("startClientUtcDate", True),
            ("endClientUtcDate", True),
            ("loclogid", False),
            ("department_id", False),
            ("machine_id", False),
            ("log_id", False),
            ("is_deleted", False),
            ("shadowExists", True),
        ]

        payload = {
            "draw": str(draw),
            "order[0][column]": "4",
            "order[0][dir]": "desc",
            "start": str(start),
            "length": str(length),
            "search[value]": "",
            "search[regex]": "false",
        }

        for idx, (col_name, orderable) in enumerate(columns):
            payload[f"columns[{idx}][data]"] = col_name
            payload[f"columns[{idx}][name]"] = ""
            payload[f"columns[{idx}][searchable]"] = "true"
            payload[f"columns[{idx}][orderable]"] = "true" if orderable else "false"
            payload[f"columns[{idx}][search][value]"] = ""
            payload[f"columns[{idx}][search][regex]"] = "false"

        # 요청 맞춤: 날짜 필터는 columns[30]/[31] 검색값으로 전달
        payload["columns[30][search][value]"] = start_dt
        payload["columns[31][search][value]"] = end_dt

        return payload

    def _looks_like_login_html(self, text: str):
        txt = str(text or "")
        hints = ["로그아웃", "환영합니다!", "/index.php/logout", "Endpoint Protector"]
        return any(h in txt for h in hints)

    def _fetch_cf_logs(self, payload, timeout=None):
        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Referer": f"{self.base_url}/index.php/",
            "Origin": self.base_url,
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        }

        r = self.session.post(
            self.cf_log_list_url,
            data=payload,
            headers=headers,
            timeout=timeout if timeout is not None else self.timeout,
            verify=self.verify_ssl,
        )
        r.raise_for_status()
        content_type = str(r.headers.get("Content-Type", "") or "")
        body_preview = r.text[:600]
        log.info(
            f"DLP cf_log/list status={r.status_code} url={r.url} content_type={content_type} "
            f"body_len={len(r.text)}"
        )

        if self._looks_like_login_html(r.text):
            raise RuntimeError("DLP cf_log/list returned login/main HTML instead of JSON")

        try:
            result = r.json()
        except Exception as e:
            raise RuntimeError(f"Failed to parse DLP response as JSON: {body_preview}") from e

        if "data" not in result:
            keys = list(result.keys()) if isinstance(result, dict) else []
            raise RuntimeError(f"Unexpected DLP response keys={keys} preview={body_preview}")

        rows = result.get("data", [])
        if not isinstance(rows, list):
            rows = []

        records_total = result.get("recordsTotal", len(rows))
        records_filtered = result.get("recordsFiltered", len(rows))
        try:
            records_total = int(records_total)
        except Exception:
            records_total = len(rows)
        try:
            records_filtered = int(records_filtered)
        except Exception:
            records_filtered = len(rows)

        log.info(
            f"DLP cf_log/list parsed recordsTotal={records_total} recordsFiltered={records_filtered} rows={len(rows)}"
        )

        return {
            "rows": rows,
            "records_filtered": max(records_filtered, 0),
            "raw": result,
        }

    def fetch_daily_logs_window(self, date_str: str, start_dt: str, end_dt: str, length: int = -1, draw: int = 1, start: int = 0, timeout=None):
        payload = self.build_cf_log_payload(
            date_str=date_str,
            draw=draw,
            start=start,
            length=length,
            start_dt=start_dt,
            end_dt=end_dt,
        )
        return self._fetch_cf_logs(payload, timeout=timeout)

    def _merge_rows_unique(self, rows):
        dedup = {}
        order = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            key = (
                row.get("log_id")
                or row.get("id")
                or row.get("loclogid")
                or "|".join([
                    str(row.get("timestamp", "")),
                    str(row.get("event_id", "")),
                    str(row.get("machine_name", "")),
                    str(row.get("filename", "")),
                ])
            )
            if key in dedup:
                continue
            dedup[key] = row
            order.append(key)
        return [dedup[k] for k in order]

    def fetch_daily_logs(self, date_str: str):
        try:
            first_try = self.fetch_daily_logs_window(
                date_str=date_str,
                start_dt=f"{date_str} 00:00:00",
                end_dt=f"{date_str} 23:30:00",
                length=-1,
                draw=1,
            )
            first_rows = first_try.get("rows", [])
            first_filtered = int(first_try.get("records_filtered", len(first_rows)) or 0)
            if first_filtered > 0 and len(first_rows) == 0:
                log.warning(
                    f"DLP full-day fetch returned 0 rows but recordsFiltered={first_filtered}. "
                    "Retry with paged fetch (start/length)."
                )
            else:
                return first_rows
        except requests.exceptions.Timeout:
            log.warning(f"DLP full-day fetch timed out ({date_str}). Retry with paged fetch (start/length).")
        except requests.exceptions.RequestException as e:
            if "timed out" not in str(e).lower():
                raise
            log.warning(f"DLP full-day fetch timed out ({date_str}). Retry with paged fetch (start/length).")

        start_dt = f"{date_str} 00:00:00"
        end_dt = f"{date_str} 23:30:00"
        page_size = 500
        fallback_timeout = max(self.timeout, 60)
        retry_count = 2

        self._notify_progress("DLP 2차 조회 시작 (페이징 500건 단위)")

        def fetch_page_with_retry(page_start, draw):
            last_exc = None
            for attempt in range(1, retry_count + 1):
                try:
                    return self.fetch_daily_logs_window(
                        date_str=date_str,
                        start_dt=start_dt,
                        end_dt=end_dt,
                        start=page_start,
                        length=page_size,
                        draw=draw,
                        timeout=fallback_timeout,
                    )
                except requests.exceptions.Timeout as e:
                    last_exc = e
                    log.warning(f"DLP fallback page timeout start={page_start} attempt={attempt}/{retry_count}")
            if last_exc:
                raise last_exc

        first_page = fetch_page_with_retry(0, 1)

        total_count = first_page.get("records_filtered", 0)
        all_rows = list(first_page.get("rows", []))

        if total_count <= len(all_rows):
            merged = self._merge_rows_unique(all_rows)
            log.info(f"DLP fallback paged fetch completed ({date_str}) total={total_count} raw={len(all_rows)} unique={len(merged)}")
            return merged

        page_count = (total_count + page_size - 1) // page_size
        for page_index in range(1, page_count):
            page_start = page_index * page_size
            self._notify_progress(f"DLP 2차 조회 진행중 {page_index + 1}/{page_count} (start={page_start})")
            page = fetch_page_with_retry(page_start, page_index + 1)
            page_rows = page.get("rows", [])
            if not page_rows:
                break
            all_rows.extend(page_rows)

        merged = self._merge_rows_unique(all_rows)
        log.info(f"DLP fallback paged fetch completed ({date_str}) total={total_count} raw={len(all_rows)} unique={len(merged)}")
        self._notify_progress(f"DLP 2차 조회 완료 total={total_count} raw={len(all_rows)} unique={len(merged)}")
        return merged

    def refresh_dlp_day(self, date_str: str):
        log.info(f"Refreshing DLP ({date_str})")

        self.login()
        rows = self.fetch_daily_logs(date_str)

        file_path = os.path.join(DLP_DAY_DIR, f"{date_str}.jsonl")
        save_jsonl(file_path, rows)

        log.info(f"DLP saved: {len(rows)} ({file_path})")
        return {
            "date": date_str,
            "count": len(rows),
            "path": file_path,
        }


# ======================================================
# API clients / Sophos Firewall
# - Handles firewall XML API group lookup and response actions.
