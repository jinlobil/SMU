# Generated verbatim from uimain_window.py report implementation.
from __future__ import annotations
import html, json, logging, os, re, time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
try:
 from matplotlib.figure import Figure
except ImportError:
 Figure = None
log=logging.getLogger("smu.report")
REPORT_DIR="reports"
ENDPOINTS=[]
ORGS=[]
DEPT_MAP={}
REPORT_EXCEPTION_MAP={}
DIRECTORY_USER_INDEX={}
HOSTNAME_DEPT_MAP={}
MAILSCREEN_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
MAILSCREEN_BLANK_VALUES = {"", "none", "null", "nan", "미분류", "&nbsp;"}

DLP_AI_DEST_KW = [
    "openai", "chatgpt", "oaiusercontent", "claude", "claudeusercontent",
    "gemini", "copilot", "perplexity", "ppl-ai-file-upload", "midjourney",
    "magnific", "klingai", "zeta-ai", "aspose.ai", "genspark",
    "aicreation", "gamma.app", "vizcom", "firefly", "sensei.adobe",
    "vyro.ai", "chaton.ai", "flowith.io", "linnk.ai", "upscale.media",
    "miricanvas", "clovanote", "deevid.ai", "nano-banana.ai", "napkin.ai",
    "picaapi.com", "meshy.ai", "topazlabs", "photoroom",
    "picsart", "krea.ai", "use.ai", "clova-x.naver.com", "polarishare",
    "livewiki", "freepik", "chat-orchestrator-prod", "aistudio.google.com", "aigc",
]

DLP_CONVERTER_DEST_KW = [
    "ilovepdf.com", "iloveimg.com", "convertio.me", "cloudconvert.com",
    "smallpdf", "freeconvert.com", "pdfaid.com", "ezgif.com",
    "allinpdf.com", "pdf24.org", "pdfguru.com", "thebestpdf.com",
    "onlinedoctranslator.com", "tinypng.com", "tinyjpg.com", "imagetostl.com",
    "runconvert.com", "transloadit.com", "pdfhouse.com",
]

DLP_MESSENGER_DEST_KW = [
    "slack.com", "slack-edge.com", "chat.google.com", "talk.naver.com",
    "channel.io", "intercomcdn.com", "intercomcdn.eu", "zendesk.com",
    "instagram.com", "whatsapp", "skype.com", "chat.linkareer.com",
]

DLP_CLOUD_DEST_KW = [
    "dropbox", "onedrive", "sharepoint", "box.com", "notion", "confluence",
    "wetransfer", "mega", "icloud", "pcloud", "cloudflarestorage.com",
    "blob.core.windows.net", "storage.googleapis.com", "firebasestorage.googleapis.com",
    "s3.amazonaws.com", "amazonaws-s3", "s3-accelerate.amazonaws.com",
    "sandollcloud.com", "mybox.naver.com", "ncloud.com", "hancomdocs.com",
    "graph.microsoft.com", "officeapps.live.com", "teams.microsoft.com",
    "my.microsoftpersonalcontent.com", "objects-origin.githubusercontent.com",
    "supabase.co", "cloudfront.net", "aliyuncs.com", "ktcloud.com",
]

DLP_DESIGN_DEST_KW = [
    "figma.com", "canva.com", "miro.com", "lucid.app", "adobe.io",
    "shutterstock.com", "sandollcloud.com", "bizhows.com", "mangoboard",
    "freepik", "photoroom", "picsart", "krea.ai", "topazlabs",
]

DLP_SOCIAL_DEST_KW = [
    "upload.youtube.com", "upload.x.com", "tiktokcdn", "facebook.com",
    "threads.com", "pinterest.com", "x.com", "instagram.com",
    "upload.facebook.com", "vupload-edge.facebook.com", "u.pinimg.com",
]

DLP_COMMERCE_DEST_KW = [
    "seller", "vendorcentral.amazon", "sellercentral.amazon", "partner.",
    "partners.", "lotteon", "cjonstyle", "temu.com", "wconcept",
    "wadiz", "coupang", "navercorp.com", "shopee", "alibaba",
    "made-in-china", "baemin", "coupangeats", "29cm", "giftishow",
    "shopping.naver.com", "ssg", "kurly", "welstorymall", "kcp.co.kr",
]

DLP_HR_DEST_KW = [
    "saramin.co.kr", "greetinghr.com", "recruiter.co.kr", "recruit.",
    "ninehire", "albamon.com", "jobkorea.co.kr", "mokahr.com",
    "incruit.com", "jobda.im", "careernote.io", "specter.co.kr",
    "sterlingdirect.com", "ashbyhq",
]

DLP_MARKETING_DEST_KW = [
    "gfa.naver.com", "ad-creative.gfa.naver.com", "ads.naver.com",
    "doubleclick.net", "groobee.io", "dable.io", "stackadapt.com",
    "tiktok.com", "onaudience.com", "ipredictive.com", "mediamixer.co.kr",
    "adpnut.com", "adnmore.co.kr", "mtgroup.kr", "doyouad.com",
    "sauceflex.com", "quantummetric.com", "dataflare.net",
]

DLP_BUSINESS_DEST_KW = [
    "opensurvey.io", "bsgglobal.net", "licensingworkspace.com", "hancomdocs.com",
    "bizhows.com", "pokemonkorea.co.kr", "fss.or.kr", "energy.or.kr",
    "rnd.or.kr", "worldjob.or.kr", "axa.co.kr", "meritzfire.com",
    "samsungfire.com", "kbinsure.co.kr", "easypay.co.kr", "ezwel.com",
    "pay.naver.com", "payoneer.com", "typeform", "atlassian.net",
    "notability.com", "githubusercontent.com", "captcha.com", "google.com",
]


class ReportPerfTimer:
 def __init__(self,name): self.name=name; self.started=time.perf_counter()
 def mark(self,label): log.info("[REPORT PERF] %s %s %.3fs",self.name,label,time.perf_counter()-self.started)
 def finish(self): log.info("[REPORT PERF] %s total %.3fs",self.name,time.perf_counter()-self.started)

# These five loader hooks are installed by ReportService before rendering.
def load_endpoint_detections_by_range(start,end): raise RuntimeError("report loader is not configured")
def load_xdr_email_detections_by_range(start,end): raise RuntimeError("report loader is not configured")
def load_emails_by_range(start,end): raise RuntimeError("report loader is not configured")
def load_mailscreen_by_range(start,end): raise RuntimeError("report loader is not configured")
def load_dlp_by_range(start,end): raise RuntimeError("report loader is not configured")

def _collapse_report_hostname(hostname: str) -> str:
    host = str(hostname or "").strip().lower().strip(".")
    if not host:
        return ""

    if host == "local-file-path":
        return "로컬 경로"

    if host.startswith("www."):
        host = host[4:]

    if re.fullmatch(r"api\d+(?:-cf)?\.ilovepdf\.com", host) or host.endswith(".ilovepdf.com"):
        return "ilovepdf.com"
    if re.fullmatch(r"api\d+\.iloveimg\.com", host) or host.endswith(".iloveimg.com"):
        return "iloveimg.com"
    if re.fullmatch(r"s\d+[-a-z]*\.convertio\.me", host) or host.endswith(".convertio.me"):
        return "convertio.me"
    if host.endswith(".freeconvert.com"):
        return "freeconvert.com"
    if host.endswith(".cloudconvert.com"):
        return "cloudconvert.com"
    if host.endswith(".transloadit.com"):
        return "transloadit.com"
    if host.startswith("filetools") and host.endswith(".pdf24.org"):
        return "pdf24.org"
    if host.endswith(".oaiusercontent.com"):
        return "oaiusercontent.com"
    if host.endswith(".claudeusercontent.com"):
        return "claudeusercontent.com"
    if host.endswith(".cloudflarestorage.com"):
        return "cloudflarestorage.com"
    if host.endswith(".blob.core.windows.net"):
        return "blob.core.windows.net"
    if host.endswith(".sharepoint.com"):
        return "sharepoint.com"
    if host.endswith(".storage.googleapis.com") or host == "storage.googleapis.com":
        return "storage.googleapis.com"
    if (
        host == "s3.amazonaws.com"
        or host.startswith("s3.") and host.endswith("amazonaws.com")
        or host.startswith("s3-") and host.endswith("amazonaws.com")
        or ".s3" in host and host.endswith("amazonaws.com")
    ):
        return "amazonaws-s3"
    if host.endswith(".mail.naver.com"):
        return "mail.naver.com"
    if host.endswith(".tiktokcdn.com") or "tiktokcdn" in host:
        return "tiktokcdn.com"

    return host

def _extract_report_hostname(value: str):
    s = _strip_dlp_origin_suffix(value).strip().strip('"\'')
    if not s:
        return ""

    if s.startswith("\\"):
        parts = [p for p in s.split("\\") if p]
        return parts[0].lower() if parts else "internal-file-server"

    if s.startswith("/") or re.match(r"^[a-z]:[\\/]", s, flags=re.IGNORECASE):
        return "local-file-path"

    if " " in s:
        s = s.split()[0]

    s = s.rstrip(".,;)")

    try:
        from urllib.parse import urlparse

        parsed = urlparse(s if "://" in s else f"//{s}")
        if parsed.hostname:
            return parsed.hostname.lower().strip("[]")
    except Exception:
        pass

    if "/" in s:
        s = s.split("/", 1)[0]
    if "@" in s:
        s = s.rsplit("@", 1)[-1]
    if ":" in s and s.count(":") == 1:
        s = s.split(":", 1)[0]

    return s.lower().strip("[]")

def _strip_dlp_origin_suffix(value: str) -> str:
    return re.sub(r"\s*\(\s*origin\s*:\s*[^)]*\)\s*$", "", str(value or ""), flags=re.IGNORECASE).strip()

def classify_dlp_destination(target_name="", target_type="", dest_detail=""):
    target = str(target_name or "").strip().lower()
    ttype = str(target_type or "").strip().lower()
    raw_detail = str(dest_detail or "").strip().lower()
    normalized_detail = normalize_report_destination(dest_detail)
    normalized_l = str(normalized_detail or "").lower()
    haystack = " ".join([target, ttype, raw_detail, normalized_l])

    if normalized_detail == "내부 파일서버" or raw_detail.startswith("\\"):
        return "내부 파일서버"
    if normalized_detail == "로컬 경로" or raw_detail.startswith("/"):
        return "로컬/앱 임시파일"
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", normalized_l):
        return "IP 직접 접속"

    if any(k in haystack for k in DLP_AI_DEST_KW):
        return "AI/생성형AI"
    if any(k in haystack for k in DLP_CONVERTER_DEST_KW):
        return "문서/PDF/이미지 변환"
    if ttype == "e-mail" or "mail" in normalized_l or ".mail." in raw_detail:
        return "메일/대용량 첨부"
    if target in {"kakaotalk", "nateon messenger", "naver line", "wechat", "viber", "messages", "whatsapp.root.dll"}:
        return "메신저/고객상담"
    if any(k in haystack for k in DLP_MESSENGER_DEST_KW):
        return "메신저/고객상담"
    if any(k in haystack for k in DLP_SOCIAL_DEST_KW):
        return "소셜/미디어 업로드"
    if any(k in haystack for k in DLP_DESIGN_DEST_KW):
        return "디자인/협업 SaaS"
    if ttype == "cloud services / file sharing" or target in {"airdrop outgoing", "filezilla", "google drive file stream"}:
        return "클라우드/오브젝트 스토리지"
    if any(k in haystack for k in DLP_CLOUD_DEST_KW):
        return "클라우드/오브젝트 스토리지"
    if any(k in haystack for k in DLP_HR_DEST_KW):
        return "채용/HR"
    if any(k in haystack for k in DLP_MARKETING_DEST_KW):
        return "광고/마케팅/분석"
    if any(k in haystack for k in DLP_COMMERCE_DEST_KW):
        return "쇼핑몰/판매자/파트너 포털"
    if any(k in haystack for k in DLP_BUSINESS_DEST_KW):
        return "업무/공공/금융 포털"

    return "웹 브라우저/기타"

def enrich_mailscreen_sender_fields(row):
    if not isinstance(row, dict):
        return row

    enriched = dict(row)
    identity = resolve_mailscreen_sender_identity(enriched)
    sender_email = mailscreen_identity_text(identity.get("email"))
    sender_name = mailscreen_identity_text(identity.get("user_name"))
    sender_dept = mailscreen_identity_text(identity.get("dept_name"))

    if not sender_email:
        sender_email = mailscreen_extract_email(enriched.get("sender"), enriched.get("sender_detail"))
    if not sender_name or sender_name == "None":
        raw_sender = mailscreen_identity_text(enriched.get("sender"))
        sender_name = "" if "@" in raw_sender else raw_sender
    if not sender_dept or sender_dept == "None":
        sender_dept = mailscreen_identity_text(enriched.get("dept"))

    enriched["sender_email"] = sender_email or "None"
    enriched["sender_name"] = sender_name or "None"
    enriched["sender_user_id"] = identity.get("user_id", "None") or "None"
    enriched["sender_dept"] = sender_dept or "None"
    enriched["sender"] = enriched["sender_email"] if enriched["sender_email"] != "None" else mailscreen_identity_text(enriched.get("sender")) or "None"
    enriched["dept"] = enriched["sender_dept"]
    return enriched

def extract_xdr_email_fields(d):
    rule = "None"
    dd = d.get("detectionDescription", {})
    if isinstance(dd, dict):
        rule = dd.get("createdReasonId", "None") or "None"
    if rule == "None":
        rule = d.get("detectionRule", "None") or "None"

    raw_data = d.get("rawData", {})
    if not isinstance(raw_data, dict):
        raw_data = {}

    raw = safe_json_loads(raw_data.get("raw"), {})
    if not isinstance(raw, dict):
        raw = {}

    from_addr = raw.get("mailFrom") or raw.get("from") or "None"

    mailbox = "None"
    if raw.get("mailboxAddress"):
        mailbox = raw.get("mailboxAddress")
    elif raw.get("envelopeRecipients"):
        mailbox = join_or_none(raw.get("envelopeRecipients"))

    to_value = "None"
    if raw.get("to"):
        to_value = join_or_none(raw.get("to"))
    elif raw.get("mailboxAddress"):
        to_value = raw.get("mailboxAddress")
    elif raw.get("envelopeRecipients"):
        to_value = join_or_none(raw.get("envelopeRecipients"))

    subject = raw.get("subject") or "None"
    sender_ip = raw.get("clientIp") or "None"

    ioc = "None"
    ioc_sha = "None"
    detail = "None"

    if rule == "XDR-sophos-email-maliciousurl":
        url_data = raw.get("highRiskUrlData", {})
        urls = url_data.get("urls", []) if isinstance(url_data, dict) else []
        if urls and isinstance(urls[0], dict):
            ioc = urls[0].get("url") or "None"
            detail = urls[0].get("urlCategory") or "None"

    elif rule == "XDR-sophos-email-virus":
        attachments = raw.get("attachments", [])
        if attachments and isinstance(attachments[0], dict):
            att = attachments[0]
            ioc = att.get("name") or "None"
            ioc_sha = att.get("checksum") or "None"
            detail = att.get("intelixThreatVerdict") or "None"

    elif rule == "XDR-sophos-email-impersonation":
        impersonation = raw.get("impersonationData", {})
        if isinstance(impersonation, dict):
            ioc = impersonation.get("categoryDetails") or "None"
            category = impersonation.get("category") or "None"
            is_imp = impersonation.get("isImpersonation")
            if is_imp is None:
                detail = category
            else:
                detail = f"{category} / isImpersonation={is_imp}"

    return {
        "time": kst_time(d.get("time")),
        "rule": rule,
        "mailbox": str(mailbox),
        "from": str(from_addr),
        "to": str(to_value),
        "subject": str(subject),
        "sender_ip": str(sender_ip),
        "ioc": str(ioc),
        "ioc_sha": str(ioc_sha),
        "detail": str(detail),
        "raw": d,
    }

def get_dept_by_hostname(hostname: str):
    key = normalize_name_key(hostname)
    if not key:
        return "미분류", ""

    info = HOSTNAME_DEPT_MAP.get(key, {})
    return (
        str(info.get("dept_name", "미분류") or "미분류"),
        str(info.get("dept_code", "") or ""),
    )

def get_directory_user_info(*values):
    for value in values:
        key = normalize_name_key(value)
        if not key:
            continue
        info = DIRECTORY_USER_INDEX.get(key)
        if info:
            return info
    return {}

def get_display_file_and_sha(raw):
    if not isinstance(raw, dict):
        return "None", "None"

    # 1) ioc_event_files 우선
    files = raw.get("ioc_event_files", [])
    f0 = files[0] if isinstance(files, list) and files and isinstance(files[0], dict) else {}

    file_name = f0.get("file_name")
    file_sha = f0.get("sha256")

    if file_name:
        return file_name, (file_sha or "None")

    # 2) 일반 프로세스/파일명 fallback
    display_name = (
        raw.get("process_name")
        or raw.get("meta_process_name")
        or raw.get("target_process_name")
        or raw.get("name")
        or raw.get("file_name")
        or raw.get("original_filename")
        or "None"
    )

    display_sha = (
        raw.get("process_sha256")
        or raw.get("meta_sha256")
        or raw.get("target_process_sha256")
        or raw.get("sha256")
        or "None"
    )

    return display_name, display_sha

def get_endpoint_user_by_machine_name(machine_name):
    target = normalize_name_key(machine_name)
    if not target:
        return "", "", ""

    for e in ENDPOINTS:
        if not isinstance(e, dict):
            continue

        hostname = str(e.get("hostname", "") or "").strip()
        if normalize_name_key(hostname) != target:
            continue

        person = e.get("associatedPerson", {})
        if not isinstance(person, dict):
            person = {}

        raw_name = str(person.get("name", "") or "").strip()
        via_login = str(person.get("viaLogin", "") or "").strip()
        user_id = via_login.split("\\")[-1] if "\\" in via_login else via_login

        user_name = normalize_org_match_name(raw_name)

        # Asset-xxxx 형태는 공용PC로 처리
        if is_shared_pc_name(user_name) or is_shared_pc_name(hostname):
            return "공용PC", user_id, "shared_pc"

        return user_name, user_id, "normal"

    return "", "", "not_found"

def get_org_info_by_user(user_name, user_id="", hostname=""):
    user_name_key = normalize_name_key(user_name)
    user_id_key = normalize_name_key(user_id)

    dept_name = "미분류"
    dept_code = ""

    for org in ORGS:
        if not isinstance(org, dict):
            continue

        org_dept_code = str(org.get("deptCode", "") or "").strip()
        raw_dept_name = str(org.get("deptName", "") or "").strip()
        org_dept_name = DEPT_MAP.get(org_dept_code, raw_dept_name) or "미분류"

        users = org.get("users", [])
        if not isinstance(users, list):
            continue

        matched = False
        for u in users:
            if isinstance(u, dict):
                org_user_name = str(u.get("name", "") or "").strip()
                org_user_id = str(u.get("id", "") or u.get("userId", "") or "").strip()
            else:
                org_user_name = str(u or "").strip()
                org_user_id = ""

            if user_name_key and normalize_name_key(org_user_name) == user_name_key:
                matched = True
                break

            if user_id_key and org_user_id and normalize_name_key(org_user_id) == user_id_key:
                matched = True
                break

        if matched:
            dept_name = org_dept_name
            dept_code = org_dept_code
            break

    if dept_name == "미분류" and user_id:
        directory_info = get_directory_user_info(user_id)
        if directory_info:
            dept_name = str(directory_info.get("dept_name", "미분류") or "미분류")
            dept_code = str(directory_info.get("dept_code", "") or "")

    # Report_exception_List 는 일반 분류가 끝난 뒤 마지막에 덮어쓴다.
    exc_dept = get_report_exception_dept(user_name, user_id, hostname)
    if exc_dept:
        return exc_dept, ""

    return dept_name, dept_code

def get_org_user_name_by_user_id(user_id: str):
    user_id_key = normalize_name_key(user_id)
    if not user_id_key:
        return ""

    for org in ORGS:
        if not isinstance(org, dict):
            continue

        users = org.get("users", [])
        if not isinstance(users, list):
            continue

        for u in users:
            if not isinstance(u, dict):
                continue

            org_user_id = str(u.get("id", "") or u.get("userId", "") or "").strip()
            if org_user_id and normalize_name_key(org_user_id) == user_id_key:
                return str(u.get("name", "") or "").strip()

    return ""

def get_report_exception_dept(*values):
    for value in values:
        key = normalize_name_key(value)
        if not key:
            continue

        dept = str(REPORT_EXCEPTION_MAP.get(key, "") or "").strip()
        if dept:
            return dept

    return ""

def get_unique_path(path):
    if not os.path.exists(path):
        return path

    base, ext = os.path.splitext(path)
    idx = 1

    while True:
        new_path = f"{base}_({idx}){ext}"
        if not os.path.exists(new_path):
            return new_path
        idx += 1

def is_shared_pc_name(value):
    s = str(value or "").strip()
    return bool(re.match(r"(?i)^asset-\d+$", s))

def join_or_none(values):
    if not values:
        return "None"
    if isinstance(values, list):
        return ", ".join([str(x) for x in values if str(x).strip()]) or "None"
    return str(values) if str(values).strip() else "None"

def kst_time(iso):
    if not iso:
        return "None"
    try:
        dt = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
        return dt.astimezone(timezone(timedelta(hours=9))).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(iso)

def mailscreen_extract_email(*values):
    for value in values:
        text = mailscreen_identity_text(value)
        if not text:
            continue
        m = MAILSCREEN_EMAIL_RE.search(text)
        if m:
            return m.group(0).strip()
    return ""

def mailscreen_identity_text(value):
    text = html.unescape(str(value or "")).strip()
    text = re.sub(r"\s+", " ", text)
    return "" if text.lower() in MAILSCREEN_BLANK_VALUES else text

def normalize_name_key(value):
    return re.sub(r"\s+", "", str(value or "")).strip().lower()

def normalize_org_match_name(value):
    s = str(value or "").strip()

    if "\\" in s:
        left, right = s.split("\\", 1)
        if right.strip().lower() in {"locknlock", "lnl", "local"}:
            s = left.strip()
        else:
            s = right.strip()

    s = re.sub(r"(?i)_mac$", "", s).strip()
    return s

def normalize_report_destination(value):
    s = str(value or "").strip()
    if not s or s.lower() == "none":
        return "None"

    if s.startswith("\\"):
        return "내부 파일서버"
    if s.startswith("/") or re.match(r"^[a-z]:[\\/]", s, flags=re.IGNORECASE):
        return "로컬 경로"

    hostname = _extract_report_hostname(s)
    collapsed = _collapse_report_hostname(hostname)
    return collapsed or s.lower()

def resolve_identity_by_hostname(hostname: str):
    host = str(hostname or "").strip()
    if not host:
        return {
            "hostname": "None",
            "user_name": "None",
            "user_id": "",
            "dept_name": "미분류",
            "dept_code": "",
        }

    user_name, user_id, _ = get_endpoint_user_by_machine_name(host)

    if not user_name:
        user_name = "None"

    dept_name, dept_code = get_dept_by_hostname(host)

    return {
        "hostname": host,
        "user_name": str(user_name or "None"),
        "user_id": str(user_id or ""),
        "dept_name": str(dept_name or "미분류"),
        "dept_code": str(dept_code or ""),
    }

def resolve_identity_by_mailbox(mailbox_addr: str):
    mailbox_addr = str(mailbox_addr or "").strip()
    mailbox_lower = mailbox_addr.lower()

    if not mailbox_lower or "@" not in mailbox_lower:
        return {
            "mailbox": mailbox_addr or "None",
            "mailbox_user": "",
            "hostname": "None",
            "user_id": "None",
            "user_name": "None",
            "dept_name": "미분류",
            "dept_code": "",
        }

    mailbox_user = mailbox_lower.split("@", 1)[0].strip()

    matched_hostname = "None"
    matched_user_id = "None"
    matched_user_name = "None"

    for ep in ENDPOINTS:
        if not isinstance(ep, dict):
            continue

        ap = ep.get("associatedPerson") or {}
        via_login = str(ap.get("viaLogin") or "").strip()
        if not via_login:
            continue

        login_user = via_login.split("\\")[-1].strip().lower()
        if not login_user:
            continue

        if login_user == mailbox_user:
            matched_hostname = str(ep.get("hostname") or "None")
            matched_user_id = via_login.split("\\")[-1].strip() or "None"
            matched_user_name = str(ap.get("name") or "None")
            break

    dept_name = "미분류"
    dept_code = ""

    if matched_hostname != "None":
        dept_name, dept_code = get_dept_by_hostname(matched_hostname)
    elif mailbox_user:
        # Endpoint 매칭이 안 되면 mailbox local-part를 User ID로 보고 User API 맵을 먼저 시도한다.
        matched_user_id = mailbox_user
        directory_info = get_directory_user_info(mailbox_addr, mailbox_user)
        if directory_info:
            matched_user_name = str(directory_info.get("name", "") or "None")
            matched_user_id = str(directory_info.get("user_id", "") or mailbox_user)
            dept_name = str(directory_info.get("dept_name", "미분류") or "미분류")
            dept_code = str(directory_info.get("dept_code", "") or "")
        else:
            org_user_name = get_org_user_name_by_user_id(mailbox_user)
            if org_user_name:
                matched_user_name = org_user_name
            dept_name, dept_code = get_org_info_by_user(org_user_name, mailbox_user, mailbox_user)

    # Report_exception_List 는 Endpoint/User API/조직도 분류가 끝난 뒤 마지막에 덮어쓴다.
    exc_dept = get_report_exception_dept(matched_user_name, matched_user_id, mailbox_user, mailbox_addr)
    if exc_dept:
        dept_name = exc_dept
        dept_code = ""

    return {
        "mailbox": mailbox_addr or "None",
        "mailbox_user": mailbox_user,
        "hostname": matched_hostname,
        "user_id": matched_user_id,
        "user_name": matched_user_name,
        "dept_name": dept_name or "미분류",
        "dept_code": dept_code or "",
    }

def resolve_mailscreen_sender_identity(row):
    if not isinstance(row, dict):
        return {
            "email": "",
            "user_id": "None",
            "user_name": "None",
            "dept_name": "미분류",
            "dept_code": "",
        }

    sender = mailscreen_identity_text(row.get("sender"))
    sender_detail = mailscreen_identity_text(row.get("sender_detail"))
    dept = mailscreen_identity_text(row.get("dept"))
    email_addr_text = mailscreen_extract_email(sender, sender_detail)
    local_user_id = email_addr_text.split("@", 1)[0].strip() if email_addr_text else ""
    display_sender = "" if "@" in sender else sender

    identity = {}
    if email_addr_text:
        identity = resolve_identity_by_mailbox(email_addr_text)

    directory_info = get_directory_user_info(email_addr_text, local_user_id, display_sender)
    if not email_addr_text and directory_info:
        email_addr_text = str(directory_info.get("email", "") or "").strip()
        local_user_id = str(directory_info.get("user_id", "") or "").strip()

    user_id = str(identity.get("user_id", "") or "").strip()
    if user_id in {"", "None"}:
        user_id = str(directory_info.get("user_id", "") or "").strip() or local_user_id
    if not user_id:
        user_id = "None"

    user_name = str(identity.get("user_name", "") or "").strip()
    if user_name in {"", "None"}:
        user_name = str(directory_info.get("name", "") or "").strip() or display_sender
    if not user_name and sender and "@" in sender:
        user_name = local_user_id
    if not user_name:
        user_name = "None"

    dept_name = dept
    dept_code = ""
    if not dept_name:
        dept_name = str(identity.get("dept_name", "") or "").strip()
        dept_code = str(identity.get("dept_code", "") or "").strip()
    if (not dept_name or dept_name == "미분류") and directory_info:
        dept_name = str(directory_info.get("dept_name", "") or "").strip() or dept_name
        dept_code = str(directory_info.get("dept_code", "") or "").strip() or dept_code
    if (not dept_name or dept_name == "미분류") and (display_sender or local_user_id):
        org_dept, org_code = get_org_info_by_user(display_sender or user_name, local_user_id)
        dept_name = org_dept or dept_name
        dept_code = org_code or dept_code
    if not dept_name:
        dept_name = "미분류"

    return {
        "email": email_addr_text,
        "user_id": user_id,
        "user_name": user_name,
        "dept_name": dept_name,
        "dept_code": dept_code,
    }

def safe_json_loads(value, default=None):
    if default is None:
        default = {}

    if isinstance(value, dict):
        return value

    if not value:
        return default

    try:
        return json.loads(value)
    except Exception:
        return default

def shorten_path_text(text, max_len=46):
    s = str(text or "").strip()
    if not s:
        return "-"

    s = s.replace("\\", "/")
    parts = [p for p in s.split("/") if p]

    if not parts:
        return "-"

    filename = parts[-1]
    parent = parts[-2] if len(parts) >= 2 else ""

    # 1차: .../folder/file.ext
    if parent:
        candidate = f".../{parent}/{filename}"
        if len(candidate) <= max_len:
            return candidate

    # 2차: .../file.ext
    candidate = f".../{filename}"
    if len(candidate) <= max_len:
        return candidate

    # 3차: 파일명 자체를 최대한 살리되, 확장자는 유지
    name, ext = os.path.splitext(filename)

    if ext:
        remain = max_len - len(".../") - len(ext)
        if remain > 1:
            return f".../{name[:remain]}{ext}"

    remain = max_len - len(".../")
    if remain > 1:
        return f".../{filename[:remain]}"

    return f".../{filename}"

def timeline_parse_dt(value):
    value = str(value or "").strip()
    if not value or value == "None":
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(value[:19], fmt)
        except Exception:
            pass
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone(timedelta(hours=9))).replace(tzinfo=None)
    except Exception:
        return None


class LegacySecurityReport:

    def setup_report_font(self):
        try:
            from reportlab.pdfbase import pdfmetrics
            from reportlab.pdfbase.ttfonts import TTFont

            candidates = [
                os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "Fonts", "malgun.ttf"),
                os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "Fonts", "malgunbd.ttf"),
            ]

            regular_path = None

            for path in candidates:
                if os.path.exists(path) and path.lower().endswith("malgun.ttf"):
                    regular_path = path
                    break

            if regular_path:
                try:
                    pdfmetrics.registerFont(TTFont("ReportFont", regular_path))
                    return "ReportFont"
                except Exception:
                    pass

        except Exception:
            pass

        return "Helvetica"

    def is_dlp_blocked_row(self, row):
        if not isinstance(row, dict):
            return False

        event_name = str(row.get("event_id", "")).strip()
        return "차단" in event_name

    def build_report_identity_resolver(self):
        identity_cache = {}

        def resolve(machine_name):
            key = str(machine_name or "").strip()
            cache_key = normalize_name_key(key)
            if cache_key in identity_cache:
                return identity_cache[cache_key]

            endpoint_user_name, endpoint_user_id, user_type = get_endpoint_user_by_machine_name(key)

            if user_type == "shared_pc":
                result = {
                    "user_name": endpoint_user_name,
                    "user_id": endpoint_user_id,
                    "user_type": user_type,
                    "dept_name": "공용PC",
                    "dept_code": "",
                    "is_unclassified": False,
                    "display_name": endpoint_user_name or key,
                }
            else:
                dept_name, dept_code = get_org_info_by_user(endpoint_user_name, endpoint_user_id, key)
                is_unclassified = False
                display_name = str(endpoint_user_name or "").strip()

                if not dept_name or dept_name == "미분류":
                    manual_dept = get_report_exception_dept(endpoint_user_name)
                    if not manual_dept:
                        manual_dept = get_report_exception_dept(key)
                    if manual_dept:
                        dept_name = manual_dept
                        dept_code = ""
                    else:
                        dept_name = "미분류"
                        if not display_name:
                            display_name = f"[NO_USER] {key}"
                        is_unclassified = True

                result = {
                    "user_name": endpoint_user_name,
                    "user_id": endpoint_user_id,
                    "user_type": user_type,
                    "dept_name": dept_name or "미분류",
                    "dept_code": dept_code or "",
                    "is_unclassified": is_unclassified,
                    "display_name": display_name,
                }

            identity_cache[cache_key] = result
            return result

        return resolve

    def build_dlp_overall_insight_lines(self, dlp_rows):
        if not dlp_rows:
            return ["DLP 이벤트가 확인되지 않았습니다."]

        AI_KW = [
            "openai", "chatgpt", "claude", "gemini", "copilot",
            "oaiusercontent", "bard", "perplexity",
            "ppl-ai-file-upload.s3.amazonaws.com",
            "clients6.google.com/upload",
            "aicreation.s3.ap-northeast-2.amazonaws.com"
        ]

        CLOUD_KW = [
            "drive", "dropbox", "onedrive", "sharepoint",
            "box.com", "notion", "confluence", "wetransfer",
            "mega", "icloud", "pcloud", "cloudflarestorage.com",
            "archisketch-resources.s3.ap-northeast-2.amazonaws.com",
            "sandollcloud.com"
        ]

        MESSENGER_TARGETS = {
            "kakaotalk",
            "nateon messenger",
            "naver line",
            "wechat",
            "viber",
            "messages",
            "whatsapp.root.dll",
        }

        MESSENGER_DEST_KW = [
            "files.slack.com",
            "app.slack.com",
            "www.instagram.com",
            "talk.naver.com",
            "media.channel.io",
            "chat.google.com",
        ]

        SENSITIVE_DOC_KW = [
            "신분증", "여권", "명함", "사업자", "사업자등록증",
            "통장사본", "계좌", "세금계산서", "임신확인서",
            "학자금", "잔액현황", "입금내역", "계약서"
        ]

        EXPENSE_KW = [
            "영수증", "거래확인증", "통행", "통행료", "주차", "주차료",
            "택배", "택시", "교통비", "식대", "회식", "접대비",
            "우편", "출장", "숙박", "환전", "주유", "로밍"
        ]

        AI_FILE_KW = [
            "chatgpt image", "gemini_generated_image", "claude", "/11_ai/"
        ]

        DESIGN_KW = [
            "배너", "banner", "thumb", "썸네일", "상세페이지", "누끼",
            "랜더링", "연출", "고화질", "promotion", "메인", "예고페이지",
            "스토리", "instagram", "인스타", "제품자료", "제품디자인",
            "시안", "팝업", "광고", "행사", "프로모션"
        ]

        MESSENGER_FILE_KW = [
            "kakaotalk_", "카카오톡 받은 파일", "네이트온 받은 파일",
            "viberdownloads", "xwechat_files", "whatsapp image",
            "messages/attachments", "wechat", "viber"
        ]

        VIDEO_EXT = {".mp4", ".mov", ".m4a", ".avi"}

        def norm(v):
            return str(v or "").strip()

        def low(v):
            return norm(v).lower()

        def kw_match(text, kw_list):
            t = low(text)
            return any(k in t for k in kw_list)

        def get_source_name(row):
            return (
                row.get("source")
                or row.get("source_name")
                or row.get("fileName")
                or row.get("filename")
                or ""
            )

        def extract_file_ext_for_report(path_text):
            s = str(path_text or "").strip().lower()

            if not s or s == "none":
                return ""

            # URL 파라미터/앵커 제거
            s = s.split("?", 1)[0]
            s = s.split("#", 1)[0]

            # 윈도우/리눅스 경로 구분자 통일
            s = s.replace("\\", "/")

            # 마지막 파일명만 추출
            filename = s.rsplit("/", 1)[-1].strip()

            if not filename or "." not in filename:
                return ""

            # 마지막 . 오른쪽만 확장자로 사용
            ext = filename.rsplit(".", 1)[-1].strip()

            # 확장자에 섞인 공백, 괄호, 제어문자 등 제거
            ext = re.sub(r"[^a-z0-9]+", "", ext)

            if not ext:
                return ""

            return f".{ext}"

        def get_target_name(row):
            return row.get("target") or row.get("destination") or ""

        def get_target_type(row):
            return row.get("targetType") or row.get("target_type") or row.get("destination_type") or ""

        def get_dest_detail(row):
            return (
                row.get("destinationDetails")
                or row.get("destination_details")
                or row.get("item_details")
                or ""
            )

        def classify_row(row):
            return classify_dlp_destination(
                get_target_name(row),
                get_target_type(row),
                get_dest_detail(row),
            )

        def classify_filename_detail(path_text):
            s = low(path_text)
            base = os.path.basename(norm(path_text))
            base_l = base.lower()
            ext = os.path.splitext(base_l)[1]

            # 우선순위 중요
            if any(k in s for k in SENSITIVE_DOC_KW):
                return "민감 개인 증빙 / 신분 관련"

            if any(k in s for k in EXPENSE_KW):
                return "영수증 / 정산 / 비용 증빙"

            if any(k in s for k in AI_FILE_KW):
                return "AI 생성 / AI 작업 결과물"

            if ext in VIDEO_EXT:
                return "영상 / 녹음 파일"

            if any(k in s for k in DESIGN_KW):
                return "상품 이미지 / 디자인 시안"

            if any(k in s for k in MESSENGER_FILE_KW):
                return "메신저 수신 이미지 / 외부 공유본"

            return "기타 이미지 / 파일"

        bucket_rows = defaultdict(list)
        for row in dlp_rows:
            if not isinstance(row, dict):
                continue
            category = classify_row(row)
            bucket_rows[category].append(row)

        ranked = sorted(
            bucket_rows.items(),
            key=lambda x: len(x[1]),
            reverse=True
        )[:3]

        lines = []
        total_count = len(dlp_rows)

        for idx, (category, rows) in enumerate(ranked, 1):
            cnt = len(rows)

            detail_counter = Counter()
            dest_counter = Counter()
            ext_counter = Counter()

            for row in rows:
                src = norm(get_source_name(row))
                dest_detail = normalize_report_destination(get_dest_detail(row))
                ext = extract_file_ext_for_report(src)

                detail_label = classify_filename_detail(src)
                detail_counter[detail_label] += 1

                if dest_detail and dest_detail != "None":
                    dest_counter[dest_detail] += 1

                if ext:
                    ext_counter[ext] += 1

            block_lines = []
            block_lines.append(f"{category} (약 {cnt:,}건 / 전체 {round(cnt / total_count * 100, 1)}%)")

            top_details = detail_counter.most_common(3)
            if top_details:
                for label, sub_cnt in top_details:
                    block_lines.append(f"- {label} ({sub_cnt}건)")

            top_dests = dest_counter.most_common(2)
            if top_dests:
                dest_text = " / ".join([f"{name} ({d_cnt}건)" for name, d_cnt in top_dests])
                block_lines.append(f"- 주요 목적지: {dest_text}")

            top_exts = ext_counter.most_common(3)
            if top_exts:
                ext_text = " / ".join([f"{ext} ({e_cnt}건)" for ext, e_cnt in top_exts])
                block_lines.append(f"- 주요 확장자: {ext_text}")

            lines.append(block_lines)

        return lines

    def build_dlp_dept_insight_lines(self, dlp_dept_rank, metrics):
        if not dlp_dept_rank:
            return ["DLP 이벤트가 확인되지 않았습니다."]

        total_events = sum(d.get("total", 0) for d in dlp_dept_rank)
        lines = []

        AI_KW = [
            "openai", "chatgpt", "claude", "gemini", "copilot",
            "oaiusercontent", "bard", "perplexity",
            "ppl-ai-file-upload.s3.amazonaws.com",
            "clients6.google.com/upload",
            "aicreation.s3.ap-northeast-2.amazonaws.com"
        ]

        CLOUD_KW = [
            "drive", "dropbox", "onedrive", "sharepoint",
            "box.com", "notion", "confluence", "wetransfer",
            "mega", "icloud", "pcloud", "cloudflarestorage.com",
            "archisketch-resources.s3.ap-northeast-2.amazonaws.com",
            "sandollcloud.com"
        ]

        MESSENGER_TARGETS = {
            "kakaotalk",
            "nateon messenger",
            "naver line",
            "wechat",
            "viber",
            "messages",
            "whatsapp.root.dll",
        }

        MESSENGER_DEST_KW = [
            "files.slack.com",
            "app.slack.com",
            "www.instagram.com",
            "talk.naver.com",
            "media.channel.io",
        ]

        SENSITIVE_EXT = {
            ".xlsx", ".xls", ".csv", ".pdf", ".dwg",
            ".psd", ".ai", ".doc", ".docx", ".ppt",
            ".pptx", ".zip", ".7z", ".tar", ".sql"
        }

        def kw_match(text, kw_list):
            t = str(text or "").lower()
            return any(k in t for k in kw_list)

        def top_share(cnt, base):
            if not base:
                return 0.0
            return round(cnt / base * 100, 1)

        def normalize_text(value):
            return str(value or "").strip().lower()

        def is_ai(dest_detail):
            return kw_match(dest_detail, AI_KW)

        def is_messenger(target_name, dest_detail):
            t = normalize_text(target_name)
            d = normalize_text(dest_detail)
            return (t in MESSENGER_TARGETS) or kw_match(d, MESSENGER_DEST_KW)

        def is_mail(target_type, dest_detail):
            ttype = normalize_text(target_type)
            d = normalize_text(dest_detail)
            return ttype == "e-mail" or ("mail" in d)

        def is_cloud(target_name, target_type, dest_detail):
            t = normalize_text(target_name)
            ttype = normalize_text(target_type)
            d = normalize_text(dest_detail)

            if ttype == "cloud services / file sharing":
                return True
            if t in {"airdrop outgoing", "filezilla", "google drive file stream"}:
                return True
            if kw_match(d, CLOUD_KW):
                return True
            return False

        for rank, item in enumerate(dlp_dept_rank[:5], 1):
            dept_name = item.get("dept_name", "미분류")
            total = item.get("total", 0)
            blocked = item.get("blocked", 0)
            allowed = item.get("allowed", 0)
            block_ratio = item.get("block_ratio", 0.0)
            user_count = item.get("user_count", 0)
            machine_count = item.get("machine_count", 0)
            top_dests = item.get("top_dest_details", [])
            top_types = item.get("top_target_types", [])
            top_srcs = item.get("top_sources", [])
            top_dest_group_rows = item.get("top_dest_group_rows", [])

            share_pct = round(total / total_events * 100, 1) if total_events else 0.0

            header = (
                f"{rank}. {dept_name} | 총 {total}건 (전체 {share_pct}%) / "
                f"차단 {blocked}건 / 허용 {allowed}건 / 차단율 {block_ratio}%"
            )
            lines.append(header)

            if user_count > 0:
                avg_user = round(total / user_count, 1)
                if avg_user >= 100:
                    lines.append(f"- 사용자 1인당 평균 {avg_user}건 — 소수 사용자 집중 발생 가능성 높음.")
                elif avg_user >= 50:
                    lines.append(f"- 사용자 1인당 평균 {avg_user}건 — 반복 사용자 여부 확인 필요.")
                else:
                    lines.append(f"- 사용자 1인당 평균 {avg_user}건 — 분산 발생 양상.")

            if machine_count > 0:
                avg_pc = round(total / machine_count, 1)
                if avg_pc >= 100:
                    lines.append(f"- PC당 평균 {avg_pc}건 — 특정 단말 집중 여부 점검 필요.")

            if block_ratio >= 90:
                lines.append("- 정책 차단률 90% 이상 — 통제가 효과적으로 작동 중이나 우회 시도 여부 병행 점검 권장.")
            elif block_ratio <= 10 and total >= 100:
                lines.append(f"- 차단율 {block_ratio}%로 낮음 — 정책 미적용 구간이거나 업무 예외 처리가 광범위하게 적용되고 있을 가능성.")

            classified_dests = []
            ai_related = False
            messenger_related = False
            mail_related = False
            cloud_related = False

            for group_row in top_dest_group_rows[:5]:
                target_name = str(group_row.get("target_text", "") or "")
                target_type = str(group_row.get("target_text", "") or "")
                dest_detail = str(group_row.get("dest_detail", "") or "")
                cnt = int(group_row.get("count", 0) or 0)

                category = classify_dlp_destination(target_name, target_type, dest_detail)

                if category == "AI/생성형AI":
                    ai_related = True
                elif category == "메신저/고객상담":
                    messenger_related = True
                elif category == "메일/대용량 첨부":
                    mail_related = True
                elif category == "클라우드/오브젝트 스토리지":
                    cloud_related = True

                if category != "웹 브라우저/기타":
                    classified_dests.append(f"{category}({dest_detail or target_name}) {cnt}건({top_share(cnt, total)}%)")

            if classified_dests:
                lines.append("- 주요 분류: " + " / ".join(classified_dests[:3]) + " — 민감 데이터 포함 여부 확인 필요.")

            type_flags = []
            for t_name, cnt in top_types[:3]:
                t_lower = str(t_name or "").lower()
                if "instant messaging" in t_lower:
                    type_flags.append(f"메신저({t_name}) {cnt}건")
                elif "e-mail" in t_lower:
                    type_flags.append(f"메일({t_name}) {cnt}건")
                elif "cloud services / file sharing" in t_lower:
                    type_flags.append(f"클라우드/파일공유({t_name}) {cnt}건")

            if type_flags:
                lines.append("- 주요 대상유형: " + " / ".join(type_flags))

            sensitive_files = []
            for src, cnt in top_srcs[:5]:
                src_str = str(src or "")
                _, ext = os.path.splitext(src_str.lower())
                if ext in SENSITIVE_EXT:
                    sensitive_files.append(f"{os.path.basename(src_str)} ({cnt}건)")

            if sensitive_files:
                lines.append("- 민감 파일 유형 포함: " + " / ".join(sensitive_files[:3]))

            sensitive_related = len(sensitive_files) > 0

            if ai_related and sensitive_related:
                lines.append("→ AI 서비스 + 민감 파일 조합 → 정보 유출 리스크 상위 점검 대상")
            elif ai_related:
                lines.append("→ AI 서비스 업로드 → 파일 내용 기준 추가 검토 필요")
            elif messenger_related and sensitive_related:
                lines.append("→ 메신저 + 민감 파일 조합 → 외부 전송 파일 추가 점검 필요")
            elif mail_related and sensitive_related:
                lines.append("→ 메일 + 민감 파일 조합 → 송신 파일 적정성 확인 필요")
            elif cloud_related and block_ratio < 30:
                lines.append("→ 클라우드/파일공유 비중 존재 + 낮은 차단율 → 정책 예외 범위 재검토 권장")

        return lines

    def build_dlp_destination_insight_rows(self, dlp_rows, dept_resolver=None):
        if not dlp_rows:
            return []

        def get_target_name(row):
            return row.get("target") or row.get("destination") or ""

        def get_target_type(row):
            return row.get("targetType") or row.get("target_type") or row.get("destination_type") or ""

        def get_dest_detail(row):
            return (
                row.get("destinationDetails")
                or row.get("destination_detail")
                or row.get("destination_details")
                or row.get("destination")
                or row.get("item_details")
                or ""
            )

        def get_source_name(row):
            return str(
                row.get("filename", "")
                or row.get("source", "")
                or row.get("source_name", "")
                or row.get("fileName", "")
                or row.get("item_name", "")
                or "None"
            ).strip()

        dept_cache = {}

        def resolve_dept(machine_name):
            key = str(machine_name or "").strip()
            if key in dept_cache:
                return dept_cache[key]

            if not key:
                dept_cache[key] = "미분류"
                return dept_cache[key]

            if dept_resolver:
                resolved = dept_resolver(key)
                if isinstance(resolved, dict):
                    dept_name = str(resolved.get("dept_name", "미분류") or "미분류")
                else:
                    dept_name = str(resolved or "미분류")
                dept_cache[key] = dept_name
                return dept_cache[key]

            endpoint_user_name, endpoint_user_id, user_type = get_endpoint_user_by_machine_name(key)
            if user_type == "shared_pc":
                dept_name = "공용PC"
            else:
                dept_name, _ = get_org_info_by_user(endpoint_user_name, endpoint_user_id, key)
                if not dept_name or dept_name == "미분류":
                    dept_name = (
                        get_report_exception_dept(endpoint_user_name)
                        or get_report_exception_dept(key)
                        or "미분류"
                    )

            dept_cache[key] = dept_name or "미분류"
            return dept_cache[key]

        total_rows = 0
        category_stats = defaultdict(lambda: {
            "total": 0,
            "allowed": 0,
            "blocked": 0,
            "destinations": defaultdict(lambda: {
                "total": 0,
                "allowed": 0,
                "blocked": 0,
                "departments": Counter(),
                "sources": Counter(),
                "target_types": Counter(),
            }),
        })

        for row in dlp_rows:
            if not isinstance(row, dict):
                continue

            raw_dest = get_dest_detail(row)
            dest_name = normalize_report_destination(raw_dest)
            if not dest_name or dest_name == "None":
                continue

            target_name = get_target_name(row)
            target_type = get_target_type(row)
            category = classify_dlp_destination(target_name, target_type, raw_dest)
            blocked = self.is_dlp_blocked_row(row)

            machine_name = str(row.get("machine_name", "") or "").strip()
            dept_name = resolve_dept(machine_name)
            source_name = get_source_name(row)

            total_rows += 1
            cat_stat = category_stats[category]
            cat_stat["total"] += 1
            cat_stat["blocked" if blocked else "allowed"] += 1

            dest_stat = cat_stat["destinations"][dest_name]
            dest_stat["total"] += 1
            dest_stat["blocked" if blocked else "allowed"] += 1

            if dept_name and dept_name != "None":
                dest_stat["departments"][dept_name] += 1
            if source_name and source_name != "None":
                dest_stat["sources"][source_name] += 1
            if target_type and target_type != "None":
                dest_stat["target_types"][str(target_type)] += 1

        category_rows = []
        for category, stat in sorted(category_stats.items(), key=lambda x: (-x[1]["total"], x[0]))[:5]:
            cat_total = stat["total"]
            dest_rows = []

            for dest_name, dest_stat in sorted(
                stat["destinations"].items(),
                key=lambda x: (-x[1]["total"], x[0])
            )[:5]:
                top_departments = dest_stat["departments"].most_common(3)
                department_total = sum(dest_stat["departments"].values())
                top_department_total = sum(cnt for _, cnt in top_departments)
                department_other_count = max(department_total - top_department_total, 0)
                department_other_dept_count = max(len(dest_stat["departments"]) - len(top_departments), 0)
                top_sources = [
                    (shorten_path_text(name, 34), cnt)
                    for name, cnt in dest_stat["sources"].most_common(3)
                ]

                dest_rows.append({
                    "destination": dest_name,
                    "total": dest_stat["total"],
                    "allowed": dest_stat["allowed"],
                    "blocked": dest_stat["blocked"],
                    "share": round((dest_stat["total"] / cat_total) * 100, 1) if cat_total else 0.0,
                    "top_departments": top_departments,
                    "department_other_count": department_other_count,
                    "department_other_dept_count": department_other_dept_count,
                    "top_sources": top_sources,
                    "top_target_types": dest_stat["target_types"].most_common(2),
                })

            category_rows.append({
                "category": category,
                "total": cat_total,
                "allowed": stat["allowed"],
                "blocked": stat["blocked"],
                "share": round((cat_total / total_rows) * 100, 1) if total_rows else 0.0,
                "top_destinations": dest_rows,
            })

        return category_rows

    def draw_dlp_destination_insights(self, c, y_pos, category_rows, rf, margin, content_w):
        from reportlab.pdfbase.pdfmetrics import stringWidth

        def wrap_cell_text(text, max_width, font_size=7, max_lines=2):
            text = str(text or "").strip()
            if not text:
                return [""]

            lines = []
            for raw_line in text.split("\n"):
                words = raw_line.split() or [raw_line]
                current = ""
                for word in words:
                    if stringWidth(word, rf, font_size) > max_width:
                        pieces = []
                        piece = ""
                        for ch in word:
                            if stringWidth(piece + ch, rf, font_size) <= max_width:
                                piece += ch
                            else:
                                if piece:
                                    pieces.append(piece)
                                piece = ch
                        if piece:
                            pieces.append(piece)
                    else:
                        pieces = [word]

                    for piece in pieces:
                        test = piece if not current else f"{current} {piece}"
                        if stringWidth(test, rf, font_size) <= max_width:
                            current = test
                        else:
                            if current:
                                lines.append(current)
                            current = piece
                if current:
                    lines.append(current)

            if max_lines and len(lines) > max_lines:
                lines = lines[:max_lines]
                suffix = "..."
                while lines[-1] and stringWidth(lines[-1] + suffix, rf, font_size) > max_width:
                    lines[-1] = lines[-1][:-1]
                lines[-1] = (lines[-1].rstrip() + suffix) if lines[-1] else suffix

            return lines or [""]

        def draw_table(headers, rows, col_widths, y_table, font_size=6.8, line_height=8):
            header_h = 19
            table_w = sum(col_widths)
            y_table = self.check_page(c, y_table, threshold=100, font_name=rf, font_size=font_size)
            table_top = y_table + 4

            c.setFillColor(colors.HexColor("#dbeafe"))
            c.roundRect(margin + 1.4, y_table - header_h + 1.8, table_w, header_h, 5, fill=1, stroke=0)
            c.setFillColor(colors.HexColor("#005ce6"))
            c.roundRect(margin, y_table - header_h + 4, table_w, header_h, 5, fill=1, stroke=0)
            c.setFillGray(1)
            c.setFont(rf, font_size)
            ox = margin
            for h, cw in zip(headers, col_widths):
                c.drawString(ox + 4, y_table - 11, str(h))
                ox += cw
            c.setFillColor(colors.black)
            y_table -= header_h

            for ri, row in enumerate(rows):
                wrapped_cells = []
                max_lines = 1
                for val, cw in zip(row, col_widths):
                    wrapped = wrap_cell_text(val, cw - 7, font_size=font_size, max_lines=3)
                    wrapped_cells.append(wrapped)
                    max_lines = max(max_lines, len(wrapped))

                row_h = max(25, (max_lines * line_height) + 13)
                y_table = self.check_page(c, y_table, threshold=row_h + 45, font_name=rf, font_size=font_size)

                bg = colors.HexColor("#f8fbff") if ri % 2 == 0 else colors.white
                c.setFillColor(bg)
                c.rect(margin, y_table - row_h + 4, table_w, row_h, fill=1, stroke=0)
                c.setFillColor(colors.HexColor("#111827"))
                c.setFont(rf, font_size)

                ox = margin
                for cell_lines, cw in zip(wrapped_cells, col_widths):
                    ty = y_table - 9
                    for line in cell_lines:
                        c.drawString(ox + 4, ty, line)
                        ty -= line_height
                    ox += cw

                c.setStrokeColor(colors.HexColor("#d6e4f5"))
                c.setLineWidth(0.45)
                c.line(margin, y_table - row_h + 4, margin + table_w, y_table - row_h + 4)
                y_table -= row_h

            c.setStrokeColor(colors.HexColor("#cfe1ff"))
            c.setLineWidth(0.65)
            c.roundRect(margin, y_table + 4, table_w, table_top - (y_table + 4), 5, fill=0, stroke=1)
            c.setStrokeColor(colors.black)
            return y_table - 10

        def draw_category_visual(rows, y_chart):
            if not rows:
                return y_chart

            chart_h = 152
            y_chart = self.check_page(c, y_chart, threshold=chart_h + 40, font_name=rf, font_size=8)
            card_x = margin
            card_y = y_chart - chart_h + 4
            card_w = content_w
            colors_palette = [
                colors.HexColor("#0b63ff"),
                colors.HexColor("#16a3a3"),
                colors.HexColor("#8b5cf6"),
                colors.HexColor("#f59e0b"),
                colors.HexColor("#ef4444"),
            ]

            # 프로그램 UI 톤과 맞춘 밝은 카드 + 부드러운 그림자
            c.setFillColor(colors.HexColor("#dbeafe"))
            c.roundRect(card_x + 2.2, card_y - 2.2, card_w, chart_h, 10, fill=1, stroke=0)
            c.setFillColor(colors.HexColor("#ffffff"))
            c.roundRect(card_x, card_y, card_w, chart_h, 10, fill=1, stroke=0)
            c.setStrokeColor(colors.HexColor("#cfe1ff"))
            c.setLineWidth(0.7)
            c.roundRect(card_x, card_y, card_w, chart_h, 10, fill=0, stroke=1)

            c.setFont(rf, 8.4)
            c.setFillColor(colors.HexColor("#005ce6"))
            c.drawString(card_x + 12, y_chart - 14, "Top 분류 시각화")
            c.setFont(rf, 7)
            c.setFillColor(colors.HexColor("#667085"))
            c.drawRightString(card_x + card_w - 12, y_chart - 14, "총건수 기준 / 허용·차단 포함")

            max_total = max(int(row.get("total", 0) or 0) for row in rows) or 1
            bar_x = card_x + 14
            bar_y = y_chart - 36
            label_w = 86
            bar_w = 190
            row_gap = 18

            for idx, row in enumerate(rows[:5]):
                total = int(row.get("total", 0) or 0)
                category = str(row.get("category", "-"))
                y_row = bar_y - idx * row_gap
                color = colors_palette[idx % len(colors_palette)]
                share_w = max(4, bar_w * total / max_total)

                c.setFont(rf, 6.8)
                c.setFillColor(colors.HexColor("#344054"))
                label = f"{idx + 1}. {category}"
                while stringWidth(label, rf, 6.8) > label_w and len(label) > 5:
                    label = label[:-2] + "…"
                c.drawString(bar_x, y_row, label)

                c.setFillColor(colors.HexColor("#eef4ff"))
                c.roundRect(bar_x + label_w, y_row - 5, bar_w, 7, 3, fill=1, stroke=0)
                c.setFillColor(color)
                c.roundRect(bar_x + label_w, y_row - 5, share_w, 7, 3, fill=1, stroke=0)
                c.setFillColor(colors.HexColor("#1f2937"))
                c.setFont(rf, 6.8)
                c.drawRightString(bar_x + label_w + bar_w + 42, y_row - 1, f"{total:,}건")

            pie_rows = rows[:5]
            pie_sum = sum(int(row.get("total", 0) or 0) for row in pie_rows) or 1
            cx = card_x + card_w - 96
            cy = card_y + 78
            radius = 42
            start_angle = 90
            for idx, row in enumerate(pie_rows):
                total = int(row.get("total", 0) or 0)
                extent = 360 * total / pie_sum
                c.setFillColor(colors_palette[idx % len(colors_palette)])
                c.wedge(cx - radius, cy - radius, cx + radius, cy + radius, start_angle, extent, fill=1, stroke=0)
                start_angle += extent

            c.setFillColor(colors.white)
            c.circle(cx, cy, radius * 0.55, fill=1, stroke=0)
            c.setFillColor(colors.HexColor("#005ce6"))
            c.setFont(rf, 10)
            c.drawCentredString(cx, cy + 3, "TOP 5")
            c.setFillColor(colors.HexColor("#667085"))
            c.setFont(rf, 6.8)
            c.drawCentredString(cx, cy - 9, f"{pie_sum:,}건")
            c.setFillColor(colors.black)
            return y_chart - chart_h - 12

        if not category_rows:
            c.setFont(rf, 10)
            c.setFillColor(colors.black)
            c.drawString(margin + 6, y_pos, "DLP 목적지 데이터가 확인되지 않았습니다.")
            return y_pos - 18

        top_total = sum(int(row.get("total", 0) or 0) for row in category_rows)
        c.setFont(rf, 9)
        c.setFillColor(colors.HexColor("#374151"))
        c.drawString(margin + 6, y_pos, f"전체 DLP 목적지 중 총건수 상위 5개 분류를 표시합니다. (상위 분류 합계 {top_total:,}건)")
        y_pos -= 18

        y_pos = draw_category_visual(category_rows, y_pos)

        summary_rows = []
        for idx, row in enumerate(category_rows, 1):
            top_dest_text = ", ".join([
                f"{d.get('destination')}({d.get('total')})"
                for d in row.get("top_destinations", [])[:3]
            ]) or "-"
            summary_rows.append([
                str(idx),
                row.get("category", "-"),
                str(row.get("total", 0)),
                str(row.get("allowed", 0)),
                str(row.get("blocked", 0)),
                f"{row.get('share', 0.0)}%",
                top_dest_text,
            ])

        y_pos = draw_table(
            ["순위", "분류", "총", "허용", "차단", "비율", "주요 목적지"],
            summary_rows,
            [28, 112, 36, 36, 36, 42, content_w - 290],
            y_pos,
            font_size=7.0,
            line_height=8
        )

        for rank_idx, row in enumerate(category_rows, start=1):
            category = row.get("category", "-")
            total_count = int(row.get("total", 0) or 0)
            allowed = int(row.get("allowed", 0) or 0)
            blocked = int(row.get("blocked", 0) or 0)
            share = row.get("share", 0.0)
            top_destinations = row.get("top_destinations", [])
            top_destination = top_destinations[0].get("destination", "-") if top_destinations else "-"

            y_pos -= 20 if rank_idx > 1 else 10
            y_pos = self.check_page(c, y_pos, threshold=210, font_name=rf, font_size=9)
            c.setFillColor(colors.HexColor("#dbeafe"))
            c.roundRect(margin + 2.4, y_pos - 33.4, content_w, 36, 10, fill=1, stroke=0)
            c.setFillColor(colors.HexColor("#f8fbff"))
            c.roundRect(margin, y_pos - 31, content_w, 36, 10, fill=1, stroke=0)
            c.setStrokeColor(colors.HexColor("#93c5fd"))
            c.setLineWidth(0.8)
            c.roundRect(margin, y_pos - 31, content_w, 36, 10, fill=0, stroke=1)
            c.setFillColor(colors.HexColor("#005ce6"))
            c.roundRect(margin + 10, y_pos - 20, 48, 16, 8, fill=1, stroke=0)
            c.setFont(rf, 7.2)
            c.setFillColor(colors.white)
            c.drawCentredString(margin + 34, y_pos - 15, f"TOP {rank_idx}")
            c.setFont(rf, 9.2)
            c.setFillColor(colors.HexColor("#111827"))
            c.drawString(
                margin + 68,
                y_pos - 8,
                str(category)
            )
            c.setFont(rf, 7.2)
            c.setFillColor(colors.HexColor("#667085"))
            c.drawString(
                margin + 68,
                y_pos - 21,
                f"총 {total_count:,}건 · 허용 {allowed:,}건 · 차단 {blocked:,}건 · 전체 {share}%"
            )
            y_pos -= 43

            comment = self.get_dlp_destination_category_comment(category, top_destination)
            c.setFont(rf, 7.4)
            c.setFillColor(colors.HexColor("#374151"))
            for line in wrap_cell_text(comment, content_w - 12, font_size=7.4, max_lines=2):
                c.drawString(margin + 6, y_pos, line)
                y_pos -= 10
            y_pos -= 2

            dest_rows = []
            for dest in top_destinations[:5]:
                dept_lines = [f"{name}({cnt})" for name, cnt in dest.get("top_departments", [])]
                department_other_count = int(dest.get("department_other_count", 0) or 0)
                department_other_dept_count = int(dest.get("department_other_dept_count", 0) or 0)
                if department_other_count > 0:
                    dept_lines.append(f"외 {department_other_dept_count}개 부서({department_other_count})")
                dept_text = "\n".join(dept_lines) or "-"
                source_text = "\n".join([f"{name}({cnt})" for name, cnt in dest.get("top_sources", [])]) or "-"
                dest_rows.append([
                    dest.get("destination", "-"),
                    str(dest.get("total", 0)),
                    str(dest.get("allowed", 0)),
                    str(dest.get("blocked", 0)),
                    f"{dest.get('share', 0.0)}%",
                    dept_text,
                    source_text,
                ])

            y_pos = draw_table(
                ["목적지", "총", "허용", "차단", "비중", "주요 부서", "주요 파일"],
                dest_rows or [["-", "0", "0", "0", "0%", "-", "-"]],
                [118, 30, 30, 30, 44, 105, content_w - 357],
                y_pos,
                font_size=6.7,
                line_height=8
            )
            c.setStrokeColor(colors.HexColor("#dbeafe"))
            c.setLineWidth(1.2)
            c.line(margin + 8, y_pos + 2, margin + content_w - 8, y_pos + 2)
            c.setStrokeColor(colors.black)
            y_pos -= 34

        c.setFillColor(colors.black)
        return y_pos

    def _generate_security_report_v2(self, start_dt, end_dt, progress_cb=None):
        perf = ReportPerfTimer("security_report")

        def progress(message):
            log.info("[REPORT] %s", message)
            if progress_cb:
                progress_cb(message)

        try:
            progress("데이터 로딩 중...")
            os.makedirs(REPORT_DIR, exist_ok=True)

            start_date = start_dt.strftime("%Y-%m-%d")
            end_date = end_dt.strftime("%Y-%m-%d")

            endpoint_detections = load_endpoint_detections_by_range(start_date, end_date)
            xdr_detections_report = load_xdr_email_detections_by_range(start_date, end_date)
            emails = load_emails_by_range(start_date, end_date)
            mailscreen_rows = load_mailscreen_by_range(start_date, end_date)
            dlp_rows = load_dlp_by_range(start_date, end_date)
            perf.mark("load data")
            progress("DLP 분석 중...")
            report_identity_resolver = self.build_report_identity_resolver()

            dlp_total_count = len(dlp_rows)
            dlp_blocked_rows = [r for r in dlp_rows if self.is_dlp_blocked_row(r)]
            dlp_allowed_rows = [r for r in dlp_rows if not self.is_dlp_blocked_row(r)]

            dlp_blocked_count = len(dlp_blocked_rows)
            dlp_allowed_count = len(dlp_allowed_rows)

            dlp_blocked_pct = round((dlp_blocked_count / dlp_total_count) * 100, 1) if dlp_total_count else 0.0
            dlp_allowed_pct = round((dlp_allowed_count / dlp_total_count) * 100, 1) if dlp_total_count else 0.0

            detection_timeline = defaultdict(int)
            for d in endpoint_detections:
                if not isinstance(d, dict):
                    continue
                t = d.get("time")
                if t:
                    try:
                        dt  = datetime.fromisoformat(str(t).replace("Z", "+00:00"))
                        kst = dt.astimezone(timezone(timedelta(hours=9)))
                        detection_timeline[kst.strftime("%Y-%m-%d")] += 1
                    except Exception:
                        pass

            # ── Email - XDR 부서별 집계 ─────────────────────────────
            _xdr_dept_stats = defaultdict(lambda: {
                "total": 0,
                "rules": Counter(),
                "mailboxes": set(),
                "users": set(),
                "iocs": Counter(),
            })
            for _d in xdr_detections_report:
                if not isinstance(_d, dict):
                    continue
                _row_data = extract_xdr_email_fields(_d)
                _mailbox  = _row_data.get("mailbox", "")
                _rule_val = _row_data.get("rule", "")
                _ioc_val  = _row_data.get("ioc", "")
                _identity = resolve_identity_by_mailbox(_mailbox)
                _dept     = _identity.get("dept_name", "미분류") or "미분류"
                _stat     = _xdr_dept_stats[_dept]
                _stat["total"] += 1
                if _rule_val:
                    _stat["rules"][_rule_val] += 1
                if _mailbox and _mailbox != "None":
                    _stat["mailboxes"].add(_mailbox)
                _uname = _identity.get("user_name", "")
                if _uname and _uname != "None":
                    _stat["users"].add(_uname)
                if _ioc_val and _ioc_val != "None":
                    _stat["iocs"][_ioc_val] += 1

            xdr_dept_rank = sorted(
                [
                    {
                        "dept_name": _dn,
                        "total":     _st["total"],
                        "mailbox_count": len(_st["mailboxes"]),
                        "user_count":    len(_st["users"]),
                        "top_rules":     _st["rules"].most_common(3),
                        "top_iocs":      _st["iocs"].most_common(5),
                        "mailboxes_preview": sorted(list(_st["mailboxes"]))[:5],
                    }
                    for _dn, _st in _xdr_dept_stats.items()
                ],
                key=lambda x: (-x["total"], x["dept_name"])
            )

            # ── Outbound Mail(MailScreen) 부서/결재 집계 ─────────────────────────
            outbound_rows = []
            outbound_dept_stats = defaultdict(lambda: {
                "total": 0,
                "success": 0,
                "fail": 0,
                "approved": 0,
                "rejected": 0,
                "canceled": 0,
                "senders": set(),
                "receivers": Counter(),
                "policies": Counter(),
                "processes": Counter(),
            })
            outbound_process_counter = Counter()
            outbound_policy_counter = Counter()
            outbound_receiver_domain_counter = Counter()
            outbound_success_count = 0
            outbound_fail_count = 0

            def _outbound_receiver_domain(value):
                text = str(value or "").strip()
                if not text or text == "None":
                    return "None"
                first = text.split(",")[0].strip().split()[0].strip("<>()[];,")
                if "@" in first:
                    return first.rsplit("@", 1)[-1].lower() or "None"
                return "None"

            for _row in mailscreen_rows:
                if not isinstance(_row, dict):
                    continue
                _row = enrich_mailscreen_sender_fields(_row)
                _dt = timeline_parse_dt(_row.get("date"))
                if _dt and (_dt < start_dt or _dt > end_dt):
                    continue

                outbound_rows.append(_row)
                _dept = str(_row.get("sender_dept") or _row.get("dept") or "미분류").strip() or "미분류"
                _sender = str(_row.get("sender_name") or _row.get("sender_email") or _row.get("sender") or "None").strip()
                _send_result = str(_row.get("send_result") or "None").strip()
                _mail_process = str(_row.get("mail_process") or "None").strip()
                _policy = str(_row.get("policy") or "None").strip()
                _receiver_domain = _outbound_receiver_domain(_row.get("receiver_detail") or _row.get("receiver"))

                _stat = outbound_dept_stats[_dept]
                _stat["total"] += 1
                if _sender and _sender != "None":
                    _stat["senders"].add(_sender)
                if _receiver_domain != "None":
                    _stat["receivers"][_receiver_domain] += 1
                    outbound_receiver_domain_counter[_receiver_domain] += 1
                if _policy and _policy != "None":
                    _stat["policies"][_policy] += 1
                    outbound_policy_counter[_policy] += 1
                if _mail_process and _mail_process != "None":
                    _stat["processes"][_mail_process] += 1
                    outbound_process_counter[_mail_process] += 1

                if _send_result == "성공":
                    _stat["success"] += 1
                    outbound_success_count += 1
                elif _send_result == "실패":
                    _stat["fail"] += 1
                    outbound_fail_count += 1

                if "결재" in _mail_process and "승인" in _mail_process:
                    _stat["approved"] += 1
                elif "결재" in _mail_process and "반려" in _mail_process:
                    _stat["rejected"] += 1
                elif "결재" in _mail_process and "취소" in _mail_process:
                    _stat["canceled"] += 1

            outbound_dept_rank = sorted(
                [
                    {
                        "dept_name": _dept,
                        "total": _st["total"],
                        "success": _st["success"],
                        "fail": _st["fail"],
                        "approved": _st["approved"],
                        "rejected": _st["rejected"],
                        "canceled": _st["canceled"],
                        "sender_count": len(_st["senders"]),
                        "top_policies": _st["policies"].most_common(3),
                        "top_receivers": _st["receivers"].most_common(3),
                        "top_processes": _st["processes"].most_common(3),
                    }
                    for _dept, _st in outbound_dept_stats.items()
                ],
                key=lambda x: (-x["total"], x["dept_name"])
            )
            outbound_approval_rows = [
                {"status": "결재(승인)", "total": sum(int(x.get("approved", 0) or 0) for x in outbound_dept_rank)},
                {"status": "결재(반려)", "total": sum(int(x.get("rejected", 0) or 0) for x in outbound_dept_rank)},
                {"status": "결재(취소)", "total": sum(int(x.get("canceled", 0) or 0) for x in outbound_dept_rank)},
            ]
            outbound_approval_rows = [x for x in outbound_approval_rows if int(x.get("total", 0) or 0) > 0]

            perf.mark("pre-metrics aggregation")
            metrics = self.build_security_insight_metrics(
                endpoint_detections,
                emails,
                dlp_rows,
                detection_timeline,
                report_identity_resolver=report_identity_resolver,
            )
            perf.mark("security metrics")
            progress("PDF 생성 중...")
            dlp_dept_rank        = metrics.get("dlp_dept_rank", [])
            dlp_dept_block_rank  = metrics.get("dlp_dept_block_rank", [])
            unclassified_user_counts = metrics.get("unclassified_user_counts", [])
            det_dept_rank        = metrics.get("det_dept_rank", [])
            selected_days = max((end_dt.date() - start_dt.date()).days + 1, 1)

            risk = self.build_security_risk_assessment(metrics, selected_days=selected_days)
            insight_lines = self.build_security_insight_lines(metrics)
            action_items = self.build_security_action_items(metrics, risk)
            manager_summary = self.build_security_manager_summary(metrics, risk)
            score_breakdown = risk.get("score_breakdown", [])

            cross_host_count       = metrics.get("cross_host_count", 0)
            cross_host_ratio       = metrics.get("cross_host_ratio", 0.0)
            overlap_day_count      = metrics.get("overlap_day_count", 0)
            triple_overlap_count   = metrics.get("triple_overlap_count", 0)
            repeated_cross_count   = metrics.get("repeated_cross_host_count", 0)

            ts = datetime.now().strftime("%Y%m%d_%H%M%S")

            pdf_path = os.path.join(
                REPORT_DIR,
                f"Security_Report_{start_date}_{end_date}.pdf"
            )
            pdf_path = get_unique_path(pdf_path)

            c          = canvas.Canvas(pdf_path, pagesize=A4)
            PAGE_W, _  = A4
            rf         = self.setup_report_font()
            perf.mark("pdf setup")
            MARGIN     = 45
            CONTENT_W  = PAGE_W - MARGIN * 2   # ≈ 505pt

            # ── 공통 헬퍼 ────────────────────────────────────────
            page_state = {"number": 1}
            theme = {
                "page_bg": colors.HexColor("#f8fbff"),
                "primary": colors.HexColor("#005ce6"),
                "primary_dark": colors.HexColor("#174ea6"),
                "border": colors.HexColor("#bfdbfe"),
                "shadow": colors.HexColor("#d8e8f6"),
                "text": colors.HexColor("#111827"),
                "muted": colors.HexColor("#667085"),
                "card": colors.white,
            }

            def draw_page_background():
                c.saveState()
                c.setFillColor(theme["page_bg"])
                c.rect(0, 0, PAGE_W, A4[1], fill=1, stroke=0)
                c.restoreState()

            def draw_soft_card(x, y_top, w, h, radius=10, fill=None, stroke=None, shadow=True):
                fill = fill or theme["card"]
                stroke = stroke or theme["border"]
                if shadow:
                    c.setFillColor(theme["shadow"])
                    c.roundRect(x + 2.4, y_top - h - 2.6, w, h, radius, fill=1, stroke=0)
                c.setFillColor(fill)
                c.roundRect(x, y_top - h, w, h, radius, fill=1, stroke=0)
                c.setStrokeColor(stroke)
                c.setLineWidth(0.65)
                c.roundRect(x, y_top - h, w, h, radius, fill=0, stroke=1)

            def draw_page_footer():
                c.saveState()
                c.setFont(rf, 7)
                c.setFillColor(theme["muted"])
                c.drawCentredString(PAGE_W / 2, 24, f"- {page_state['number']} -")
                c.restoreState()

            def after_show_page():
                page_state["number"] += 1
                draw_page_background()
                c.setFont(rf, 10)
                c.setFillColor(theme["text"])

            draw_page_background()
            c._smu_report_draw_footer = draw_page_footer
            c._smu_report_after_show_page = after_show_page

            def new_page():
                draw_page_footer()
                c.showPage()
                after_show_page()
                return 810

            def section_bar(title, y_pos):
                c.setFillColor(colors.HexColor("#dbeafe"))
                c.roundRect(MARGIN + 1.8, y_pos - 24.2, CONTENT_W, 24, 8, fill=1, stroke=0)
                c.setFillColor(theme["primary_dark"])
                c.roundRect(MARGIN, y_pos - 22, CONTENT_W, 24, 8, fill=1, stroke=0)
                c.setFillGray(1)
                c.setFont(rf, 11)
                c.drawString(MARGIN + 10, y_pos - 14, title)
                c.setFillColor(theme["text"])
                return y_pos - 38

            def numbered_list(lines, y_pos, indent=MARGIN + 10):
                c.setFont(rf, 10)

                def wrap_by_width(text, max_width, font_name=rf, font_size=10):
                    text = str(text or "").strip()
                    if not text:
                        return [""]

                    words = text.split()
                    wrapped = []
                    current = ""

                    for word in words:
                        test = word if not current else f"{current} {word}"
                        if c.stringWidth(test, font_name, font_size) <= max_width:
                            current = test
                        else:
                            if current:
                                wrapped.append(current)
                            current = word

                    if current:
                        wrapped.append(current)

                    return wrapped or [""]

                for i, item in enumerate(lines, 1):
                    y_pos = self.check_page(c, y_pos, threshold=140, font_name=rf, font_size=10)

                    if isinstance(item, list):
                        block_lines = [str(x or "") for x in item]
                    else:
                        block_lines = [str(item or "")]

                    prefix = f"{i}. "
                    prefix_w = c.stringWidth(prefix, rf, 10)

                    first_lines = wrap_by_width(block_lines[0], CONTENT_W - 20 - prefix_w, rf, 10)
                    c.drawString(indent, y_pos, prefix + first_lines[0])
                    y_pos -= 15

                    for extra in first_lines[1:]:
                        c.drawString(indent + prefix_w, y_pos, extra)
                        y_pos -= 15

                    for sub in block_lines[1:]:
                        sub_lines = wrap_by_width(sub, CONTENT_W - 30 - prefix_w, rf, 10)

                        for idx, extra in enumerate(sub_lines):
                            if idx == 0:
                                c.drawString(indent + prefix_w + 4, y_pos, extra)
                            else:
                                c.drawString(indent + prefix_w + 12, y_pos, extra)
                            y_pos -= 15

                    y_pos -= 10

                return y_pos

            def mini_table(x, y_pos, headers, rows, col_widths, font_size=9):
                """앱 UI 톤의 헤더+행 소형 테이블 (페이지 넘김 없음)."""
                from reportlab.pdfbase.pdfmetrics import stringWidth

                row_h = 19
                total_w = sum(col_widths)
                table_top = y_pos + 4

                # 헤더: DLP 목적지 인사이트와 동일한 파란 라운드 스타일
                c.setFillColor(colors.HexColor("#dbeafe"))
                c.roundRect(x + 1.3, y_pos - row_h + 1.6, total_w, row_h, 5, fill=1, stroke=0)
                c.setFillColor(theme["primary"])
                c.roundRect(x, y_pos - row_h + 4, total_w, row_h, 5, fill=1, stroke=0)
                c.setFillGray(1)
                c.setFont(rf, font_size)
                ox = x
                for h, cw in zip(headers, col_widths):
                    c.drawString(ox + 4, y_pos - 11, str(h))
                    ox += cw
                c.setFillColor(theme["text"])
                y_pos -= row_h

                # 행
                for ri, row in enumerate(rows):
                    bg = colors.HexColor("#f8fbff") if ri % 2 == 0 else colors.white
                    c.setFillColor(bg)
                    c.rect(x, y_pos - row_h + 4, total_w, row_h, fill=1, stroke=0)
                    c.setFillColor(theme["text"])
                    c.setFont(rf, font_size)
                    ox = x
                    for val, cw in zip(row, col_widths):
                        text = str(val)
                        while stringWidth(text, rf, font_size) > cw - 8 and len(text) > 3:
                            text = text[:-2] + "…"
                        c.drawString(ox + 4, y_pos - 11, text)
                        ox += cw
                    c.setStrokeColor(colors.HexColor("#d6e4f5"))
                    c.setLineWidth(0.45)
                    c.line(x, y_pos - row_h + 4, x + total_w, y_pos - row_h + 4)
                    y_pos -= row_h

                c.setStrokeColor(colors.HexColor("#cfe1ff"))
                c.setLineWidth(0.65)
                c.roundRect(x, y_pos + 4, total_w, table_top - (y_pos + 4), 5, fill=0, stroke=1)
                c.setStrokeColor(colors.black)
                return y_pos - 8

            def mini_table_multiline(x, y_pos, headers, rows, col_widths, font_size=8, line_height=11):
                def wrap_cell_text(text, max_width, max_lines=None):
                    from reportlab.pdfbase.pdfmetrics import stringWidth

                    def split_long_token(token, width):
                        parts = []
                        current = ""
                        for ch in token:
                            test = current + ch
                            if stringWidth(test, rf, font_size) <= width:
                                current = test
                            else:
                                if current:
                                    parts.append(current)
                                current = ch
                        if current:
                            parts.append(current)
                        return parts or [""]

                    def ellipsize_to_width(text_value, width):
                        text_value = str(text_value or "").rstrip()
                        if stringWidth(text_value, rf, font_size) <= width:
                            return text_value

                        suffix = "..."
                        out = text_value
                        while out and stringWidth(out + suffix, rf, font_size) > width:
                            out = out[:-1]

                        return (out.rstrip() + suffix) if out else suffix

                    lines = []

                    for raw_line in str(text or "").split("\n"):
                        raw_line = str(raw_line).strip()
                        if not raw_line:
                            lines.append("")
                            continue

                        words = raw_line.split()
                        current = ""

                        if not words:
                            lines.append("")
                            continue

                        for word in words:
                            if stringWidth(word, rf, font_size) > max_width:
                                pieces = split_long_token(word, max_width)
                            else:
                                pieces = [word]

                            for piece in pieces:
                                test = piece if not current else f"{current} {piece}"
                                if stringWidth(test, rf, font_size) <= max_width:
                                    current = test
                                else:
                                    if current:
                                        lines.append(current)
                                    current = piece

                        if current:
                            lines.append(current)

                    if not lines:
                        lines = [""]

                    if max_lines and len(lines) > max_lines:
                        lines = lines[:max_lines]
                        lines[-1] = ellipsize_to_width(lines[-1], max_width)

                    return lines

                header_h = 19
                total_w = sum(col_widths)
                table_top = y_pos + 4
                c.setFillColor(colors.HexColor("#dbeafe"))
                c.roundRect(x + 1.3, y_pos - header_h + 1.6, total_w, header_h, 5, fill=1, stroke=0)
                c.setFillColor(theme["primary"])
                c.roundRect(x, y_pos - header_h + 4, total_w, header_h, 5, fill=1, stroke=0)
                c.setFillGray(1)
                c.setFont(rf, font_size)
                ox = x
                for h, cw in zip(headers, col_widths):
                    c.drawString(ox + 4, y_pos - 11, str(h))
                    ox += cw
                c.setFillColor(theme["text"])
                y_pos -= header_h

                for ri, row in enumerate(rows):
                    wrapped_cells = []
                    max_lines = 1

                    for col_idx, (val, cw) in enumerate(zip(row, col_widths)):
                        if col_idx == 0:      # 소스
                            wrapped = wrap_cell_text(val, cw - 8, max_lines=5)
                        elif col_idx == 1:    # 분류/대상유형
                            wrapped = wrap_cell_text(val, cw - 8, max_lines=5)
                        elif col_idx == 2:    # 목적지 세부정보
                            wrapped = wrap_cell_text(val, cw - 8, max_lines=1)
                        else:                 # 건수
                            wrapped = wrap_cell_text(val, cw - 8, max_lines=1)

                        wrapped_cells.append(wrapped)
                        max_lines = max(max_lines, len(wrapped))

                    row_h = max(26, (max_lines * line_height) + 16)

                    if y_pos - row_h < 40:
                        y_pos = new_page()
                        table_top = y_pos + 4

                        c.setFillColor(colors.HexColor("#dbeafe"))
                        c.roundRect(x + 1.3, y_pos - header_h + 1.6, total_w, header_h, 5, fill=1, stroke=0)
                        c.setFillColor(theme["primary"])
                        c.roundRect(x, y_pos - header_h + 4, total_w, header_h, 5, fill=1, stroke=0)
                        c.setFillGray(1)
                        c.setFont(rf, font_size)

                        ox = x
                        for h, cw in zip(headers, col_widths):
                            c.drawString(ox + 4, y_pos - 11, str(h))
                            ox += cw

                        c.setFillColor(theme["text"])
                        y_pos -= header_h

                    bg = colors.HexColor("#f8fbff") if ri % 2 == 0 else colors.white
                    c.setFillColor(bg)
                    c.rect(x, y_pos - row_h + 4, total_w, row_h, fill=1, stroke=0)
                    c.setFillColor(theme["text"])
                    c.setFont(rf, font_size)

                    ox = x
                    for cell_lines, cw in zip(wrapped_cells, col_widths):
                        text_block_h = max(1, len(cell_lines)) * line_height
                        top_padding = max(4, (row_h - text_block_h) / 2)
                        text_block_h = len(cell_lines) * line_height
                        ty = y_pos - ((row_h - text_block_h) / 2) - 1

                        for line in cell_lines:
                            c.drawString(ox + 4, ty, str(line))
                            ty -= line_height

                        ox += cw

                    c.setStrokeColor(colors.HexColor("#d6e4f5"))
                    c.setLineWidth(0.45)
                    c.line(x, y_pos - row_h + 4, x + total_w, y_pos - row_h + 4)
                    y_pos -= row_h

                c.setStrokeColor(colors.HexColor("#cfe1ff"))
                c.setLineWidth(0.65)
                c.roundRect(x, y_pos + 4, total_w, table_top - (y_pos + 4), 5, fill=0, stroke=1)
                c.setStrokeColor(colors.black)
                return y_pos - 8


            def mini_table_fixed(x, y_pos, headers, rows, col_widths, font_size=6.8, row_h=20):
                from reportlab.pdfbase.pdfmetrics import stringWidth

                total_w = sum(col_widths)

                def fit_text(text, max_width):
                    text = str(text or "").replace("\n", " / ").strip()
                    if not text:
                        return "-"

                    if stringWidth(text, rf, font_size) <= max_width:
                        return text

                    ell = "…"
                    usable = max_width - stringWidth(ell, rf, font_size)
                    if usable <= 8:
                        return ell

                    out = ""
                    for ch in text:
                        test = out + ch
                        if stringWidth(test, rf, font_size) > usable:
                            break
                        out = test

                    return (out.rstrip() + ell) if out else ell

                # 헤더
                c.setFillColor(colors.HexColor("#2f5ea8"))
                c.rect(x, y_pos - row_h + 4, total_w, row_h, fill=1, stroke=0)

                c.setFont(rf, font_size)
                c.setFillColor(colors.white)

                ox = x
                for h, cw in zip(headers, col_widths):
                    c.drawString(ox + 4, y_pos - 11, str(h))
                    ox += cw

                # 헤더 세로선
                c.setStrokeColor(colors.white)
                c.setLineWidth(0.4)
                ox = x
                for cw in col_widths[:-1]:
                    ox += cw
                    c.line(ox, y_pos - row_h + 4, ox, y_pos + 4)

                c.setFillColor(colors.black)
                c.setStrokeColor(colors.HexColor("#c7d3e3"))
                y_pos -= row_h

                # 본문
                for ri, row in enumerate(rows):
                    bg = colors.HexColor("#f7f9fc") if ri % 2 == 0 else colors.white
                    c.setFillColor(bg)
                    c.rect(x, y_pos - row_h + 4, total_w, row_h, fill=1, stroke=0)

                    ox = x
                    c.setFont(rf, font_size)
                    c.setFillColor(colors.black)

                    for idx, (val, cw) in enumerate(zip(row, col_widths)):
                        text = fit_text(val, cw - 8)

                        if idx == len(col_widths) - 1:
                            # 건수는 우측 정렬
                            tw = stringWidth(text, rf, font_size)
                            c.drawString(ox + cw - tw - 4, y_pos - 11, text)
                        else:
                            c.drawString(ox + 4, y_pos - 11, text)

                        ox += cw

                    # 세로선
                    ox = x
                    for cw in col_widths[:-1]:
                        ox += cw
                        c.setStrokeColor(colors.HexColor("#d6deea"))
                        c.setLineWidth(0.35)
                        c.line(ox, y_pos - row_h + 4, ox, y_pos + 4)

                    # 가로선
                    c.setStrokeColor(colors.HexColor("#d6deea"))
                    c.setLineWidth(0.45)
                    c.line(x, y_pos - row_h + 4, x + total_w, y_pos - row_h + 4)

                    y_pos -= row_h

                return y_pos - 6

            def draw_distribution_card(title, rows, y_pos, *, label_key="dept_name", value_key="total",
                                       subtitle="총건수 기준", empty_text="데이터가 확인되지 않았습니다."):
                from reportlab.pdfbase.pdfmetrics import stringWidth

                rows = [r for r in (rows or []) if int(r.get(value_key, 0) or 0) > 0][:5]
                card_h = 150
                y_pos = self.check_page(c, y_pos, threshold=card_h + 48, font_name=rf, font_size=8)
                if not rows:
                    draw_soft_card(MARGIN, y_pos, CONTENT_W, 44, radius=10, fill=theme["card"], stroke=theme["border"], shadow=True)
                    c.setFont(rf, 8.5)
                    c.setFillColor(theme["muted"])
                    c.drawString(MARGIN + 12, y_pos - 24, empty_text)
                    c.setFillColor(theme["text"])
                    return y_pos - 58

                draw_soft_card(MARGIN, y_pos, CONTENT_W, card_h, radius=12, fill=theme["card"], stroke=theme["border"], shadow=True)
                palette = [
                    colors.HexColor("#0b63ff"),
                    colors.HexColor("#16a3a3"),
                    colors.HexColor("#8b5cf6"),
                    colors.HexColor("#f59e0b"),
                    colors.HexColor("#ef4444"),
                ]
                c.setFont(rf, 8.5)
                c.setFillColor(theme["primary"])
                c.drawString(MARGIN + 14, y_pos - 16, title)
                c.setFont(rf, 7)
                c.setFillColor(theme["muted"])
                c.drawRightString(MARGIN + CONTENT_W - 14, y_pos - 16, subtitle)

                max_total = max(int(row.get(value_key, 0) or 0) for row in rows) or 1
                total_sum = sum(int(row.get(value_key, 0) or 0) for row in rows) or 1
                bar_x = MARGIN + 16
                bar_y = y_pos - 40
                label_w = 104
                bar_w = 178
                row_gap = 18

                for idx, row in enumerate(rows):
                    value = int(row.get(value_key, 0) or 0)
                    label = str(row.get(label_key, "-") or "-")
                    y_row = bar_y - idx * row_gap
                    color = palette[idx % len(palette)]
                    display = f"{idx + 1}. {label}"
                    while stringWidth(display, rf, 6.8) > label_w and len(display) > 5:
                        display = display[:-2] + "…"
                    c.setFont(rf, 6.8)
                    c.setFillColor(colors.HexColor("#344054"))
                    c.drawString(bar_x, y_row, display)
                    c.setFillColor(colors.HexColor("#eef4ff"))
                    c.roundRect(bar_x + label_w, y_row - 5, bar_w, 7, 3, fill=1, stroke=0)
                    c.setFillColor(color)
                    c.roundRect(bar_x + label_w, y_row - 5, max(4, bar_w * value / max_total), 7, 3, fill=1, stroke=0)
                    c.setFillColor(theme["text"])
                    c.drawRightString(bar_x + label_w + bar_w + 48, y_row - 1, f"{value:,}건")

                cx = MARGIN + CONTENT_W - 92
                cy = y_pos - 78
                radius = 41
                start_angle = 90
                for idx, row in enumerate(rows):
                    value = int(row.get(value_key, 0) or 0)
                    extent = 360 * value / total_sum
                    c.setFillColor(palette[idx % len(palette)])
                    c.wedge(cx - radius, cy - radius, cx + radius, cy + radius, start_angle, extent, fill=1, stroke=0)
                    start_angle += extent
                c.setFillColor(theme["card"])
                c.circle(cx, cy, radius * 0.55, fill=1, stroke=0)
                c.setFillColor(theme["primary"])
                c.setFont(rf, 9.5)
                c.drawCentredString(cx, cy + 3, "TOP 5")
                c.setFillColor(theme["muted"])
                c.setFont(rf, 6.8)
                c.drawCentredString(cx, cy - 9, f"{total_sum:,}건")
                c.setFillColor(theme["text"])
                return y_pos - card_h - 18

            def draw_rank_header(rank, title, meta, y_pos, *, accent=None):
                y_pos = self.check_page(c, y_pos, threshold=76, font_name=rf, font_size=8)
                accent = accent or theme["primary"]
                draw_soft_card(MARGIN, y_pos, CONTENT_W, 38, radius=11, fill=colors.HexColor("#f8fbff"), stroke=colors.HexColor("#93c5fd"), shadow=True)
                c.setFillColor(accent)
                c.roundRect(MARGIN + 10, y_pos - 24, 52, 17, 8.5, fill=1, stroke=0)
                c.setFillColor(colors.white)
                c.setFont(rf, 7.2)
                c.drawCentredString(MARGIN + 36, y_pos - 18.5, f"TOP {rank}")
                c.setFillColor(theme["text"])
                c.setFont(rf, 9.2)
                c.drawString(MARGIN + 72, y_pos - 12, str(title))
                c.setFillColor(theme["muted"])
                c.setFont(rf, 7.2)
                c.drawString(MARGIN + 72, y_pos - 26, str(meta))
                c.setFillColor(theme["text"])
                return y_pos - 48

            def wrap_report_text(text, max_width, font_size=8, font_name=None):
                from reportlab.pdfbase.pdfmetrics import stringWidth

                font_name = font_name or rf
                text = str(text or "").strip()
                if not text:
                    return [""]
                lines = []
                for raw_line in text.split("\n"):
                    words = raw_line.split() or [raw_line]
                    current = ""
                    for word in words:
                        pieces = [word]
                        if stringWidth(word, font_name, font_size) > max_width:
                            pieces = []
                            piece = ""
                            for ch in word:
                                if stringWidth(piece + ch, font_name, font_size) <= max_width:
                                    piece += ch
                                else:
                                    if piece:
                                        pieces.append(piece)
                                    piece = ch
                            if piece:
                                pieces.append(piece)
                        for piece in pieces:
                            test = piece if not current else f"{current} {piece}"
                            if stringWidth(test, font_name, font_size) <= max_width:
                                current = test
                            else:
                                if current:
                                    lines.append(current)
                                current = piece
                    if current:
                        lines.append(current)
                return lines or [""]

            def draw_numbered_card_list(items, y_pos, *, accent=None, chip_prefix="", font_size=8.1):
                accent = accent or theme["primary"]
                for idx, item in enumerate(items or [], start=1):
                    if isinstance(item, (list, tuple)):
                        header = str(item[0] if item else "")
                        details = [str(x) for x in item[1:] if str(x or "").strip()]
                    else:
                        header = str(item or "")
                        details = []
                    if chip_prefix:
                        header = re.sub(r"^\d+\.\s*", "", header).strip()

                    chip_w = 46 if chip_prefix else 28
                    header_lines = wrap_report_text(header, CONTENT_W - chip_w - 56, font_size=font_size)
                    detail_lines = []
                    for detail in details:
                        bullet = detail if detail.lstrip().startswith(("-", "→")) else f"- {detail}"
                        detail_lines.extend(wrap_report_text(bullet, CONTENT_W - 42, font_size=7.2))

                    card_h = max(34, 18 + len(header_lines) * 10 + len(detail_lines) * 9 + (4 if detail_lines else 0))
                    y_pos = self.check_page(c, y_pos, threshold=card_h + 54, font_name=rf, font_size=font_size)
                    draw_soft_card(MARGIN, y_pos, CONTENT_W, card_h, radius=10, fill=theme["card"], stroke=theme["border"], shadow=True)

                    chip_text = f"{chip_prefix}{idx}" if chip_prefix else str(idx)
                    c.setFillColor(accent)
                    c.roundRect(MARGIN + 10, y_pos - 24, chip_w, 16, 8, fill=1, stroke=0)
                    c.setFillColor(colors.white)
                    c.setFont(rf, 7)
                    c.drawCentredString(MARGIN + 10 + chip_w / 2, y_pos - 18.5, chip_text)

                    text_x = MARGIN + chip_w + 20
                    text_y = y_pos - 14
                    c.setFillColor(theme["text"])
                    c.setFont(rf, font_size)
                    for line in header_lines:
                        c.drawString(text_x, text_y, line)
                        text_y -= 10

                    if detail_lines:
                        text_y -= 2
                        c.setFillColor(theme["muted"])
                        c.setFont(rf, 7.2)
                        for line in detail_lines:
                            c.drawString(MARGIN + 18, text_y, line)
                            text_y -= 9

                    c.setFillColor(theme["text"])
                    y_pos -= card_h + 9
                return y_pos

            def draw_insight_block_cards(blocks, y_pos, *, accent=None):
                return draw_numbered_card_list(blocks, y_pos, accent=accent or theme["primary"], chip_prefix="TOP ", font_size=8.1)

            def draw_risk_score_card(y_pos):
                card_h = 74
                y_pos = self.check_page(c, y_pos, threshold=card_h + 50, font_name=rf, font_size=8)
                draw_soft_card(MARGIN, y_pos, CONTENT_W, card_h, radius=13, fill=theme["card"], stroke=theme["border"], shadow=True)
                c.setFillColor(theme["primary"])
                c.roundRect(MARGIN + 14, y_pos - 28, 58, 18, 9, fill=1, stroke=0)
                c.setFillColor(colors.white)
                c.setFont(rf, 8)
                c.drawCentredString(MARGIN + 43, y_pos - 22, str(risk_level))

                c.setFillColor(theme["text"])
                c.setFont(rf, 18)
                c.drawString(MARGIN + 86, y_pos - 24, f"{risk_score}/100점")
                c.setFont(rf, 8)
                c.setFillColor(theme["muted"])
                c.drawString(MARGIN + 86, y_pos - 40, f"선택 기간 {selected_days}일 기준 종합 위험도")

                summary = (risk.get("factors", []) or ["주요 위험 요인을 기준으로 산정되었습니다."])[0]
                summary_lines = wrap_report_text(summary, CONTENT_W - 236, font_size=7.6)[:2]
                c.setFont(rf, 7.6)
                for idx, line in enumerate(summary_lines):
                    c.drawRightString(MARGIN + CONTENT_W - 16, y_pos - 22 - idx * 12, line)
                c.setFillColor(theme["text"])
                return y_pos - card_h - 18

            def summary_mini_card(x, y_pos, w, h, title, value, sub_text="", accent=None):
                accent = accent or colors.HexColor("#eef5ff")
                draw_soft_card(x, y_pos, w, h, radius=9, fill=accent, stroke=theme["border"], shadow=True)

                c.setFillColor(theme["primary_dark"])
                c.setFont(rf, 8)
                c.drawString(x + 10, y_pos - 15, str(title))

                c.setFillColor(theme["text"])
                c.setFont(rf, 18)
                c.drawString(x + 10, y_pos - 36, str(value))

                if sub_text:
                    c.setFillColor(theme["muted"])
                    c.setFont(rf, 7)
                    c.drawString(x + 10, y_pos - 49, str(sub_text))

                c.setFillColor(theme["text"])

            # ═══════════════════════════════════════════════════
            # PAGE 1 — 커버
            # ═══════════════════════════════════════════════════
            y = 810

            # 제목
            c.setFont(rf, 25)
            c.setFillColor(theme["text"])
            c.drawString(MARGIN, y, "보안 분석 보고서")
            c.setFillColor(theme["primary"])
            c.roundRect(MARGIN, y - 11, 74, 3, 1.5, fill=1, stroke=0)
            y -= 28
            c.setFont(rf, 9)
            c.setFillColor(theme["muted"])
            c.drawString(MARGIN, y, f"분석 기간: {start_dt.strftime('%Y-%m-%d %H:%M')} ~ {end_dt.strftime('%Y-%m-%d %H:%M')}")
            c.setFillColor(theme["text"])
            y -= 24

            # 리스크 카드
            risk_level = risk.get("level", "LOW")
            risk_score = risk.get("score", 0)
            rc = {
                "CRITICAL": colors.HexColor("#991b1b"),
                "HIGH": colors.HexColor("#dc2626"),
                "MEDIUM": colors.HexColor("#f59e0b"),
                "LOW": colors.HexColor("#10b981"),
            }.get(risk_level, colors.HexColor("#64748b"))
            draw_soft_card(MARGIN, y, CONTENT_W, 72, radius=12, fill=rc, stroke=rc, shadow=True)
            c.setFillGray(1)
            c.setFont(rf, 10)
            c.drawString(MARGIN + 16, y - 18, "종합 위험도")
            c.setFont(rf, 28)
            c.drawString(MARGIN + 16, y - 54, str(risk_level))
            c.setFont(rf, 24)
            c.drawRightString(MARGIN + CONTENT_W - 18, y - 54, f"Score: {risk_score}/100")
            c.setFillColor(theme["text"])
            y -= 88

            # 숫자 카드 3개
            card_data = [
                ("Endpoint Detection", metrics.get("endpoint_detection_count", 0), colors.HexColor("#1d4ed8")),
                ("Email Events",       metrics.get("email_count", 0),              colors.HexColor("#0f766e")),
                ("DLP Events",         metrics.get("dlp_count", 0),                colors.HexColor("#92400e")),
            ]
            cw_card = (CONTENT_W - 12) / 3
            for i, (ct, cv, cc) in enumerate(card_data):
                cx = MARGIN + i * (cw_card + 6)
                draw_soft_card(cx, y, cw_card, 70, radius=11, fill=cc, stroke=cc, shadow=True)
                c.setFillGray(1)
                c.setFont(rf, 8.2)
                c.drawString(cx + 11, y - 18, ct)
                c.setFont(rf, 27)
                c.drawString(cx + 11, y - 53, f"{int(cv):,}" if isinstance(cv, int) else str(cv))
                c.setFillColor(theme["text"])
            y -= 84

            # 교차 호스트 배너
            cross_hosts = metrics.get("cross_hosts", [])
            if cross_hosts:
                draw_soft_card(MARGIN, y, CONTENT_W, 48, radius=10, fill=colors.HexColor("#fff4d6"), stroke=colors.HexColor("#fde68a"), shadow=True)
                c.setFillColorRGB(0.65, 0.28, 0.0)
                c.setFont(rf, 9)
                c.drawString(MARGIN + 8, y - 14, "⚠  Detection + DLP 동시 발생 호스트")
                c.setFillGray(0.15)
                c.setFont(rf, 9)
                hosts_txt = ",   ".join(cross_hosts[:6])
                c.drawString(MARGIN + 8, y - 30, hosts_txt)
                c.setFillGray(0)
                y -= 56

            # 상관분석 미니 카드
            mini_gap = 6
            mini_w = (CONTENT_W - (mini_gap * 3)) / 4
            mini_h = 54

            summary_mini_card(
                MARGIN + (mini_w + mini_gap) * 0,
                y,
                mini_w,
                mini_h,
                "교차 호스트",
                f"{cross_host_count}",
                "Detection + DLP"
            )
            summary_mini_card(
                MARGIN + (mini_w + mini_gap) * 1,
                y,
                mini_w,
                mini_h,
                "교차 비율",
                f"{cross_host_ratio}%",
                "탐지 호스트 기준"
            )
            summary_mini_card(
                MARGIN + (mini_w + mini_gap) * 2,
                y,
                mini_w,
                mini_h,
                "동시 발생일",
                f"{overlap_day_count}",
                "Detection + DLP"
            )
            summary_mini_card(
                MARGIN + (mini_w + mini_gap) * 3,
                y,
                mini_w,
                mini_h,
                "3종 동시일",
                f"{triple_overlap_count}",
                "Det + Email + DLP"
            )

            y -= (mini_h + 14)

            repeated_cross_hosts_preview = metrics.get("repeated_cross_hosts_preview", [])

            if repeated_cross_count > 0:
                if repeated_cross_hosts_preview:
                    preview = ", ".join(repeated_cross_hosts_preview)
                    msg = f"반복 교차 호스트 {repeated_cross_count}개 확인 — {preview}"
                else:
                    msg = f"반복 교차 호스트 {repeated_cross_count}개 확인 — 단발성보다 반복형 패턴 점검 필요"

                words = str(msg).split()
                wrapped_msg = []
                current = ""

                for word in words:
                    test = word if not current else f"{current} {word}"
                    if c.stringWidth(test, rf, 8) <= (CONTENT_W - 16):
                        current = test
                    else:
                        if current:
                            wrapped_msg.append(current)
                        current = word

                if current:
                    wrapped_msg.append(current)

                if not wrapped_msg:
                    wrapped_msg = [msg]

                line_h = 10
                box_h = max(24, len(wrapped_msg) * line_h + 12)

                draw_soft_card(MARGIN, y + 2, CONTENT_W, box_h, radius=8, fill=colors.HexColor("#f1f6ff"), stroke=theme["border"], shadow=False)

                c.setFillColorRGB(0.28, 0.38, 0.56)
                c.setFont(rf, 8)

                text_y = y - 12
                for line in wrapped_msg:
                    c.drawString(MARGIN + 8, text_y, line)
                    text_y -= line_h

                c.setFillGray(0)

                # 박스 높이 + 아래 여백 확보
                y -= (box_h + 10)

            # 관리자 요약 — 핵심 항목만 카드형으로 요약
            y = section_bar("관리자 요약", y)

            manager_highlights = [
                f"총 이벤트: Detection {metrics.get('endpoint_detection_count', 0):,}건 / Email {metrics.get('email_count', 0):,}건 / DLP {metrics.get('dlp_count', 0):,}건",
            ]
            if metrics.get("top_host"):
                manager_highlights.append(
                    f"최다 탐지 호스트: {metrics.get('top_host')} ({metrics.get('top_host_count', 0):,}건)"
                )
            if metrics.get("top_rule"):
                manager_highlights.append(
                    f"주요 탐지 룰: {metrics.get('top_rule')} ({metrics.get('top_rule_count', 0):,}건)"
                )
            top_dlp_dept = metrics.get("top_dlp_dept", {}) or {}
            if top_dlp_dept:
                manager_highlights.append(
                    f"DLP 최다 부서: {top_dlp_dept.get('dept_name', '미분류')} ({top_dlp_dept.get('total', 0):,}건)"
                )
            if cross_host_count > 0:
                manager_highlights.append(
                    f"Detection + DLP 교차 호스트 {cross_host_count:,}개 — 우선 점검 대상"
                )
            if triple_overlap_count > 0:
                manager_highlights.append(
                    f"Detection·Email·DLP 3종 동시 발생일 {triple_overlap_count:,}일 확인"
                )

            # 과도한 문장형 설명 대신 한눈에 보는 결론 5개만 표시한다.
            y = draw_numbered_card_list(manager_highlights[:5], y, accent=theme["primary"], font_size=7.8)
            y -= 4

            # ═══════════════════════════════════════════════════
            # PAGE 2 — 그래프 (전체 너비) + 3개 테이블 나란히
            # ═══════════════════════════════════════════════════
            y = new_page()

            # 탐지 추이 그래프 — 전체 너비
            graph_path = os.path.join(REPORT_DIR, f"trend_{ts}.png")
            if detection_timeline:
                saved = self.create_report_trend_graph(detection_timeline, graph_path, font_name=rf)
                if saved:
                    c.setFont(rf, 13)
                    c.drawString(MARGIN, y, "탐지 추이")
                    y -= 8
                    GH = 220
                    c.drawImage(saved, MARGIN, y - GH, width=CONTENT_W, height=GH)
                    y -= GH + 20

            # 3개 테이블 나란히 (Rules | Hosts | Files)
            top_rules = metrics.get("top_rules", [])
            top_hosts = metrics.get("top_hosts", [])
            top_files = metrics.get("top_files", [])
            cross_host_ratio = metrics.get("cross_host_ratio", 0.0)
            overlap_day_count = metrics.get("overlap_day_count", 0)
            triple_overlap_count = metrics.get("triple_overlap_count", 0)
            repeated_cross_count = metrics.get("repeated_cross_host_count", 0)

            TW = (CONTENT_W - 16) / 3   # 각 테이블 전체 너비
            CNT_W = 30                   # Count 열 너비
            NAME_W = TW - CNT_W          # 이름 열 너비

            table_defs = [
                ("Top Rules",  top_rules, ["Rule",     "Cnt"], [NAME_W, CNT_W]),
                ("Top Hosts",  top_hosts, ["Hostname", "Cnt"], [NAME_W, CNT_W]),
                ("Top Files",  top_files, ["File",     "Cnt"], [NAME_W, CNT_W]),
            ]

            ty = y
            for ti, (title, data, hdrs, cws) in enumerate(table_defs):
                tx = MARGIN + ti * (TW + 8)
                c.setFont(rf, 11)
                c.drawString(tx, ty, title)
                rows = [(name, str(cnt)) for name, cnt in data] if data else [("No Data", "-")]
                mini_table(tx, ty - 10, hdrs, rows, cws, font_size=8)

            # 페이지 2 하단 상관분석 요약
            info_y = ty - 128

            c.setFillColorRGB(0.95, 0.97, 1.0)
            c.roundRect(MARGIN, info_y - 18, CONTENT_W, 22, 5, fill=1, stroke=0)
            c.setFillColorRGB(0.18, 0.32, 0.56)
            c.setFont(rf, 8)
            c.drawString(
                MARGIN + 8,
                info_y - 11,
                f"상관분석 요약 ①  Detection + DLP 교차 비율 {cross_host_ratio}% / 동시 발생일 {overlap_day_count}일"
            )

            c.setFillColorRGB(0.96, 0.97, 0.99)
            c.roundRect(MARGIN, info_y - 46, CONTENT_W, 22, 5, fill=1, stroke=0)
            c.setFillColorRGB(0.28, 0.38, 0.56)
            c.setFont(rf, 8)
            c.drawString(
                MARGIN + 8,
                info_y - 39,
                f"상관분석 요약 ②  3종 동시 발생일 {triple_overlap_count}일 / 반복 교차 호스트 {repeated_cross_count}개"
            )
            c.setFillGray(0)

            # ═══════════════════════════════════════════════════
            # PAGE 3 — 위험도 + 인사이트 + 권장 조치
            # ═══════════════════════════════════════════════════
            y = new_page()

            # 위험도 평가
            y = section_bar("위험도 평가", y)
            y = draw_risk_score_card(y)

            risk_factors = risk.get("factors", [])
            if risk_factors:
                c.setFont(rf, 9)
                c.setFillColor(theme["primary_dark"])
                c.drawString(MARGIN + 6, y, "핵심 위험 요인")
                c.setFillColor(theme["text"])
                y -= 14
                y = draw_numbered_card_list(risk_factors, y, accent=colors.HexColor("#f59e0b"), font_size=7.8)
                y -= 16

            # 점수 산정 기준
            if score_breakdown:
                y = self.check_page(c, y, threshold=145, font_name=rf, font_size=8)
                c.setFont(rf, 9)
                c.setFillColor(theme["primary_dark"])
                c.drawString(MARGIN + 6, y, f"점수 산정 기준 (선택 기간 {selected_days}일 기준)")
                c.setFillColor(theme["text"])
                y -= 12

                score_rows = []
                for item in score_breakdown:
                    label = str(item.get("label", ""))
                    item_score = item.get("score", 0)
                    max_score = item.get("max_score", "")
                    score_display = str(item.get("score_display", "") or (f"{item_score}/{max_score}" if max_score else f"+{item_score}"))
                    detail = str(item.get("detail", ""))
                    interpretation = str(item.get("interpretation", "") or "")
                    detail_text = f"{detail}\n→ {interpretation}" if interpretation else detail
                    score_rows.append([label, score_display, detail_text])

                y = mini_table_multiline(
                    MARGIN,
                    y,
                    ["평가 영역", "점수", "근거 및 해석"],
                    score_rows,
                    [118, 42, CONTENT_W - 160],
                    font_size=7.0,
                    line_height=8
                )
                y -= 8

            # 주요 인사이트는 별도 페이지에서 시작해 섹션 경계를 명확히 한다.
            y = new_page()
            y = section_bar("주요 인사이트", y)
            y = draw_numbered_card_list(insight_lines, y, accent=theme["primary"], font_size=7.8)

            # 권장 조치도 별도 페이지에서 시작한다.
            y = new_page()
            y = section_bar("권장 조치", y)
            y = draw_numbered_card_list(action_items, y, accent=colors.HexColor("#16a3a3"), font_size=7.8)

            # ═══════════════════════════════════════════════════
            # PAGE Detection — Detection 부서별 분석
            # ═══════════════════════════════════════════════════
            # Detection 전체 현황은 권장 조치 다음 새 페이지에서 시작한다.
            if det_dept_rank:
                y = new_page()

                # Detection 전체 현황 요약
                y = section_bar("Detection 전체 현황", y)
                c.setFont(rf, 10)
                total_det_cnt  = metrics.get("endpoint_detection_count", 0)
                unique_hosts   = metrics.get("unique_host_count", 0)
                unique_rules   = metrics.get("unique_rule_count", 0)
                unique_files   = metrics.get("unique_file_count", 0)
                c.drawString(
                    MARGIN + 6, y,
                    f"Endpoint Detection 총 {total_det_cnt:,}건  /  탐지 호스트 {unique_hosts}개  "
                    f"/  탐지 룰 {unique_rules}종  /  연관 파일 {unique_files}종"
                )
                y -= 18
                y = draw_distribution_card(
                    "Detection 부서 Top 5 시각화",
                    det_dept_rank,
                    y,
                    subtitle="탐지건수 기준 / 상위 부서 합계",
                )

                # Detection 부서별 현황 테이블
                y = section_bar("Detection 부서별 현황", y)

                det_summary_rows = []
                for item in det_dept_rank[:5]:
                    det_summary_rows.append([
                        item.get("dept_name", "미분류"),
                        str(item.get("total", 0)),
                        str(item.get("host_count", 0)),
                        str(item.get("user_count", 0)),
                    ])

                y = mini_table(
                    MARGIN, y,
                    ["부서", "탐지건수", "호스트수", "사용자수"],
                    det_summary_rows,
                    [220, 100, 100, 85],
                    font_size=8
                )
                y -= 10

                y = section_bar("Detection 상위 부서 상세", y)

                for di, item in enumerate(det_dept_rank[:5], start=1):
                    dept_name  = item.get("dept_name", "미분류")
                    total      = item.get("total", 0)
                    host_count = item.get("host_count", 0)
                    user_count = item.get("user_count", 0)
                    top_rules  = item.get("top_rules", [])
                    top_files  = item.get("top_files", [])
                    hosts_prev = item.get("hosts_preview", [])

                    y = self.check_page(c, y, threshold=160, font_name=rf, font_size=8)

                    y = draw_rank_header(
                        di,
                        dept_name,
                        f"탐지 {total:,}건 · 호스트 {host_count:,}개 · 사용자 {user_count:,}명",
                        y,
                    )

                    # Top Rules 미니 테이블
                    rule_rows = [
                        [r, str(cnt)]
                        for r, cnt in top_rules
                    ] or [["-", "0"]]
                    y = mini_table(
                        MARGIN, y,
                        ["주요 탐지 룰", "건수"],
                        rule_rows,
                        [430, 75],
                        font_size=7
                    )
                    y -= 4

                    # Top Files 미니 테이블
                    file_rows = [
                        [f, str(cnt)]
                        for f, cnt in top_files
                    ] or [["-", "0"]]
                    y = mini_table(
                        MARGIN, y,
                        ["주요 연관 파일", "건수"],
                        file_rows,
                        [430, 75],
                        font_size=7
                    )
                    y -= 4

                    # 호스트 미리보기
                    if hosts_prev:
                        c.setFont(rf, 7.5)
                        c.setFillColor(colors.HexColor("#374151"))
                        preview_text = "주요 호스트: " + ", ".join(hosts_prev)
                        c.drawString(MARGIN + 6, y, preview_text)
                        y -= 14

                    c.setStrokeColor(colors.HexColor("#dbeafe"))
                    c.setLineWidth(1.0)
                    c.line(MARGIN + 8, y + 2, MARGIN + CONTENT_W - 8, y + 2)
                    c.setStrokeColor(colors.black)
                    y -= 24

            # ═══════════════════════════════════════════════════
            # PAGE XDR — Email - XDR 부서별 분석
            # ═══════════════════════════════════════════════════
            if xdr_dept_rank:
                y = new_page()

                y = section_bar("Email - XDR 전체 현황", y)
                c.setFont(rf, 10)
                total_xdr_cnt = len(xdr_detections_report)
                c.drawString(
                    MARGIN + 6, y,
                    f"Email - XDR 총 {total_xdr_cnt:,}건  /  부서 {len(xdr_dept_rank)}개"
                )
                y -= 18
                y = draw_distribution_card(
                    "Email - XDR 부서 Top 5 시각화",
                    xdr_dept_rank,
                    y,
                    subtitle="탐지건수 기준 / 상위 부서 합계",
                )

                y = section_bar("Email - XDR 부서별 현황", y)

                xdr_summary_rows = []
                for item in xdr_dept_rank[:5]:
                    xdr_summary_rows.append([
                        item.get("dept_name", "미분류"),
                        str(item.get("total", 0)),
                        str(item.get("mailbox_count", 0)),
                        str(item.get("user_count", 0)),
                    ])

                y = mini_table(
                    MARGIN, y,
                    ["부서", "탐지건수", "메일박스수", "사용자수"],
                    xdr_summary_rows,
                    [220, 100, 100, 85],
                    font_size=8
                )
                y -= 10

                y = section_bar("Email - XDR 상위 부서 상세", y)

                for xi, item in enumerate(xdr_dept_rank[:5], start=1):
                    dept_name     = item.get("dept_name", "미분류")
                    total         = item.get("total", 0)
                    mailbox_count = item.get("mailbox_count", 0)
                    user_count    = item.get("user_count", 0)
                    top_rules     = item.get("top_rules", [])
                    top_iocs      = item.get("top_iocs", [])
                    mb_preview    = item.get("mailboxes_preview", [])

                    y = self.check_page(c, y, threshold=200, font_name=rf, font_size=8)

                    y = draw_rank_header(
                        xi,
                        dept_name,
                        f"탐지 {total:,}건 · 메일박스 {mailbox_count:,}개 · 사용자 {user_count:,}명",
                        y,
                    )

                    # Top Rules
                    rule_rows = [
                        [r, str(cnt)]
                        for r, cnt in top_rules
                    ] or [["-", "0"]]
                    y = mini_table(
                        MARGIN, y,
                        ["주요 탐지 룰", "건수"],
                        rule_rows,
                        [430, 75],
                        font_size=7
                    )
                    y -= 4

                    # Top IOCs
                    if top_iocs:
                        ioc_rows = [
                            [ioc_val, str(cnt)]
                            for ioc_val, cnt in top_iocs
                        ]
                        y = mini_table_multiline(
                            MARGIN, y,
                            ["주요 IOC", "건수"],
                            ioc_rows,
                            [430, 75],
                            font_size=6.8,
                            line_height=9
                        )
                        y -= 4

                    # 메일박스 미리보기
                    if mb_preview:
                        c.setFont(rf, 7.5)
                        c.setFillColor(colors.HexColor("#374151"))
                        c.drawString(MARGIN + 6, y, "주요 메일박스: " + ", ".join(mb_preview))
                        y -= 14

                    c.setStrokeColor(colors.HexColor("#dbeafe"))
                    c.setLineWidth(1.0)
                    c.line(MARGIN + 8, y + 2, MARGIN + CONTENT_W - 8, y + 2)
                    c.setStrokeColor(colors.black)
                    y -= 24

            # ═══════════════════════════════════════════════════
            # PAGE Outbound Mail — MailScreen 부서/결재 분석
            # ═══════════════════════════════════════════════════
            if outbound_rows:
                y = new_page()

                y = section_bar("Outbound Mail 전체 현황", y)
                c.setFont(rf, 10)
                outbound_total_count = len(outbound_rows)
                approval_total = sum(int(x.get("total", 0) or 0) for x in outbound_approval_rows)
                c.drawString(
                    MARGIN + 6,
                    y,
                    f"Outbound Mail 총 {outbound_total_count:,}건  /  성공 {outbound_success_count:,}건  "
                    f"/  실패 {outbound_fail_count:,}건  /  결재 {approval_total:,}건"
                )
                y -= 18

                y = draw_distribution_card(
                    "Outbound Mail 부서 Top 5 시각화",
                    outbound_dept_rank,
                    y,
                    subtitle="발송건수 기준 / 상위 부서 합계",
                )

                if outbound_approval_rows:
                    y = draw_distribution_card(
                        "Outbound Mail 결재 처리 현황",
                        outbound_approval_rows,
                        y,
                        label_key="status",
                        value_key="total",
                        subtitle="승인·반려·취소 건수",
                    )

                y = section_bar("Outbound Mail 부서별 현황", y)

                outbound_summary_rows = []
                for item in outbound_dept_rank[:5]:
                    outbound_summary_rows.append([
                        item.get("dept_name", "미분류"),
                        str(item.get("total", 0)),
                        str(item.get("success", 0)),
                        str(item.get("fail", 0)),
                        str(item.get("approved", 0)),
                        str(item.get("rejected", 0)),
                        str(item.get("canceled", 0)),
                    ])

                y = mini_table(
                    MARGIN,
                    y,
                    ["부서", "총건수", "성공", "실패", "승인", "반려", "취소"],
                    outbound_summary_rows,
                    [160, 62, 56, 56, 56, 56, 59],
                    font_size=7.3
                )
                y -= 10

                y = section_bar("Outbound Mail 결재 인사이트", y)
                approval_summary_rows = [[
                    "결재(승인)",
                    str(sum(int(x.get("approved", 0) or 0) for x in outbound_dept_rank)),
                    "승인 절차를 거쳐 외부 발송된 정책 대상 메일",
                ], [
                    "결재(반려)",
                    str(sum(int(x.get("rejected", 0) or 0) for x in outbound_dept_rank)),
                    "승인 단계에서 외부 발송이 반려된 메일",
                ], [
                    "결재(취소)",
                    str(sum(int(x.get("canceled", 0) or 0) for x in outbound_dept_rank)),
                    "요청 후 취소되어 실제 발송으로 이어지지 않은 메일",
                ]]
                y = mini_table_multiline(
                    MARGIN,
                    y,
                    ["결재 상태", "건수", "해석"],
                    approval_summary_rows,
                    [95, 50, CONTENT_W - 145],
                    font_size=7.2,
                    line_height=9
                )
                y -= 10

                y = section_bar("Outbound Mail 상위 부서 상세", y)

                for oi, item in enumerate(outbound_dept_rank[:5], start=1):
                    dept_name = item.get("dept_name", "미분류")
                    total = item.get("total", 0)
                    success = item.get("success", 0)
                    fail = item.get("fail", 0)
                    approved = item.get("approved", 0)
                    rejected = item.get("rejected", 0)
                    canceled = item.get("canceled", 0)

                    y = self.check_page(c, y, threshold=185, font_name=rf, font_size=8)
                    y = draw_rank_header(
                        oi,
                        dept_name,
                        f"총 {total:,}건 · 성공 {success:,}건 · 실패 {fail:,}건 · 승인 {approved:,}건 · 반려 {rejected:,}건 · 취소 {canceled:,}건",
                        y,
                    )

                    policy_rows = [[name, str(cnt)] for name, cnt in item.get("top_policies", [])] or [["-", "0"]]
                    y = mini_table(
                        MARGIN,
                        y,
                        ["주요 정책", "건수"],
                        policy_rows,
                        [430, 75],
                        font_size=7
                    )
                    y -= 4

                    receiver_rows = [[name, str(cnt)] for name, cnt in item.get("top_receivers", [])] or [["-", "0"]]
                    y = mini_table(
                        MARGIN,
                        y,
                        ["주요 수신 도메인", "건수"],
                        receiver_rows,
                        [430, 75],
                        font_size=7
                    )

                    c.setStrokeColor(colors.HexColor("#dbeafe"))
                    c.setLineWidth(1.0)
                    c.line(MARGIN + 8, y + 2, MARGIN + CONTENT_W - 8, y + 2)
                    c.setStrokeColor(colors.black)
                    y -= 24

            # ═══════════════════════════════════════════════════
            # PAGE 4 — DLP 부서 분석
            # ═══════════════════════════════════════════════════
            if dlp_dept_rank:
                y = new_page()

                # =========================
                # DLP 전체 상위 3개 분석
                # =========================
                y = section_bar("DLP 전체 유형 분석", y)

                c.setFont(rf, 10)
                c.drawString(
                    MARGIN + 6,
                    y,
                    f"DLP 전체 총 건수 : {dlp_total_count:,}건 (차단 {dlp_blocked_pct}%, 탐지 {dlp_allowed_pct}%)"
                )
                y -= 18

                overall_dlp_lines = self.build_dlp_overall_insight_lines(dlp_allowed_rows)
                y = draw_insight_block_cards(overall_dlp_lines, y, accent=theme["primary"])
                y -= 8

                # 목적지별 인사이트를 DLP 상세 앞쪽에 배치해, 주요 유출 경로를 먼저 확인하도록 구성한다.
                y = new_page()
                y = section_bar("DLP 목적지별 인사이트", y)
                dlp_destination_rows = self.build_dlp_destination_insight_rows(
                    dlp_rows,
                    dept_resolver=report_identity_resolver,
                )
                perf.mark("dlp destination insights build")
                y = self.draw_dlp_destination_insights(c, y, dlp_destination_rows, rf, MARGIN, CONTENT_W)
                perf.mark("dlp destination insights render")

                y = new_page()
                y = section_bar("DLP 부서별 현황", y)
                c.setFont(rf, 9)
                c.setFillColor(colors.HexColor("#374151"))
                c.drawString(MARGIN + 6, y, "DLP 이벤트가 집중된 상위 부서를 시각화하고, 허용/차단 및 사용자·PC 분포를 함께 확인합니다.")
                y -= 18
                y = draw_distribution_card(
                    "DLP 부서 Top 5 시각화",
                    dlp_dept_rank,
                    y,
                    subtitle="총건수 기준 / 허용·차단 포함",
                )

                dept_rows = []
                for item in dlp_dept_rank[:5]:
                    dept_rows.append([
                        item.get("dept_name", "미분류"),
                        str(item.get("total", 0)),
                        str(item.get("blocked", 0)),
                        f"{item.get('block_ratio', 0.0)}%",
                        str(item.get("user_count", 0)),
                        str(item.get("machine_count", 0)),
                    ])

                y = mini_table(
                    MARGIN,
                    y,
                    ["부서", "총건수", "차단", "차단율", "사용자수", "PC수"],
                    dept_rows,
                    [180, 70, 55, 65, 70, 65],
                    font_size=8
                )

                y -= 10
                y = section_bar("DLP 상위 부서 상세", y)

                inner_x = MARGIN
                inner_w = CONTENT_W

                # 부서명 바와 표 폭 완전히 동일
                detail_col_widths = [205, 120, inner_w - 205 - 120 - 36, 36]

                for dept_idx, item in enumerate(dlp_dept_rank[:5], start=1):
                    dept_name = item.get("dept_name", "미분류")
                    total = item.get("total", 0)
                    blocked = item.get("blocked", 0)
                    block_ratio = item.get("block_ratio", 0.0)
                    top_dest_group_rows = item.get("top_dest_group_rows", [])

                    y = self.check_page(c, y, threshold=150, font_name=rf, font_size=8)

                    allowed = max(total - blocked, 0)
                    y = draw_rank_header(
                        dept_idx,
                        dept_name,
                        f"총 {total:,}건 · 허용 {allowed:,}건 · 차단 {blocked:,}건 · 차단율 {block_ratio}% · 상세목록 허용 기준",
                        y,
                    )

                    dept_rows = []
                    if not top_dest_group_rows:
                        dept_rows.append(["-", "-", "-", "0"])
                    else:
                        for group_row in top_dest_group_rows[:3]:
                            dept_rows.append([
                                str(group_row.get("source_text", "-")),
                                str(group_row.get("target_text", "-")),
                                str(group_row.get("dest_detail", "-")),
                                str(group_row.get("count", 0)),
                            ])

                    y = mini_table_multiline(
                        inner_x,
                        y,
                        ["소스", "분류/대상유형", "목적지 세부정보", "건수"],
                        dept_rows,
                        detail_col_widths,
                        font_size=6.8,
                        line_height=8
                    )

                    c.setStrokeColor(colors.HexColor("#dbeafe"))
                    c.setLineWidth(1.0)
                    c.line(MARGIN + 8, y + 2, MARGIN + CONTENT_W - 8, y + 2)
                    c.setStrokeColor(colors.black)
                    y -= 26

                # DLP 상위 부서 상세 종료 후 인사이트/부록 페이지로 넘김
                y = new_page()

                y = section_bar("DLP 부서 분석 인사이트", y)
                dlp_insight_lines = self.build_dlp_dept_insight_lines(dlp_dept_rank, metrics)
                y = draw_insight_block_cards(dlp_insight_lines, y, accent=theme["primary"])

                if unclassified_user_counts:
                    y = self.check_page(c, y - 8, threshold=170, font_name=rf, font_size=8)
                    y = section_bar("DLP 미분류 사용자", y)

                    compact_rows = []
                    preview_users = unclassified_user_counts[:16]
                    for i in range(0, len(preview_users), 2):
                        left_name, left_cnt = preview_users[i]
                        left = f"{i + 1}. {left_name} ({left_cnt}건)"
                        right = ""
                        if i + 1 < len(preview_users):
                            right_name, right_cnt = preview_users[i + 1]
                            right = f"{i + 2}. {right_name} ({right_cnt}건)"
                        compact_rows.append([left, right])

                    y = mini_table_multiline(
                        MARGIN,
                        y,
                        ["미분류 사용자/호스트", "미분류 사용자/호스트"],
                        compact_rows,
                        [CONTENT_W / 2, CONTENT_W / 2],
                        font_size=7.2,
                        line_height=9
                    )

                    c.setFont(rf, 8)
                    c.setFillColor(colors.HexColor("#6b7280"))
                    if len(unclassified_user_counts) > len(preview_users):
                        c.drawString(
                            MARGIN,
                            y,
                            f"외 {len(unclassified_user_counts) - len(preview_users)}명 추가"
                        )
                        y -= 12
                    c.setFillColor(colors.black)


            draw_page_footer()
            c.save()
            perf.mark("pdf save")
            progress("저장 완료")
            perf.finish()
            return pdf_path

        except Exception:
            log.exception("generate_security_report_v2 failed")
            raise

    def check_page(self, c, y, threshold=120, font_name=None, font_size=10):
        if y < threshold:
            footer = getattr(c, "_smu_report_draw_footer", None)
            after_show_page = getattr(c, "_smu_report_after_show_page", None)
            if callable(footer):
                footer()
            c.showPage()
            if callable(after_show_page):
                after_show_page()
            if font_name:
                c.setFont(font_name, font_size)
            return 800
        return y

    def create_report_trend_graph(self, detection_timeline, graph_path, font_name="Helvetica"):
        if not detection_timeline:
            return None

        x_labels = list(sorted(detection_timeline.keys()))
        y_values = [detection_timeline[d] for d in x_labels]

        # The desktop bundle ships matplotlib.  The lightweight web backend
        # may not, so preserve the same graph slot with a dependency-free PNG
        # renderer rather than dropping the report page.
        if Figure is None:
            from PIL import Image, ImageDraw
            image = Image.new("RGB", (1344, 544), "white")
            draw = ImageDraw.Draw(image)
            left, top, right, bottom = 90, 55, 1305, 455
            for index in range(5):
                y = top + (bottom - top) * index / 4
                draw.line((left, y, right, y), fill="#dbeafe", width=2)
            maximum = max(max(y_values, default=0), 1)
            points = []
            for index, value in enumerate(y_values):
                x = left + (right - left) * index / max(len(y_values) - 1, 1)
                y = bottom - (bottom - top) * value / maximum
                points.append((x, y))
            if len(points) > 1:
                draw.line(points, fill="#0863e2", width=4)
            for (x, y), label, value in zip(points, x_labels, y_values):
                draw.ellipse((x - 6, y - 6, x + 6, y + 6), fill="#0863e2")
                draw.text((x - 12, y - 24), str(value), fill="#111827")
                draw.text((x - 22, bottom + 14), label[5:], fill="#667085")
            image.save(graph_path)
            return graph_path

        fig = Figure(figsize=(8.4, 3.4))
        ax = fig.add_subplot(111)

        x_positions = list(range(len(x_labels)))
        ax.plot(
            x_positions,
            y_values,
            marker="o",
            linewidth=2.2,
            markersize=5
        )

        ax.set_title("Detection Trend", fontsize=13, pad=12)
        ax.set_xlabel("Date", fontsize=10)
        ax.set_ylabel("Count", fontsize=10)

        ax.grid(True, linestyle="--", alpha=0.30)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)

        max_y = max(y_values) if y_values else 1
        ax.set_ylim(0, max(max_y * 1.25, 3))

        for i, value in enumerate(y_values):
            ax.annotate(
                str(value),
                xy=(x_positions[i], value),
                xytext=(0, 8),
                textcoords="offset points",
                ha="center",
                fontsize=9
            )

        step = max(1, len(x_labels) // 8) if len(x_labels) >= 10 else 1
        visible_labels = []
        for idx, label in enumerate(x_labels):
            if idx % step == 0 or idx == len(x_labels) - 1:
                visible_labels.append(label[5:] if len(label) >= 10 else label)
            else:
                visible_labels.append("")
        ax.set_xticks(x_positions)
        ax.set_xticklabels(visible_labels, rotation=35, ha="right", fontsize=9)

        ax.tick_params(axis="y", labelsize=9)

        fig.tight_layout()
        fig.savefig(graph_path, dpi=160)
        return graph_path

    def build_security_insight_metrics(self, endpoint_detections, emails, dlp_rows, detection_timeline=None, report_identity_resolver=None):
        rule_counter = Counter()
        host_counter = Counter()
        file_counter = Counter()

        det_host_day_counter = defaultdict(set)
        dlp_host_day_counter = defaultdict(set)

        for d in endpoint_detections:
            if not isinstance(d, dict):
                continue

            raw = d.get("rawData", {})
            if not isinstance(raw, dict):
                raw = {}

            dd = d.get("detectionDescription", {})
            rule = ""
            if isinstance(dd, dict):
                rule = str(dd.get("createdReasonId", "") or "").strip()
            if not rule:
                rule = str(d.get("detectionRule", "") or "").strip()

            hostname = str(raw.get("meta_hostname", "") or "").strip()
            file_name, _ = get_display_file_and_sha(raw)

            if rule:
                rule_counter[rule] += 1
            if hostname and hostname != "None":
                host_counter[hostname] += 1
            if file_name and file_name != "None":
                file_counter[file_name] += 1

            if hostname and hostname != "None":
                t = d.get("time")
                if t:
                    try:
                        dt = datetime.fromisoformat(str(t).replace("Z", "+00:00"))
                        kst = dt.astimezone(timezone(timedelta(hours=9)))
                        det_host_day_counter[hostname.lower()].add(kst.strftime("%Y-%m-%d"))
                    except Exception:
                        pass

        # ── Detection 부서별 통계 ──────────────────────────────────────
        det_dept_stats = defaultdict(lambda: {
            "total": 0,
            "rules": Counter(),
            "files": Counter(),
            "hosts": set(),
            "users": set(),
        })

        for d in endpoint_detections:
            if not isinstance(d, dict):
                continue

            raw = d.get("rawData", {})
            if not isinstance(raw, dict):
                raw = {}

            dd = d.get("detectionDescription", {})
            rule = ""
            if isinstance(dd, dict):
                rule = str(dd.get("createdReasonId", "") or "").strip()
            if not rule:
                rule = str(d.get("detectionRule", "") or "").strip()

            hostname = str(raw.get("meta_hostname", "") or "").strip()
            file_name, _ = get_display_file_and_sha(raw)

            identity = resolve_identity_by_hostname(hostname)
            dept_name = identity.get("dept_name", "미분류") or "미분류"

            stat = det_dept_stats[dept_name]
            stat["total"] += 1
            if rule:
                stat["rules"][rule] += 1
            if file_name and file_name != "None":
                stat["files"][file_name] += 1
            if hostname and hostname != "None":
                stat["hosts"].add(hostname)
            user_name = identity.get("user_name", "")
            if user_name and user_name != "None":
                stat["users"].add(user_name)

        det_dept_rows = []
        for dept_name, stat in det_dept_stats.items():
            det_dept_rows.append({
                "dept_name": dept_name,
                "total": stat["total"],
                "host_count": len(stat["hosts"]),
                "user_count": len(stat["users"]),
                "top_rules": stat["rules"].most_common(3),
                "top_files": stat["files"].most_common(3),
                "hosts_preview": sorted(list(stat["hosts"]))[:5],
            })

        det_dept_rank = sorted(det_dept_rows, key=lambda x: (-x["total"], x["dept_name"]))


        high_risk_email_count = 0
        email_date_set = set()

        for m in emails:
            if not isinstance(m, dict):
                continue

            reason = str(m.get("reason", "") or "").lower()
            if any(x in reason for x in ["malware", "virus", "phish", "spam", "suspicious", "impersonation"]):
                high_risk_email_count += 1

            received_at = m.get("receivedAt")
            if received_at:
                try:
                    dt = datetime.fromisoformat(str(received_at).replace("Z", "+00:00"))
                    kst = dt.astimezone(timezone(timedelta(hours=9)))
                    email_date_set.add(kst.strftime("%Y-%m-%d"))
                except Exception:
                    pass

        dlp_host_set = set()
        dlp_date_set = defaultdict(int)
        dlp_category_counter = Counter()

        dept_stats = defaultdict(lambda: {
            "total": 0,
            "blocked": 0,
            "allowed": 0,
            "users": set(),
            "machines": set(),
            "sources": Counter(),
            "target_types": Counter(),
            "dest_details": Counter(),
            "dest_groups": defaultdict(lambda: {
                "count": 0,
                "sources": Counter(),
                "target_types": Counter(),
            }),
        })

        unclassified_user_counter = Counter()

        for row in dlp_rows:
            if not isinstance(row, dict):
                continue

            machine_name = str(row.get("machine_name", "") or "").strip()
            event_name = str(row.get("event_id", "") or row.get("content_policy", "") or "").strip()

            source_name = str(
                row.get("filename", "")
                or row.get("source", "")
                or row.get("item_name", "")
                or "None"
            ).strip()

            target_type = str(
                row.get("destination_type", "")
                or row.get("target_type", "")
                or row.get("targetType", "")
                or "None"
            ).strip()

            dest_detail = str(
                row.get("destinationDetails", "")
                or row.get("destination_detail", "")
                or row.get("destination", "")
                or row.get("item_details", "")
                or "None"
            ).strip()

            dest_detail = normalize_report_destination(dest_detail)
            dest_category = classify_dlp_destination("", target_type, dest_detail)
            if dest_category:
                dlp_category_counter[dest_category] += 1

            if machine_name:
                dlp_host_set.add(machine_name.lower())

            t = str(row.get("eventtimelocal", "") or "").strip()
            if len(t) >= 10:
                day_key = t[:10]
                dlp_date_set[day_key] += 1
                if machine_name:
                    dlp_host_day_counter[machine_name.lower()].add(day_key)

            if report_identity_resolver:
                identity_info = report_identity_resolver(machine_name)
                endpoint_user_name = str(identity_info.get("user_name", "") or "")
                endpoint_user_id = str(identity_info.get("user_id", "") or "")
                user_type = str(identity_info.get("user_type", "") or "")
                dept_name = str(identity_info.get("dept_name", "미분류") or "미분류")
                dept_code = str(identity_info.get("dept_code", "") or "")
                if identity_info.get("is_unclassified"):
                    display_name = str(identity_info.get("display_name", "") or "").strip()
                    if display_name:
                        unclassified_user_counter[display_name] += 1
            else:
                endpoint_user_name, endpoint_user_id, user_type = get_endpoint_user_by_machine_name(machine_name)

                if user_type == "shared_pc":
                    dept_name = "공용PC"
                    dept_code = ""
                else:
                    dept_name, dept_code = get_org_info_by_user(endpoint_user_name, endpoint_user_id, machine_name)

                    if not dept_name or dept_name == "미분류":
                        manual_dept = get_report_exception_dept(endpoint_user_name)

                        if not manual_dept:
                            manual_dept = get_report_exception_dept(machine_name)
                        if manual_dept:
                            dept_name = manual_dept
                            dept_code = ""
                        else:
                            dept_name = "미분류"

                            display_name = str(endpoint_user_name or "").strip()
                            if not display_name:
                                display_name = f"[NO_USER] {machine_name}"

                            unclassified_user_counter[display_name] += 1

            stat = dept_stats[dept_name]
            stat["total"] += 1

            event_name_l = event_name.lower()
            is_blocked = any(x in event_name_l for x in ["block", "deny", "차단", "반려"])

            if is_blocked:
                stat["blocked"] += 1
            else:
                stat["allowed"] += 1

            if endpoint_user_name and endpoint_user_name != "공용PC":
                stat["users"].add(endpoint_user_name)
            if machine_name:
                stat["machines"].add(machine_name)
            if source_name and source_name != "None":
                stat["sources"][source_name] += 1
            if target_type and target_type != "None":
                stat["target_types"][target_type] += 1
            if dest_detail and dest_detail != "None":
                stat["dest_details"][dest_detail] += 1

                # 상세 리스트용 목적지 그룹은 허용건만 반영
                if not is_blocked:
                    group = stat["dest_groups"][dest_detail]
                    group["count"] += 1

                    if source_name and source_name != "None":
                        group["sources"][source_name] += 1

                    if target_type and target_type != "None":
                        group["target_types"][target_type] += 1

        if unclassified_user_counter:
            log.info(
                "[DLP UNCLASSIFIED USERS] %s",
                ", ".join([f"{name}({cnt})" for name, cnt in unclassified_user_counter.most_common()])
            )

        dlp_dept_rows = []
        for dept_name, stat in dept_stats.items():
            total = stat["total"]
            blocked = stat["blocked"]
            allowed = stat["allowed"]
            block_ratio = round((blocked / total) * 100, 1) if total else 0.0

            top_dest_group_rows = []

            for dest_name, group in sorted(
                stat["dest_groups"].items(),
                key=lambda x: (-x[1]["count"], x[0])
            )[:3]:
                top_sources = [
                    shorten_path_text(name, 46)
                    for name, _ in group["sources"].most_common(5)
                ]
                source_text = "\n".join(top_sources) if top_sources else "-"

                target_parts = [
                    f"{name} ({cnt})"
                    for name, cnt in group["target_types"].most_common(5)
                ]
                target_text = "\n".join(target_parts) if target_parts else "-"
                dest_category = classify_dlp_destination("", target_text, dest_name)
                target_text_with_category = f"{dest_category}\n{target_text}" if target_text != "-" else dest_category

                top_dest_group_rows.append({
                    "dest_detail": dest_name,
                    "count": group["count"],
                    "source_text": source_text,
                    "target_text": target_text_with_category,
                    "category": dest_category,
                })

            dlp_dept_rows.append({
                "dept_name": dept_name,
                "total": total,
                "blocked": blocked,
                "allowed": allowed,
                "block_ratio": block_ratio,
                "user_count": len(stat["users"]),
                "machine_count": len(stat["machines"]),
                "top_sources": stat["sources"].most_common(5),
                "top_target_types": stat["target_types"].most_common(5),
                "top_dest_details": stat["dest_details"].most_common(5),
                "top_dest_group_rows": top_dest_group_rows,
                "users_preview": list(sorted(stat["users"]))[:5],
                "machines_preview": list(sorted(stat["machines"]))[:5],
            })

        dlp_dept_rank = sorted(dlp_dept_rows, key=lambda x: (-x["total"], x["dept_name"]))
        dlp_dept_block_rank = sorted(dlp_dept_rows, key=lambda x: (-x["blocked"], x["dept_name"]))

        top_dlp_dept = dlp_dept_rank[0] if dlp_dept_rank else {}
        top_blocked_dlp_dept = dlp_dept_block_rank[0] if dlp_dept_block_rank else {}
        dlp_total_for_ratio = len(dlp_rows)
        dlp_blocked_count = sum(row.get("blocked", 0) for row in dlp_dept_rows)
        dlp_allowed_count = sum(row.get("allowed", 0) for row in dlp_dept_rows)
        dlp_blocked_ratio = round((dlp_blocked_count / dlp_total_for_ratio) * 100, 1) if dlp_total_for_ratio else 0.0
        dlp_allowed_ratio = round((dlp_allowed_count / dlp_total_for_ratio) * 100, 1) if dlp_total_for_ratio else 0.0
        dlp_top_dept_ratio = round((top_dlp_dept.get("total", 0) / dlp_total_for_ratio) * 100, 1) if dlp_total_for_ratio and top_dlp_dept else 0.0
        dlp_sensitive_categories = {
            "AI/생성형AI",
            "클라우드/오브젝트 스토리지",
            "메일/대용량 첨부",
            "메신저/고객상담",
            "소셜/미디어 업로드",
            "문서/PDF/이미지 변환",
            "디자인/협업 SaaS",
        }
        dlp_sensitive_category_count = sum(
            cnt for category, cnt in dlp_category_counter.items()
            if category in dlp_sensitive_categories
        )
        dlp_sensitive_category_ratio = round((dlp_sensitive_category_count / dlp_total_for_ratio) * 100, 1) if dlp_total_for_ratio else 0.0
        dlp_top_sensitive_categories = [
            (category, cnt)
            for category, cnt in dlp_category_counter.most_common()
            if category in dlp_sensitive_categories
        ][:5]

        detection_host_set = set([h.lower() for h in host_counter.keys() if h])
        cross_hosts = sorted(list(detection_host_set.intersection(dlp_host_set)))
        cross_host_count = len(cross_hosts)
        detection_host_count = len(detection_host_set)
        dlp_host_count = len(dlp_host_set)

        cross_host_ratio = round((cross_host_count / detection_host_count) * 100, 1) if detection_host_count else 0.0

        cross_host_rank = []
        for host in cross_hosts:
            det_cnt = 0
            for origin_host, cnt in host_counter.items():
                if str(origin_host).lower() == host:
                    det_cnt = cnt
                    break

            dlp_cnt = 0
            for row in dlp_rows:
                if not isinstance(row, dict):
                    continue
                mname = str(row.get("machine_name", "") or "").strip().lower()
                if mname == host:
                    dlp_cnt += 1

            cross_host_rank.append((host.upper(), det_cnt + dlp_cnt))

        cross_host_rank = sorted(cross_host_rank, key=lambda x: x[1], reverse=True)

        same_day_det_dlp = {}
        if detection_timeline is None:
            detection_timeline = {}

        for d in detection_timeline.keys():
            if d in dlp_date_set:
                same_day_det_dlp[d] = {
                    "detection_count": detection_timeline.get(d, 0),
                    "dlp_count": dlp_date_set.get(d, 0),
                }

        overlap_day_count = len(same_day_det_dlp)
        detection_day_count = len(detection_timeline)
        overlap_day_ratio = round((overlap_day_count / detection_day_count) * 100, 1) if detection_day_count else 0.0

        triple_overlap_days = sorted(list(set(same_day_det_dlp.keys()).intersection(email_date_set)))
        triple_overlap_count = len(triple_overlap_days)

        repeated_det_hosts = sorted([host for host, days in det_host_day_counter.items() if len(days) >= 2])
        repeated_dlp_hosts = sorted([host for host, days in dlp_host_day_counter.items() if len(days) >= 2])
        repeated_cross_hosts = sorted(list(set(repeated_det_hosts).intersection(repeated_dlp_hosts)))

        top_rule, top_rule_count = rule_counter.most_common(1)[0] if rule_counter else ("", 0)
        top_host, top_host_count = host_counter.most_common(1)[0] if host_counter else ("", 0)
        top_file, top_file_count = file_counter.most_common(1)[0] if file_counter else ("", 0)

        return {
            "endpoint_detection_count": len(endpoint_detections),
            "email_count": len(emails),
            "dlp_count": len(dlp_rows),

            "unique_host_count": len(host_counter),
            "unique_file_count": len(file_counter),
            "unique_rule_count": len(rule_counter),

            "high_risk_email_count": high_risk_email_count,

            "top_rule": top_rule,
            "top_rule_count": top_rule_count,
            "top_host": top_host,
            "top_host_count": top_host_count,
            "top_file": top_file,
            "top_file_count": top_file_count,

            "top_rules": rule_counter.most_common(5),
            "top_hosts": host_counter.most_common(5),
            "top_files": file_counter.most_common(5),

            "repeat_rule_exists": top_rule_count >= 3,
            "repeat_host_exists": top_host_count >= 3,
            "repeat_file_exists": top_file_count >= 3,

            "cross_hosts": cross_hosts,
            "cross_host_count": cross_host_count,
            "cross_host_ratio": cross_host_ratio,
            "cross_host_rank": cross_host_rank[:5],
            "detection_host_count": detection_host_count,
            "dlp_host_count": dlp_host_count,

            "same_day_det_dlp": same_day_det_dlp,
            "overlap_day_count": overlap_day_count,
            "overlap_day_ratio": overlap_day_ratio,
            "overlap_days_preview": sorted(list(same_day_det_dlp.keys()))[:5],

            "triple_overlap_days": triple_overlap_days,
            "triple_overlap_count": triple_overlap_count,
            "triple_overlap_days_preview": triple_overlap_days[:5],

            "repeated_det_hosts": repeated_det_hosts,
            "repeated_dlp_hosts": repeated_dlp_hosts,
            "repeated_cross_hosts": repeated_cross_hosts,
            "repeated_cross_host_count": len(repeated_cross_hosts),
            "repeated_cross_hosts_preview": repeated_cross_hosts[:5],

            "dlp_dept_rows": dlp_dept_rows,
            "dlp_dept_rank": dlp_dept_rank[:5],
            "dlp_dept_block_rank": dlp_dept_block_rank[:5],
            "top_dlp_dept": top_dlp_dept,
            "top_blocked_dlp_dept": top_blocked_dlp_dept,
            "dlp_dept_count": len(dlp_dept_rows),
            "dlp_allowed_count": dlp_allowed_count,
            "dlp_blocked_count": dlp_blocked_count,
            "dlp_allowed_ratio": dlp_allowed_ratio,
            "dlp_blocked_ratio": dlp_blocked_ratio,
            "dlp_top_dept_ratio": dlp_top_dept_ratio,
            "dlp_category_counts": dlp_category_counter.most_common(),
            "dlp_sensitive_category_count": dlp_sensitive_category_count,
            "dlp_sensitive_category_ratio": dlp_sensitive_category_ratio,
            "dlp_top_sensitive_categories": dlp_top_sensitive_categories,

            "unclassified_user_names": [name for name, _ in unclassified_user_counter.most_common()],
            "unclassified_user_counts": unclassified_user_counter.most_common(),
            "unclassified_user_count": len(unclassified_user_counter),

            # Detection 부서별
            "det_dept_rank": det_dept_rank,
        }

    def build_security_insight_lines(self, metrics):
        lines = []

        endpoint_count = metrics.get("endpoint_detection_count", 0)
        unique_hosts = metrics.get("unique_host_count", 0)
        unique_files = metrics.get("unique_file_count", 0)

        top_host = metrics.get("top_host", "")
        top_host_count = metrics.get("top_host_count", 0)

        top_rule = metrics.get("top_rule", "")
        top_rule_count = metrics.get("top_rule_count", 0)

        top_file = metrics.get("top_file", "")
        top_file_count = metrics.get("top_file_count", 0)

        email_count = metrics.get("email_count", 0)
        dlp_count = metrics.get("dlp_count", 0)

        cross_host_count = metrics.get("cross_host_count", 0)
        cross_host_ratio = metrics.get("cross_host_ratio", 0.0)
        overlap_day_count = metrics.get("overlap_day_count", 0)
        overlap_day_ratio = metrics.get("overlap_day_ratio", 0.0)
        triple_overlap_count = metrics.get("triple_overlap_count", 0)
        repeated_cross_host_count = metrics.get("repeated_cross_host_count", 0)

        cross_host_rank = metrics.get("cross_host_rank", [])
        overlap_days_preview = metrics.get("overlap_days_preview", [])
        triple_overlap_days_preview = metrics.get("triple_overlap_days_preview", [])
        repeated_cross_hosts_preview = metrics.get("repeated_cross_hosts_preview", [])

        if endpoint_count == 0 and email_count == 0 and dlp_count == 0:
            return ["분석 기간 동안 확인된 보안 이벤트가 없습니다."]

        if endpoint_count > 0 and top_host:
            ratio = round((top_host_count / endpoint_count) * 100, 1) if endpoint_count else 0
            lines.append(f"탐지는 '{top_host}' 호스트에 {top_host_count}건 집중 (전체의 {ratio}%).")

        if endpoint_count > 0 and top_rule:
            ratio = round((top_rule_count / endpoint_count) * 100, 1) if endpoint_count else 0
            lines.append(f"최다 룰 '{top_rule}' — {top_rule_count}건 (전체의 {ratio}%).")

        if endpoint_count > 0 and top_file:
            lines.append(f"최다 연관 파일 '{top_file}' — {top_file_count}건.")

        if unique_hosts > 0 or unique_files > 0:
            lines.append(f"탐지 발생 호스트 {unique_hosts}개, 연관 파일 {unique_files}종.")



        top_dlp_dept = metrics.get("top_dlp_dept", {})
        top_blocked_dlp_dept = metrics.get("top_blocked_dlp_dept", {})

        if dlp_count > 0 and top_dlp_dept:
            dept_name = top_dlp_dept.get("dept_name", "미분류")
            total = top_dlp_dept.get("total", 0)
            block_ratio = top_dlp_dept.get("block_ratio", 0.0)

            top_sources = top_dlp_dept.get("top_sources", [])
            top_target_types = top_dlp_dept.get("top_target_types", [])
            top_dest_details = top_dlp_dept.get("top_dest_details", [])

            parts = [f"DLP 최다 발생 부서는 '{dept_name}'이며 총 {total}건, 차단율 {block_ratio}%입니다."]

            if top_sources:
                parts.append(f"주요 파일은 {top_sources[0][0]}")
            if top_target_types:
                parts.append(f"주요 대상유형은 {top_target_types[0][0]}")
            if top_dest_details:
                parts.append(f"주요 목적지는 {top_dest_details[0][0]}")

            lines.append(" / ".join(parts) + ".")

        if dlp_count > 0 and top_blocked_dlp_dept:
            dept_name = top_blocked_dlp_dept.get("dept_name", "미분류")
            blocked = top_blocked_dlp_dept.get("blocked", 0)

            if blocked > 0:
                lines.append(f"DLP 차단 건수는 '{dept_name}' 부서가 가장 높으며 총 {blocked}건입니다.")

        if cross_host_count > 0:
            if cross_host_rank:
                preview = ", ".join([name for name, _ in cross_host_rank[:5]])
                lines.append(
                    f"Detection + DLP 교차 호스트 {cross_host_count}개, 탐지 호스트 대비 {cross_host_ratio}% 수준이며 "
                    f"주요 교차 호스트는 {preview}입니다."
                )
            else:
                lines.append(
                    f"Detection + DLP 교차 호스트 {cross_host_count}개, 탐지 호스트 대비 {cross_host_ratio}% 수준입니다."
                )

        if overlap_day_count > 0:
            if overlap_days_preview:
                day_preview = ", ".join(overlap_days_preview)
                lines.append(
                    f"Detection과 DLP는 총 {overlap_day_count}일 동시 발생했으며, "
                    f"Detection 발생일 기준 중첩률은 {overlap_day_ratio}%입니다. "
                    f"주요 발생일: {day_preview}"
                )
            else:
                lines.append(
                    f"Detection과 DLP는 총 {overlap_day_count}일 동시 발생했으며, "
                    f"Detection 발생일 기준 중첩률은 {overlap_day_ratio}%입니다."
                )

        if triple_overlap_count > 0:
            if triple_overlap_days_preview:
                day_preview = ", ".join(triple_overlap_days_preview)
                lines.append(
                    f"Detection·Email·DLP 3종 이벤트가 같은 날짜에 함께 발생한 날이 {triple_overlap_count}일 확인되었습니다. "
                    f"주요 날짜: {day_preview}"
                )
            else:
                lines.append(
                    f"Detection·Email·DLP 3종 이벤트가 같은 날짜에 함께 발생한 날이 {triple_overlap_count}일 확인되었습니다."
                )

        if repeated_cross_host_count > 0:
            if repeated_cross_hosts_preview:
                host_preview = ", ".join(repeated_cross_hosts_preview)
                lines.append(
                    f"Detection과 DLP가 반복적으로 함께 나타난 호스트가 {repeated_cross_host_count}개이며, "
                    f"주요 호스트는 {host_preview}입니다."
                )
            else:
                lines.append(
                    f"Detection과 DLP가 반복적으로 함께 나타난 호스트가 {repeated_cross_host_count}개로, "
                    f"단발성보다 반복형 패턴 점검이 필요합니다."
                )

        if email_count > 0 and endpoint_count > 0:
            lines.append(
                f"Email {email_count}건과 Endpoint 탐지가 같은 기간 내 함께 존재하여, "
                f"유입 이벤트와 단말 행위 간 시간적 연계 여부 확인이 필요합니다."
            )

        if dlp_count > 0:
            lines.append(f"DLP {dlp_count}건 — 파일 반출 이벤트의 반복성 및 탐지 시점 중첩 여부 확인 필요.")

        top_blocked_dlp_dept = metrics.get("top_blocked_dlp_dept", {})
        if top_blocked_dlp_dept:
            dept_name = top_blocked_dlp_dept.get("dept_name", "미분류")
            blocked = top_blocked_dlp_dept.get("blocked", 0)
            if blocked > 0:
                lines.append(
                    f"DLP 차단 건수는 '{dept_name}' 부서가 가장 높으며 총 {blocked}건입니다."
                )

        return lines

    def build_security_risk_assessment(self, metrics, selected_days=1):
        """Build a weighted, explainable 100-point report risk score.

        The score intentionally separates event volume from spread, DLP exposure,
        cross-signal correlation, and attribution quality so the PDF can explain
        not only "how many events" occurred but also why the selected period is
        considered risky.
        """
        factors = []
        score_breakdown = []
        selected_days = max(int(selected_days or 1), 1)

        endpoint_count = metrics.get("endpoint_detection_count", 0)
        email_count = metrics.get("email_count", 0)
        high_risk_email_count = metrics.get("high_risk_email_count", 0)
        dlp_count = metrics.get("dlp_count", 0)

        unique_host_count = metrics.get("unique_host_count", 0)
        top_rule_count = metrics.get("top_rule_count", 0)
        top_host_count = metrics.get("top_host_count", 0)
        cross_host_count = metrics.get("cross_host_count", 0)
        cross_host_ratio = metrics.get("cross_host_ratio", 0.0)
        triple_overlap_count = metrics.get("triple_overlap_count", 0)
        repeated_cross_host_count = metrics.get("repeated_cross_host_count", 0)
        unclassified_user_count = metrics.get("unclassified_user_count", 0)

        dlp_allowed_ratio = metrics.get("dlp_allowed_ratio", 0.0)
        dlp_sensitive_category_count = metrics.get("dlp_sensitive_category_count", 0)
        dlp_sensitive_category_ratio = metrics.get("dlp_sensitive_category_ratio", 0.0)
        dlp_top_dept_ratio = metrics.get("dlp_top_dept_ratio", 0.0)
        dlp_top_sensitive_categories = metrics.get("dlp_top_sensitive_categories", []) or []

        avg_endpoint_per_day = round(endpoint_count / selected_days, 1)
        avg_email_per_day = round(email_count / selected_days, 1)
        avg_high_risk_email_per_day = round(high_risk_email_count / selected_days, 1)
        avg_dlp_per_day = round(dlp_count / selected_days, 1)
        top_host_ratio = round((top_host_count / endpoint_count) * 100, 1) if endpoint_count else 0.0
        high_risk_email_ratio = round((high_risk_email_count / email_count) * 100, 1) if email_count else 0.0

        def band(value, rules):
            for threshold, points in rules:
                if value >= threshold:
                    return points
            return 0

        def add_breakdown(label, score, max_score, detail, interpretation):
            if score <= 0:
                return
            score_breakdown.append({
                "label": label,
                "score": score,
                "max_score": max_score,
                "score_display": f"{score}/{max_score}",
                "detail": detail,
                "interpretation": interpretation,
            })
            factors.append(f"{label} {score}/{max_score} — {interpretation}")

        # 1) Endpoint 위협 활동: 단말 탐지의 양, 확산 범위, 반복 룰, 특정 호스트 집중도를 함께 본다. (25점)
        endpoint_score = 0
        endpoint_score += band(avg_endpoint_per_day, [(30, 10), (10, 6), (1, 3)])
        endpoint_score += band(unique_host_count, [(20, 7), (10, 5), (3, 3), (1, 1)])
        endpoint_score += band(top_rule_count, [(100, 5), (50, 4), (10, 2), (3, 1)])
        endpoint_score += band(top_host_ratio, [(50, 3), (30, 2), (15, 1)])
        endpoint_score = min(endpoint_score, 25)
        endpoint_interpretation = (
            "탐지량·호스트 확산·반복 룰이 함께 높아 단말 우선 분석이 필요합니다."
            if endpoint_score >= 18 else
            "반복 또는 확산 징후가 있어 상위 호스트/룰 중심 확인이 필요합니다."
            if endpoint_score >= 9 else
            "단말 탐지는 제한적이나 발생 내역은 추적 대상입니다."
        )
        add_breakdown(
            "Endpoint 위협 활동",
            endpoint_score,
            25,
            f"총 {endpoint_count:,}건 / {selected_days}일 = 일평균 {avg_endpoint_per_day:,}건, "
            f"탐지 호스트 {unique_host_count:,}개, 최다 룰 {top_rule_count:,}건, 최다 호스트 집중도 {top_host_ratio}%",
            endpoint_interpretation,
        )

        # 2) Email 유입 위험: 고위험 메일의 절대량과 메일 이벤트 내 비중을 함께 본다. (20점)
        email_score = 0
        email_score += band(avg_high_risk_email_per_day, [(30, 10), (10, 7), (3, 4), (1, 2)])
        email_score += band(avg_email_per_day, [(300, 4), (100, 3), (30, 2), (1, 1)])
        email_score += band(high_risk_email_ratio, [(50, 4), (20, 3), (10, 2), (1, 1)])
        if email_count > 0 and endpoint_count > 0:
            email_score += 2
        email_score = min(email_score, 20)
        email_interpretation = (
            "고위험 메일 유입량과 비중이 높아 유입 후 단말 행위 연계 점검이 필요합니다."
            if email_score >= 14 else
            "의심 메일이 지속 확인되어 발신자·URL·첨부파일 기준 샘플링이 필요합니다."
            if email_score >= 7 else
            "메일 유입 위험은 낮지만 Endpoint 이벤트와 같은 기간 존재 여부를 유지 관찰합니다."
        )
        add_breakdown(
            "Email 유입 위험",
            email_score,
            20,
            f"Email 총 {email_count:,}건 / 일평균 {avg_email_per_day:,}건, "
            f"고위험 {high_risk_email_count:,}건 / 일평균 {avg_high_risk_email_per_day:,}건, 고위험 비중 {high_risk_email_ratio}%",
            email_interpretation,
        )

        # 3) DLP 반출 노출: DLP 발생량, 허용 비중, 민감 목적지 분류, 부서 집중도를 함께 본다. (30점)
        dlp_score = 0
        dlp_score += band(avg_dlp_per_day, [(1000, 8), (500, 6), (100, 4), (1, 2)])
        dlp_score += band(dlp_allowed_ratio, [(95, 7), (80, 5), (50, 3), (1, 1)]) if dlp_count else 0
        dlp_score += band(dlp_sensitive_category_ratio, [(50, 8), (25, 6), (10, 4), (1, 2)])
        dlp_score += band(dlp_top_dept_ratio, [(50, 5), (30, 3), (15, 2)])
        dlp_score += band(unclassified_user_count, [(30, 2), (10, 1)])
        dlp_score = min(dlp_score, 30)
        sensitive_preview = ", ".join([f"{name} {cnt:,}건" for name, cnt in dlp_top_sensitive_categories[:3]]) or "민감 목적지 분류 없음"
        dlp_interpretation = (
            "허용 반출과 민감 목적지 사용이 함께 높아 파일 샘플링 및 정책 예외 검토가 필요합니다."
            if dlp_score >= 21 else
            "반출 이벤트가 지속 확인되어 상위 부서·목적지·파일명 기준 점검이 필요합니다."
            if dlp_score >= 10 else
            "DLP 노출은 제한적이나 허용 이벤트는 목적지 기준으로 추적합니다."
        )
        add_breakdown(
            "DLP 반출 노출",
            dlp_score,
            30,
            f"총 {dlp_count:,}건 / 일평균 {avg_dlp_per_day:,}건, 허용 비중 {dlp_allowed_ratio}%, "
            f"민감 목적지 {dlp_sensitive_category_count:,}건({dlp_sensitive_category_ratio}%), 상위 부서 집중도 {dlp_top_dept_ratio}% / {sensitive_preview}",
            dlp_interpretation,
        )

        # 4) 상관/연계 위험: Detection과 DLP, Email이 같은 호스트/날짜에서 겹치는지를 본다. (20점)
        correlation_score = 0
        correlation_score += band(cross_host_count, [(20, 8), (10, 6), (5, 4), (1, 2)])
        correlation_score += band(cross_host_ratio, [(50, 5), (30, 3), (10, 1)])
        correlation_score += band(triple_overlap_count, [(5, 4), (2, 3), (1, 2)])
        correlation_score += band(repeated_cross_host_count, [(10, 3), (1, 2)])
        correlation_score = min(correlation_score, 20)
        correlation_interpretation = (
            "탐지·메일·DLP가 같은 기간/호스트에서 겹쳐 유입부터 반출까지의 연계 가능성을 우선 확인해야 합니다."
            if correlation_score >= 14 else
            "교차 호스트 또는 동시 발생일이 확인되어 시계열 상관분석이 필요합니다."
            if correlation_score >= 6 else
            "상관 징후는 제한적이나 교차 호스트는 추적 목록에 유지합니다."
        )
        add_breakdown(
            "상관/연계 위험",
            correlation_score,
            20,
            f"Detection+DLP 교차 호스트 {cross_host_count:,}개({cross_host_ratio}%), "
            f"3종 동시 발생일 {triple_overlap_count:,}일, 반복 교차 호스트 {repeated_cross_host_count:,}개",
            correlation_interpretation,
        )

        # 5) 식별/운영 품질: 미분류 사용자가 많을수록 실제 조치 지연 위험이 커진다. (5점)
        quality_score = min(band(unclassified_user_count, [(30, 5), (10, 3), (1, 1)]), 5)
        quality_interpretation = (
            "미분류 사용자가 많아 부서 책임자 지정과 후속 조치가 지연될 수 있습니다."
            if quality_score >= 3 else
            "일부 미분류 사용자가 있어 조직 매핑 보완이 필요합니다."
            if quality_score > 0 else
            "사용자/부서 식별 품질은 위험도에 큰 영향을 주지 않습니다."
        )
        add_breakdown(
            "식별/운영 품질",
            quality_score,
            5,
            f"DLP 미분류 사용자 {unclassified_user_count:,}명",
            quality_interpretation,
        )

        score = min(sum(item.get("score", 0) for item in score_breakdown), 100)
        if score >= 80:
            level = "CRITICAL"
        elif score >= 60:
            level = "HIGH"
        elif score >= 30:
            level = "MEDIUM"
        else:
            level = "LOW"

        if not factors:
            factors.append("전반적으로 특이 위험 요소는 제한적입니다.")

        return {
            "level": level,
            "score": score,
            "max_score": 100,
            "factors": factors,
            "score_breakdown": score_breakdown,
            "selected_days": selected_days,
            "avg_endpoint_per_day": avg_endpoint_per_day,
            "avg_high_risk_email_per_day": avg_high_risk_email_per_day,
            "avg_dlp_per_day": avg_dlp_per_day,
        }

    def build_security_action_items(self, metrics, risk):
        actions = []

        if metrics.get("repeat_rule_exists"):
            actions.append("반복 발생 탐지 룰에 대해 정상 행위 기반 여부를 검토합니다.")

        if metrics.get("repeat_host_exists"):
            actions.append("탐지 집중 호스트에 대해 사용자 행위 및 실행 프로그램을 재확인합니다.")

        if metrics.get("repeat_file_exists"):
            actions.append("반복 탐지 파일에 대해 정상 프로그램 여부 및 예외처리 필요성을 검토합니다.")

        if metrics.get("high_risk_email_count", 0) > 0:
            actions.append("고위험 이메일 이벤트 — 발신자, 수신자, URL, 첨부파일 기준 추가 분석을 진행합니다.")

        cross_host_rank = metrics.get("cross_host_rank", [])
        cross_host_count = metrics.get("cross_host_count", 0)
        repeated_cross_host_count = metrics.get("repeated_cross_host_count", 0)
        triple_overlap_count = metrics.get("triple_overlap_count", 0)

        if cross_host_count > 0:
            if cross_host_rank:
                preview = ", ".join([name for name, _ in cross_host_rank[:3]])
                actions.append(f"Detection + DLP 교차 호스트({preview})를 우선 점검합니다.")
            else:
                actions.append("Detection + DLP 교차 호스트를 우선 점검합니다.")

        repeated_cross_hosts_preview = metrics.get("repeated_cross_hosts_preview", [])
        triple_overlap_days_preview = metrics.get("triple_overlap_days_preview", [])

        if repeated_cross_host_count > 0:
            if repeated_cross_hosts_preview:
                preview = ", ".join(repeated_cross_hosts_preview)
                actions.append(f"반복 교차 호스트({preview})의 업무성 행위 여부를 우선 확인합니다.")
            else:
                actions.append("반복적으로 Detection과 DLP가 함께 발생한 호스트군의 업무성 행위 여부를 우선 확인합니다.")

        if triple_overlap_count > 0:
            if triple_overlap_days_preview:
                preview = ", ".join(triple_overlap_days_preview)
                actions.append(f"3종 이벤트 동시 발생일({preview})을 기준으로 전후 행위를 교차 확인합니다.")
            else:
                actions.append("Detection·Email·DLP 3종 이벤트가 겹친 날짜를 기준으로 전후 행위를 교차 확인합니다.")

        if metrics.get("dlp_count", 0) > 0:
            actions.append("파일 반출 이벤트 — 업무 목적 여부 및 반복 업로드 패턴을 확인합니다.")

            top_blocked_dlp_dept = metrics.get("top_blocked_dlp_dept", {})
            if top_blocked_dlp_dept:
                dept_name = top_blocked_dlp_dept.get("dept_name", "미분류")
                blocked = top_blocked_dlp_dept.get("blocked", 0)
                if blocked > 0:
                    actions.append(
                        f"DLP 차단 상위 부서('{dept_name}')에 대해 주요 파일, 업로드 대상, 사용자 반복 여부를 우선 점검합니다."
                    )
        if str(risk.get("level", "LOW")) in {"CRITICAL", "HIGH"}:
            actions.append("고위험 구간 — 반복 이벤트 우선 상세 분석 및 선제 대응을 수행합니다.")

        return actions

    def build_security_manager_summary(self, metrics, risk):
        endpoint_count = metrics.get("endpoint_detection_count", 0)
        email_count = metrics.get("email_count", 0)
        dlp_count = metrics.get("dlp_count", 0)

        top_host = metrics.get("top_host", "")
        top_host_count = metrics.get("top_host_count", 0)

        top_rule = metrics.get("top_rule", "")
        top_rule_count = metrics.get("top_rule_count", 0)

        cross_host_count = metrics.get("cross_host_count", 0)
        cross_host_ratio = metrics.get("cross_host_ratio", 0.0)
        overlap_day_count = metrics.get("overlap_day_count", 0)
        triple_overlap_count = metrics.get("triple_overlap_count", 0)
        repeated_cross_host_count = metrics.get("repeated_cross_host_count", 0)

        level = str(risk.get("level", "LOW"))

        parts = [
            f"선택 기간 동안 Detection {endpoint_count}건, Email {email_count}건, DLP {dlp_count}건이 확인되었습니다."
        ]

        if top_host:
            parts.append(f"상위 호스트는 {top_host} ({top_host_count}건).")

        if top_rule:
            parts.append(f"주요 탐지 룰은 {top_rule} ({top_rule_count}건).")
        top_dlp_dept = metrics.get("top_dlp_dept", {})
        if top_dlp_dept:
            dept_name = top_dlp_dept.get("dept_name", "미분류")
            total = top_dlp_dept.get("total", 0)
            parts.append(f"DLP는 {dept_name} 부서에서 가장 많이 발생했으며 {total}건입니다.")
        if cross_host_count > 0:
            parts.append(
                f"Detection과 DLP가 함께 확인된 교차 호스트는 {cross_host_count}개이며, "
                f"탐지 호스트 대비 {cross_host_ratio}% 수준입니다."
            )

        if overlap_day_count > 0:
            parts.append(f"Detection과 DLP는 총 {overlap_day_count}일 동시 발생했습니다.")

        if triple_overlap_count > 0:
            parts.append(f"Detection·Email·DLP 3종 이벤트가 같은 날짜에 함께 발생한 날은 {triple_overlap_count}일입니다.")

        if repeated_cross_host_count > 0:
            parts.append(f"반복적으로 Detection과 DLP가 함께 나타난 호스트는 {repeated_cross_host_count}개입니다.")

        if email_count > 0 and endpoint_count > 0:
            parts.append("메일 이벤트와 Endpoint 탐지가 같은 기간 내 함께 존재하여 유입 후 행위 연계 가능성을 점검 대상으로 포함합니다.")

        level_text = {"CRITICAL": "치명 위험", "HIGH": "고위험", "MEDIUM": "중위험", "LOW": "저위험"}.get(level, "저위험")
        parts.append(f"종합 판단: {level_text} 수준.")

        return " ".join(parts)

    def get_dlp_destination_category_comment(self, category, top_destination):
        dest = str(top_destination or "주요 목적지")
        comments = {
            "AI/생성형AI": f"{dest} 중심의 AI 서비스 사용이 확인됩니다. 업로드 파일에 개인정보·계약·영업자료가 포함됐는지 우선 점검하세요.",
            "문서/PDF/이미지 변환": f"{dest} 등 외부 변환 서비스 사용이 반복됩니다. 변환 대상 문서의 민감정보 포함 여부 확인이 필요합니다.",
            "메일/대용량 첨부": f"{dest} 대용량 첨부 사용이 확인됩니다. 정상 업무 여부와 외부 수신자 적정성을 파일명 기준으로 확인하세요.",
            "클라우드/오브젝트 스토리지": f"{dest} 스토리지 목적지가 확인됩니다. SaaS 임시 버킷 또는 외부 저장소 업로드 가능성을 점검하세요.",
            "메신저/고객상담": f"{dest} 메신저·고객상담 첨부 목적지가 확인됩니다. 고객응대 자료와 외부 공유 파일을 구분해 검토하세요.",
            "디자인/협업 SaaS": f"{dest} 디자인·협업 도구 사용이 확인됩니다. 시안·이미지·제안서 등 외부 업로드 파일을 확인하세요.",
            "소셜/미디어 업로드": f"{dest} 소셜·미디어 업로드 목적지가 확인됩니다. 공개 채널 업로드 여부와 파일 성격을 점검하세요.",
            "쇼핑몰/판매자/파트너 포털": f"{dest} 판매자·파트너 포털 목적지가 확인됩니다. 업무상 제출 파일인지 확인하고 반복 업로드를 점검하세요.",
            "채용/HR": f"{dest} 채용·HR 목적지가 확인됩니다. 이력서·증빙자료 등 개인정보 포함 파일 처리 적정성을 확인하세요.",
            "광고/마케팅/분석": f"{dest} 광고·마케팅·분석 목적지가 확인됩니다. 캠페인 소재나 고객 데이터 업로드 여부를 확인하세요.",
            "업무/공공/금융 포털": f"{dest} 업무·공공·금융 포털 목적지가 확인됩니다. 정상 제출 업무인지와 첨부파일의 민감도 확인이 필요합니다.",
            "내부 파일서버": f"{dest} 내부 파일서버 접근이 확인됩니다. 외부 반출보다 내부 공유 경로 사용 맥락을 확인하세요.",
            "로컬/앱 임시파일": f"{dest} 로컬 또는 앱 임시 경로가 확인됩니다. 실제 전송 대상과 원본 앱을 추가 확인하세요.",
            "IP 직접 접속": f"{dest} IP 직접 접속 목적지가 확인됩니다. 서비스 식별과 업무 관련성을 우선 확인하세요.",
        }
        return comments.get(category, f"{dest} 목적지 사용이 확인됩니다. 반복 발생 부서와 파일명을 기준으로 업무 적정성을 검토하세요.")
