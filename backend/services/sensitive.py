import ast
import hashlib
import re
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any

from backend.services.transfers import TransferService


FILE_CATEGORIES = {
    "이직 / 취업": ["이력서", "resume", "자기소개서", "포트폴리오", "경력기술서", "입사지원"],
    "개인 증빙 / 금융": ["신분증", "주민등록", "운전면허", "여권", "통장사본", "계좌번호", "급여명세서", "연말정산"],
    "계약 / 법무": ["계약서", "사업자등록증", "채권", "변제계획서"],
    "메신저 수신 파일": ["kakaotalk", "카카오톡 받은 파일", "nateon", "wechat", "telegram", "discord"],
    "개인 사진 / 영상": ["개인사진", "가족사진", "웨딩사진", "증명사진", "셀카", "selfie", "여행사진"],
    "비용 / 정산": ["영수증", "비용정산", "법카", "receipt", "invoice"],
}
SITE_CATEGORIES = {
    "개인 클라우드 / 파일전송": ["drive.google.com", "dropbox.com", "onedrive.live.com", "wetransfer.com", "send-anywhere.com", "mega.nz"],
    "원격접속 / 파일전송 도구": ["teamviewer.com", "anydesk.com", "rustdesk.com", "winscp.net", "filezilla-project.org", "ngrok.com"],
    "금융 / 가상자산": ["kbstar.com", "shinhan.com", "wooribank.com", "upbit.com", "bithumb.com", "binance.com", "coinbase.com"],
    "채용 / 이직": ["saramin.co.kr", "jobkorea.co.kr", "wanted.co.kr", "linkedin.com", "jobplanet.co.kr"],
    "문서 변환 / PDF 도구": ["ilovepdf.com", "smallpdf.com", "pdf24.org", "convertio.co", "cloudconvert.com"],
    "SNS / 커뮤니티": ["instagram.com", "facebook.com", "x.com", "twitter.com", "tiktok.com", "discord.com", "telegram.org"],
}
URL_PATTERN = re.compile(r"(?:https?://)?(?:www\.)?([a-z0-9.-]+\.[a-z]{2,})(?:[/\w?&=.%+#:@~-]*)?", re.IGNORECASE)


def legacy_specs(project_root: Path, variable_name: str, fallback: dict[str, list[str]]) -> dict[str, list[str]]:
    source_path = project_root / "uimain_window.py"
    if not source_path.exists():
        return fallback

    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    result = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == variable_name for target in node.targets):
            try:
                result = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                continue
    if not isinstance(result, list):
        return fallback

    specs: dict[str, list[str]] = {}
    for item in result:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            continue
        category, keywords = item
        if isinstance(keywords, list):
            specs[str(category)] = [str(keyword) for keyword in keywords]
    return specs or fallback


class SensitiveService:
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.transfers = TransferService(project_root)
        self.file_categories = legacy_specs(project_root, "SENSITIVE_FILE_CATEGORY_SPECS", FILE_CATEGORIES)
        self.site_categories = legacy_specs(project_root, "SENSITIVE_SITE_CATEGORY_SPECS", SITE_CATEGORIES)

    @staticmethod
    def classify(text: str, specs: dict[str, list[str]]) -> tuple[str, list[str]] | None:
        lowered = text.lower()
        for category, keywords in specs.items():
            hits = sorted({keyword for keyword in keywords if keyword.lower() in lowered}, key=str.lower)
            if hits:
                return category, hits
        return None

    @staticmethod
    def bounds(records: list[Path]) -> tuple[date, date] | None:
        dates = []
        for path in records:
            match = re.search(r"\d{4}-\d{2}-\d{2}", path.name)
            if match:
                try:
                    dates.append(date.fromisoformat(match.group()))
                except ValueError:
                    pass
        return (min(dates), max(dates)) if dates else None

    def _transfer_records(self, kind: str):
        directory = self.transfers.dlp_dir if kind == "dlp" else self.transfers.outbound_dir
        paths = list(directory.glob("*")) if directory.exists() else []
        bounds = self.bounds(paths)
        if bounds is None:
            return []
        collector = self.transfers._collect_dlp if kind == "dlp" else self.transfers._collect_outbound
        return collector(*bounds)[0]

    def file_records(self, sources: set[str]) -> list[dict[str, Any]]:
        output = []
        for source, kind in (("DLP", "dlp"), ("Outbound Mail", "outbound")):
            if source not in sources:
                continue
            for record_id, raw, row in self._transfer_records(kind):
                value = row["source"] if kind == "dlp" else row["attachment"]
                classified = self.classify(f"{value} {raw}", self.file_categories)
                if not classified:
                    continue
                category, hits = classified
                name = str(value).replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] or "None"
                output.append({"id": f"file-{record_id}", "source": source, "name": name, "category": category, "keywords": hits, "user": row["username"] if kind == "dlp" else row["senderName"], "dept": row["dept"], "time": row["time"] if kind == "dlp" else row["date"], "path": value, "event": row["event"] if kind == "dlp" else row["sendResult"], "raw": raw})
        return output

    def site_records(self) -> list[dict[str, Any]]:
        output = []
        for record_id, raw, row in self._transfer_records("dlp"):
            text = " ".join([row["destination"], row["destinationDetail"], str(raw)])
            hosts = {match.group(1).lower().strip(".") for match in URL_PATTERN.finditer(text)}
            for host in hosts:
                classified = self.classify(host, self.site_categories)
                if not classified:
                    continue
                category, hits = classified
                output.append({"id": f"site-{record_id}-{hashlib.sha1(host.encode()).hexdigest()[:8]}", "source": "DLP", "site": host, "url": row["destination"], "category": category, "keywords": hits, "user": row["username"], "dept": row["dept"], "time": row["time"], "machine": row["computer"], "event": row["event"], "raw": raw})
        return output

    def query(self, kind: str, category: str, keyword: str, sources: set[str], offset: int, limit: int) -> dict[str, Any]:
        records = self.file_records(sources) if kind == "files" else self.site_records() if kind == "sites" else None
        if records is None:
            raise ValueError(f"Unsupported sensitive kind: {kind}")
        counts = Counter(record["category"] for record in records)
        if category and category != "전체":
            records = [record for record in records if record["category"] == category]
        search = keyword.strip().lower()
        if search:
            records = [record for record in records if search in " ".join(str(value) for key, value in record.items() if key != "raw").lower()]
        records.sort(key=lambda record: record["time"], reverse=True)
        total = len(records)
        public = [{key: value for key, value in record.items() if key != "raw"} for record in records[offset:offset + limit]]
        return {"items": public, "total": total, "offset": offset, "limit": limit, "categoryCounts": dict(counts)}

    def detail(self, kind: str, record_id: str, sources: set[str]) -> dict[str, Any] | None:
        if kind == "files":
            records = self.file_records(sources)
        elif kind == "sites":
            records = self.site_records()
        else:
            raise ValueError(f"Unsupported sensitive kind: {kind}")
        return next((record for record in records if record["id"] == record_id), None)
