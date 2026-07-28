"""Security PDF report ported from the legacy PyQt report workflow.

The web report intentionally keeps the desktop report's structure: executive
cover, trend/top analysis, risk and recommendations, and solution/department
appendices.  Rendering lives in the backend so the browser only downloads the
finished artifact.
"""
from __future__ import annotations

import os
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path
from typing import Any, Callable

from backend.services.dashboard import DashboardService, SERIES_NAMES


class ReportService:
    COLORS = {
        "Detection - XDR": "#0863e2", "Email - XDR": "#18b6df",
        "Inbound Mail": "#16a394", "Outbound Mail": "#e83e8c", "File": "#ef9400",
    }

    def __init__(self, root: Path):
        self.root = root
        self.dashboard = DashboardService(root)

    @staticmethod
    def _font() -> tuple[str, str]:
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        candidates = [
            Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts/malgun.ttf",
            Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts/malgunbd.ttf",
            Path("/usr/share/fonts/truetype/nanum/NanumGothic.ttf"),
            Path("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"),
        ]
        regular = next((path for path in candidates if path.exists() and "bold" not in path.name.lower() and "malgunbd" not in path.name.lower()), None)
        bold = next((path for path in candidates if path.exists() and ("bold" in path.name.lower() or "malgunbd" in path.name.lower())), regular)
        if regular:
            try:
                pdfmetrics.registerFont(TTFont("SMUReport", str(regular)))
                pdfmetrics.registerFont(TTFont("SMUReportBold", str(bold or regular)))
                return "SMUReport", "SMUReportBold"
            except Exception:
                pass
        return "Helvetica", "Helvetica-Bold"

    @staticmethod
    def _dept(row: dict[str, Any]) -> str:
        return str(row.get("dept") or row.get("sender_dept") or "미분류").strip() or "미분류"

    @staticmethod
    def _risk(totals: dict[str, int], rows: dict[str, list[tuple]]) -> dict[str, Any]:
        dlp_rows = [row for _id, _raw, row in rows.get("File", [])]
        blocked = sum(1 for row in dlp_rows if "차단" in str(row.get("event", "")))
        score = min(100, round(
            min(totals.get("Detection - XDR", 0), 300) / 6
            + min(totals.get("Email - XDR", 0), 200) / 10
            + min(max(len(dlp_rows) - blocked, 0), 1000) / 40
        ))
        level = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 35 else "LOW"
        return {"score": score, "level": level, "blocked": blocked, "allowed": max(len(dlp_rows) - blocked, 0)}

    def build(self, start: date, end: date, progress: Callable[[str], None] = lambda _message: None) -> dict[str, Any]:
        if start > end:
            raise ValueError("start date must not be after end date")
        progress("보고서 데이터 로딩 중")
        data = self.dashboard.summary(start, end)
        rows = self.dashboard._rows(start, end)
        risk = self._risk(data["totals"], rows)
        progress("보안 분석 및 부서별 집계 중")

        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.pdfgen import canvas
        from reportlab.platypus import Paragraph, Table, TableStyle

        output = self.root / "reports" / f"Security_Report_{start}_{end}.pdf"
        output.parent.mkdir(parents=True, exist_ok=True)
        regular, bold = self._font()
        pdf = canvas.Canvas(str(output), pagesize=A4)
        width, height = A4
        margin = 16 * mm
        content_width = width - 2 * margin
        page = 0
        page_bg = colors.HexColor("#f8fbff")
        primary = colors.HexColor("#174ea6")
        text = colors.HexColor("#111827")
        muted = colors.HexColor("#667085")
        border = colors.HexColor("#bfdbfe")
        styles = {
            "cell": ParagraphStyle("cell", fontName=regular, fontSize=7.2, leading=9, textColor=text),
            "head": ParagraphStyle("head", fontName=bold, fontSize=7.2, leading=9, textColor=colors.white),
        }

        def new_page(title: str | None = None) -> float:
            nonlocal page
            if page:
                pdf.setFont(regular, 7); pdf.setFillColor(muted); pdf.drawCentredString(width / 2, 10 * mm, f"- {page} -")
                pdf.showPage()
            page += 1
            pdf.setFillColor(page_bg); pdf.rect(0, 0, width, height, fill=1, stroke=0)
            if title:
                pdf.setFillColor(text); pdf.setFont(bold, 20); pdf.drawString(margin, height - margin, title)
                pdf.setFillColor(colors.HexColor("#0863e2")); pdf.roundRect(margin, height - margin - 7, 74, 3, 1.5, fill=1, stroke=0)
                return height - margin - 25
            return height - margin

        def section(title: str, y: float) -> float:
            if y < 38 * mm:
                y = new_page(title)
            pdf.setFillColor(primary); pdf.roundRect(margin, y - 18, content_width, 22, 7, fill=1, stroke=0)
            pdf.setFillColor(colors.white); pdf.setFont(bold, 10); pdf.drawString(margin + 10, y - 11, title)
            return y - 32

        def table(headers: list[str], body: list[list[Any]], widths: list[float], y: float, max_rows: int = 12) -> float:
            body = body[:max_rows] or [["-"] + ["0"] * (len(headers) - 1)]
            values = [[Paragraph(str(value), styles["head"]) for value in headers]]
            values += [[Paragraph(str(value if value not in (None, "") else "-"), styles["cell"]) for value in row] for row in body]
            widget = Table(values, colWidths=widths, repeatRows=1)
            widget.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0863e2")),
                ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                ("GRID", (0, 0), (-1, -1), .45, border),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]))
            _w, h = widget.wrapOn(pdf, content_width, height)
            if y - h < 22 * mm:
                y = new_page("분석 상세 (계속)")
            widget.drawOn(pdf, margin, y - h)
            return y - h - 12

        def stat_cards(cards: list[tuple[str, Any, str]], y: float) -> float:
            gap = 6; card_width = (content_width - gap * (len(cards) - 1)) / len(cards)
            for index, (label, value, color) in enumerate(cards):
                x = margin + index * (card_width + gap)
                pdf.setFillColor(colors.HexColor(color)); pdf.roundRect(x, y - 65, card_width, 65, 10, fill=1, stroke=0)
                pdf.setFillColor(colors.white); pdf.setFont(regular, 8); pdf.drawString(x + 10, y - 17, label)
                pdf.setFont(bold, 23); pdf.drawString(x + 10, y - 49, f"{value:,}" if isinstance(value, int) else str(value))
            return y - 80

        def distribution(title: str, values: list[tuple[str, int]], y: float) -> float:
            y = section(title, y); values = values[:8]
            maximum = max((count for _name, count in values), default=1)
            for name, count in values:
                if y < 25 * mm: y = new_page(f"{title} (계속)")
                pdf.setFillColor(text); pdf.setFont(regular, 7); pdf.drawString(margin + 4, y, str(name)[:30])
                bar_x = margin + 160; bar_width = max(2, (content_width - 205) * count / maximum)
                pdf.setFillColor(colors.HexColor("#dbeafe")); pdf.roundRect(bar_x, y - 2, content_width - 205, 8, 4, fill=1, stroke=0)
                pdf.setFillColor(colors.HexColor("#0863e2")); pdf.roundRect(bar_x, y - 2, bar_width, 8, 4, fill=1, stroke=0)
                pdf.setFillColor(text); pdf.setFont(bold, 7); pdf.drawRightString(margin + content_width, y, f"{count:,}")
                y -= 17
            return y - 8

        # Page 1: same executive-cover intent as the desktop report.
        y = new_page()
        pdf.setFillColor(text); pdf.setFont(bold, 25); pdf.drawString(margin, y, "보안 분석 보고서")
        pdf.setFillColor(colors.HexColor("#0863e2")); pdf.roundRect(margin, y - 11, 74, 3, 1.5, fill=1, stroke=0)
        y -= 28; pdf.setFillColor(muted); pdf.setFont(regular, 9); pdf.drawString(margin, y, f"분석 기간: {start} 00:00 ~ {end} 23:59")
        y -= 22
        risk_color = {"CRITICAL": "#991b1b", "HIGH": "#dc2626", "MEDIUM": "#f59e0b", "LOW": "#10b981"}[risk["level"]]
        pdf.setFillColor(colors.HexColor(risk_color)); pdf.roundRect(margin, y - 72, content_width, 72, 12, fill=1, stroke=0)
        pdf.setFillColor(colors.white); pdf.setFont(regular, 10); pdf.drawString(margin + 16, y - 18, "종합 위험도")
        pdf.setFont(bold, 28); pdf.drawString(margin + 16, y - 54, risk["level"]); pdf.setFont(bold, 23); pdf.drawRightString(margin + content_width - 18, y - 54, f"Score: {risk['score']}/100")
        y -= 88
        y = stat_cards([("Endpoint Detection", data["totals"]["Detection - XDR"], "#1d4ed8"), ("Email Events", data["totals"]["Email - XDR"] + data["totals"]["Inbound Mail"], "#0f766e"), ("DLP Events", data["totals"]["File"], "#92400e")], y)
        y = section("관리자 요약", y)
        summary_rows = [
            ["자산 현황", f"PC {data['endpoints']['pc']:,}대 / Server {data['endpoints']['server']:,}대 / 부서 {data['organization']['departments']:,}개 / 사용자 {data['organization']['users']:,}명"],
            ["탐지 현황", f"Detection {data['totals']['Detection - XDR']:,}건 / Email XDR {data['totals']['Email - XDR']:,}건 / Inbound {data['totals']['Inbound Mail']:,}건"],
            ["외부 전송", f"Outbound {data['totals']['Outbound Mail']:,}건 / DLP {data['totals']['File']:,}건 (차단 {risk['blocked']:,}건, 허용·탐지 {risk['allowed']:,}건)"],
        ]
        y = table(["구분", "핵심 요약"], summary_rows, [100, content_width - 100], y)

        # Page 2: trend and top analysis.
        progress("탐지 추이 및 Top 분석 렌더링 중")
        y = new_page("탐지 추이 및 Top 분석")
        y = section("솔루션별 일간 이벤트 추이", y)
        chart_h = 165; chart_x = margin + 28; chart_w = content_width - 42; chart_bottom = y - chart_h
        all_values = [value for series in data["trend"]["series"].values() for value in series]
        maximum = max(1, max(all_values, default=0))
        for grid in range(5):
            gy = chart_bottom + chart_h * grid / 4; pdf.setStrokeColor(colors.HexColor("#dbeafe")); pdf.line(chart_x, gy, chart_x + chart_w, gy)
        dates = data["trend"]["dates"]
        for name in SERIES_NAMES:
            values = data["trend"]["series"][name]; pdf.setStrokeColor(colors.HexColor(self.COLORS[name])); pdf.setLineWidth(2)
            points = []
            for i, value in enumerate(values):
                x = chart_x + (chart_w * i / max(len(values) - 1, 1)); py = chart_bottom + chart_h * value / maximum; points.append((x, py))
            for first, second in zip(points, points[1:]): pdf.line(*first, *second)
            for x, py in points: pdf.setFillColor(colors.HexColor(self.COLORS[name])); pdf.circle(x, py, 2.5, fill=1, stroke=0)
        pdf.setFont(regular, 6.5); pdf.setFillColor(muted)
        for i, day in enumerate(dates): pdf.drawCentredString(chart_x + chart_w * i / max(len(dates) - 1, 1), chart_bottom - 12, day[5:])
        y = chart_bottom - 28
        y = table(["순위", "Hostname", "Rule", "Sender IP"], [[rank + 1, *[(data["top"][key][rank][0] + f" ({data['top'][key][rank][1]})") if rank < len(data["top"][key]) else "-" for key in ("hosts", "rules", "senders")]] for rank in range(6)], [35, 135, 215, content_width - 385], y)

        # Page 3: risk factors and actions.
        y = new_page("위험도 평가 및 권장 조치")
        comparison_rows = []
        for name in SERIES_NAMES:
            day = data["comparison"][name]["day"]; month = data["comparison"][name]["month"]
            comparison_rows.append([name, "신규" if day is None else f"{day:+.1f}%", "신규" if month is None else f"{month:+.1f}%", data["totals"][name]])
        y = section("전일·전월 대비", y); y = table(["솔루션", "전일 대비", "전월 대비", "기간 합계"], comparison_rows, [150, 100, 100, content_width - 350], y)
        y = section("주요 위험 요인", y)
        factors = [
            ["Endpoint", f"Endpoint 탐지 {data['totals']['Detection - XDR']:,}건. 상위 호스트와 반복 룰을 우선 확인하십시오."],
            ["Email", f"Email XDR {data['totals']['Email - XDR']:,}건, Inbound {data['totals']['Inbound Mail']:,}건. 악성 발신지와 수신자를 교차 점검하십시오."],
            ["DLP", f"파일 이벤트 {data['totals']['File']:,}건 중 차단 {risk['blocked']:,}건. 허용·탐지 이벤트의 목적지를 검토하십시오."],
        ]
        y = table(["영역", "분석"], factors, [90, content_width - 90], y)
        y = section("권장 조치", y)
        y = table(["우선순위", "조치 항목"], [["P1", "상위 반복 탐지 호스트의 프로세스 계보, 해시 및 네트워크 IOC를 확인"], ["P1", "Email XDR 악성 URL·첨부파일과 Inbound 발신 IP 차단 여부 검토"], ["P2", "DLP 허용 이벤트 중 외부 저장소·웹 업로드·USB 목적지 집중 사용자 점검"], ["P2", "Outbound 결재·정책 우회 및 대량 외부 수신 도메인 검토"]], [70, content_width - 70], y)

        # Solution appendices mirror the legacy report's departmental pages.
        configs = [
            ("Detection", "Detection - XDR", "hostname", "rule"),
            ("Email - XDR", "Email - XDR", "mailbox", "rule"),
            ("Inbound Mail", "Inbound Mail", "to", "reason"),
            ("Outbound Mail", "Outbound Mail", "senderEmail", "policy"),
            ("DLP", "File", "computer", "destination"),
        ]
        for title, source, subject_field, detail_field in configs:
            source_rows = [row for _id, _raw, row in rows[source]]
            if not source_rows:
                continue
            progress(f"{title} 상세 분석 렌더링 중")
            y = new_page(f"{title} 분석")
            dept_counter = Counter(self._dept(row) for row in source_rows)
            y = distribution(f"{title} 부서 Top 8", dept_counter.most_common(8), y)
            y = section(f"{title} 부서별 현황", y)
            dept_details: dict[str, dict[str, Any]] = defaultdict(lambda: {"subjects": set(), "details": Counter()})
            for row in source_rows:
                item = dept_details[self._dept(row)]; subject = str(row.get(subject_field) or "None")
                if subject != "None": item["subjects"].add(subject)
                detail = str(row.get(detail_field) or "None")
                if detail != "None": item["details"][detail] += 1
            dept_rows = []
            for dept, count in dept_counter.most_common(10):
                top_detail = dept_details[dept]["details"].most_common(1)
                dept_rows.append([dept, count, len(dept_details[dept]["subjects"]), f"{top_detail[0][0]} ({top_detail[0][1]})" if top_detail else "-"])
            y = table(["부서", "총 건수", "사용자/자산", "주요 항목"], dept_rows, [145, 70, 85, content_width - 300], y)
            y = section(f"{title} 상위 이벤트 상세", y)
            detail_counter = Counter(str(row.get(detail_field) or "None") for row in source_rows)
            y = table(["순위", "항목", "건수"], [[index + 1, name, count] for index, (name, count) in enumerate(detail_counter.most_common(12))], [45, content_width - 115, 70], y)

        pdf.setFillColor(muted); pdf.setFont(regular, 7); pdf.drawCentredString(width / 2, 10 * mm, f"- {page} -")
        pdf.save()
        progress("보안 분석 보고서 저장 완료")
        return {"path": str(output), "filename": output.name, "pages": page}
