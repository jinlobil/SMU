"""Shared dependency-free XLSX writer for all SMU exports."""
from __future__ import annotations

import json
import re
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, fromstring, tostring
from zipfile import ZIP_DEFLATED, ZipFile

from backend.services.office_encryption import staged_output_path


MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
ILLEGAL_XML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
INVALID_SHEET_CHARS = re.compile(r"[\\/*?:\[\]]")

# Appended styles leave the existing export/report style indices intact.
LEDGER_STYLES = {"header": 10, "body": 11, "running": 12, "stop": 13,
                 "sophos": 14, "inbound": 15, "outbound": 16, "center": 17, "allow": 26, "deny": 27, "neutral": 28}
LEDGER_TOP_STYLE_OFFSET = 8


def _ledger_styles(styles: str) -> bytes:
    root = fromstring(styles)
    def tag(name): return f"{{{MAIN_NS}}}{name}"
    fonts, fills, borders, xfs = (root.find(tag(name)) for name in ("fonts", "fills", "borders", "cellXfs"))
    font_ids = []
    for color, bold in [("FF000000", False), ("FF172B4D", True)]:
        font_ids.append(len(fonts))
        font = SubElement(fonts, tag("font"))
        if bold: SubElement(font, tag("b"))
        SubElement(font, tag("color"), {"rgb": color})
        SubElement(font, tag("sz"), {"val": "11"})
        SubElement(font, tag("name"), {"val": "Calibri"})
    fill_ids = []
    for color in ["FF17365D", "FFFFFFFF", "FF228B46", "FFC62828", "FF2463B5", "FFDDEBF7", "FFFCE4D6", "FFE2F0D9", "FFFCE0E0", "FFF2F2F2"]:
        fill_ids.append(len(fills))
        fill = SubElement(fills, tag("fill"))
        pattern = SubElement(fill, tag("patternFill"), {"patternType": "solid"})
        SubElement(pattern, tag("fgColor"), {"rgb": color})
        SubElement(pattern, tag("bgColor"), {"indexed": "64"})
    top_border = len(borders)
    border = SubElement(borders, tag("border"))
    for edge in ["left", "right", "top", "bottom"]:
        SubElement(border, tag(edge), {"style": "medium" if edge == "top" else "thin"})
    # Header, body, state, antivirus, directions, merged body, then top-edge variants.
    models = [(1, fill_ids[0], True), (font_ids[0], fill_ids[1], False),
              (1, fill_ids[2], True), (1, fill_ids[3], True), (1, fill_ids[4], True),
              (font_ids[1], fill_ids[5], True), (font_ids[1], fill_ids[6], True),
              (font_ids[0], fill_ids[1], True)]
    for border_id in [1, top_border]:
        for font_id, fill_id, center in models:
            xf = SubElement(xfs, tag("xf"), {"numFmtId": "0", "fontId": str(font_id), "fillId": str(fill_id),
                "borderId": str(border_id), "xfId": "0", "applyFont": "1", "applyFill": "1", "applyBorder": "1", "applyAlignment": "1"})
            alignment = {"vertical": "center", "wrapText": "1"}
            if center: alignment["horizontal"] = "center"
            SubElement(xf, tag("alignment"), alignment)
    for fill_id in fill_ids[7:]:
        xf = SubElement(xfs, tag("xf"), {"numFmtId": "0", "fontId": str(font_ids[0]), "fillId": str(fill_id),
            "borderId": "1", "xfId": "0", "applyFont": "1", "applyFill": "1", "applyBorder": "1", "applyAlignment": "1"})
        SubElement(xf, tag("alignment"), {"vertical": "center", "wrapText": "1"})
    for node in [fonts, fills, borders, xfs]: node.set("count", str(len(node)))
    return b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' + tostring(root, encoding="utf-8")


def semantic_cell_style(column: str, header: str, value: object) -> int:
    """Color known semantic columns only; names/descriptions never imply status."""
    names = {re.sub(r"[^a-z0-9가-힣]", "", name.casefold()) for name in (column, header)}
    text = _text(value).strip().casefold()
    if names & {"action", "firewallaction", "동작"}:
        if text in {"allow", "accept"}: return LEDGER_STYLES["allow"]
        if text in {"drop", "reject", "deny"}: return LEDGER_STYLES["deny"]
    if names & {"direction", "방향"}:
        if text == "inbound": return LEDGER_STYLES["inbound"]
        if text == "outbound": return LEDGER_STYLES["outbound"]
    if names & {"antivirus", "av", "백신", "백신설치현황", "securityproduct", "product", "vendor"} and text == "sophos":
        return LEDGER_STYLES["sophos"]
    if names & {"status", "state", "result", "deliveryresult", "sendresult", "ztna", "상태", "전송결과", "ztna설치상태"}:
        if text in {"running", "활성", "success", "succeeded", "성공", "정상", "enabled", "enable", "설치"}: return LEDGER_STYLES["running"]
        if text in {"stop", "stopped", "stopping", "terminated", "비활성", "fail", "failed", "failure", "실패", "disabled", "disable", "미설치"}: return LEDGER_STYLES["stop"]
        if text in {"any", "n/a", "미분류"}: return LEDGER_STYLES["neutral"]
    return LEDGER_STYLES["body"]


def _column_name(index: int) -> str:
    result = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        result = chr(65 + remainder) + result
    return result


def _text(value: object) -> str:
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False)
    return ILLEGAL_XML.sub("", "" if value is None else str(value))


def safe_sheet_name(name: str, used: set[str] | None = None) -> str:
    """Return a non-empty, unique Excel worksheet name."""
    used = used if used is not None else set()
    base = INVALID_SHEET_CHARS.sub("_", str(name)).strip(" '")[:31] or "Sheet"
    candidate, suffix = base, 2
    while candidate.casefold() in {value.casefold() for value in used}:
        marker = f" ({suffix})"
        candidate = f"{base[:31-len(marker)]}{marker}"
        suffix += 1
    used.add(candidate)
    return candidate


def _worksheet(rows: list[dict], columns: list[str], headers: dict[str, str], cell_styles: dict[str, dict[str, int]] | None = None,
               ledger: bool = True, merge_columns: list[str] | None = None, group_key: str | None = None) -> bytes:
    cell_styles = cell_styles or {}
    merge_columns = list(dict.fromkeys(merge_columns or []))
    if merge_columns and (not group_key or any(key not in columns for key in merge_columns)):
        raise ValueError("Table merges require a group key and valid columns")
    merges, covered, group_starts = [], set(), set()
    if group_key:
        if any(row.get(group_key) is None for row in rows):
            raise ValueError("Table merge group identifiers must be present")
        start = 0
        while start < len(rows):
            end = start + 1
            while end < len(rows) and rows[end].get(group_key) == rows[start].get(group_key): end += 1
            group_starts.add(start + 2)
            if end - start > 1:
                for key in merge_columns:
                    if any(_text(row.get(key)) != _text(rows[start].get(key)) for row in rows[start:end]):
                        raise ValueError(f"Cannot merge differing values in column {key}")
                    column = columns.index(key) + 1
                    merges.append(f"{_column_name(column)}{start+2}:{_column_name(column)}{end+1}")
                    covered.update((row, column) for row in range(start + 3, end + 2))
            start = end
    sheet = Element("worksheet", {"xmlns": MAIN_NS})
    views = SubElement(sheet, "sheetViews")
    view = SubElement(views, "sheetView", {"workbookViewId": "0"})
    SubElement(view, "pane", {"ySplit": "1", "topLeftCell": "A2", "activePane": "bottomLeft", "state": "frozen"})
    widths = []
    for column in columns:
        values = [headers.get(column, column), *[_text(row.get(column)) for row in rows]]
        widths.append(min(60, max(10, max((max((len(line) for line in value.splitlines()), default=0) for value in values), default=10) + 2)))
    cols = SubElement(sheet, "cols")
    for index, width in enumerate(widths, 1):
        SubElement(cols, "col", {"min": str(index), "max": str(index), "width": str(width), "customWidth": "1"})
    sheet_data = SubElement(sheet, "sheetData")
    values = [[headers.get(column, column) for column in columns], *([[_text(row.get(column)) for column in columns] for row in rows])]
    for row_index, row_values in enumerate(values, 1):
        row_node = SubElement(sheet_data, "row", {"r": str(row_index)})
        for column_index, value in enumerate(row_values, 1):
            column = columns[column_index - 1]
            default_style = semantic_cell_style(column, headers.get(column, column), value) if ledger else 2
            style = (LEDGER_STYLES["header"] if ledger else 1) if row_index == 1 else cell_styles.get(column, {}).get(_text(value), default_style)
            if ledger and row_index > 1:
                if columns[column_index - 1] in merge_columns and style == LEDGER_STYLES["body"]:
                    style = LEDGER_STYLES["center"]
                if row_index in group_starts and 10 <= style <= 17: style += LEDGER_TOP_STYLE_OFFSET
            if (row_index, column_index) in covered: value = ""
            cell = SubElement(row_node, "c", {"r": f"{_column_name(column_index)}{row_index}", "t": "inlineStr", "s": str(style)})
            inline = SubElement(cell, "is")
            SubElement(inline, "t").text = _text(value)
    if columns:
        SubElement(sheet, "autoFilter", {"ref": f"A1:{_column_name(len(columns))}{max(1, len(rows)+1)}"})
    if merges:
        merged = SubElement(sheet, "mergeCells", {"count": str(len(merges))})
        for ref in merges: SubElement(merged, "mergeCell", {"ref": ref})
    return b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' + tostring(sheet, encoding="utf-8")


def _report_summary_worksheet(report: dict[str, object]) -> bytes:
    """Build a cover-style summary sheet without table headers or AutoFilter."""
    sheet = Element("worksheet", {"xmlns": MAIN_NS})
    views = SubElement(sheet, "sheetViews")
    view = SubElement(views, "sheetView", {"workbookViewId": "0", "showGridLines": "0"})
    SubElement(view, "pane", {"ySplit": "1", "topLeftCell": "A2", "activePane": "bottomLeft", "state": "frozen"})
    cols = SubElement(sheet, "cols")
    SubElement(cols, "col", {"min": "1", "max": "1", "width": "36", "customWidth": "1"})
    SubElement(cols, "col", {"min": "2", "max": "2", "width": "42", "customWidth": "1"})
    data = SubElement(sheet, "sheetData")
    merges: list[str] = []
    row_models: list[tuple[int, float | None, list[tuple[str, object, int, bool]]]] = [
        (1, 30, [("A", "TIMELINE", LEDGER_STYLES["header"], True)]),
        (2, 7, [(_column_name(index), "", LEDGER_STYLES["body"], False) for index in range(1, 3)]),
        (11, 7, [(_column_name(index), "", LEDGER_STYLES["body"], False) for index in range(1, 3)]),
    ]
    merges.append("A1:B1")
    fields = [
        (4, "검색 사용자 명", report.get("name", "-")), (5, "검색 사용자 IP", report.get("ips", "-")),
        (6, "검색 사용자 Email", report.get("email", "-")), (7, "검색 사용자 Hostname", report.get("hostnames", "-")),
        (9, "데이터 시작일", report.get("start", "-")), (10, "데이터 종료일", report.get("end", "-")),
        (13, "총 이벤트 수", report.get("total", 0)),
    ]
    fields.extend((14 + index, source, (report.get("counts") or {}).get(source, 0)) for index, source in enumerate(("Detection", "XDR", "Firewall", "Email", "Outbound Mail", "File")))
    for number, label, value in fields:
        lines = max(1, len(_text(value).splitlines()))
        height = min(72, 18 + (lines - 1) * 12) if lines > 1 else None
        row_models.append((number, height, [("A", label, LEDGER_STYLES["header"], True), ("B", value, LEDGER_STYLES["center"], True)]))
    for number, height, cells in sorted(row_models, key=lambda item: item[0]):
        attributes = {"r": str(number)}
        if height is not None:
            attributes.update({"ht": str(height), "customHeight": "1"})
        node = SubElement(data, "row", attributes)
        for column, text, style, inline_string in sorted(cells, key=lambda item: ord(item[0][0])):
            attributes = {"r": f"{column}{number}", "s": str(style)}
            if inline_string:
                attributes["t"] = "inlineStr"
            cell = SubElement(node, "c", attributes)
            if inline_string:
                inline = SubElement(cell, "is"); SubElement(inline, "t").text = _text(text)
    merged = SubElement(sheet, "mergeCells", {"count": str(len(merges))})
    for ref in merges:
        SubElement(merged, "mergeCell", {"ref": ref})
    return b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' + tostring(sheet, encoding="utf-8")


def write_xlsx_workbook(path: Path, sheets: list[dict]) -> list[str]:
    """Write a styled multi-sheet XLSX workbook and return the final sheet names."""
    if not sheets:
        sheets = [{"name": "Data", "rows": [], "columns": [], "headers": {}}]
    used: set[str] = set()
    prepared = []
    for spec in sheets:
        rows = list(spec.get("rows") or [])
        columns = list(spec.get("columns") or list(dict.fromkeys(key for row in rows for key in row)))
        prepared.append((safe_sheet_name(str(spec.get("name") or "Data"), used), rows, columns, dict(spec.get("headers") or {}), dict(spec.get("cellStyles") or {}), spec.get("reportSummary"), spec))

    overrides = "".join(f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' for i in range(1, len(prepared)+1))
    content_types = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>{overrides}<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>'''
    package_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'''
    sheet_defs = "".join(f'<sheet name="{_text(name).replace("&", "&amp;").replace(chr(34), "&quot;").replace("<", "&lt;").replace(">", "&gt;")}" sheetId="{i}" r:id="rId{i}"/>' for i, (name, *_rest) in enumerate(prepared, 1))
    workbook = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="{MAIN_NS}" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>{sheet_defs}</sheets></workbook>'''
    relations = "".join(f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i}.xml"/>' for i in range(1, len(prepared)+1))
    workbook_rels = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">{relations}<Relationship Id="rId{len(prepared)+1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>'''
    styles = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="6"><font><sz val="11"/><name val="Calibri"/></font><font><b/><color rgb="FFFFFFFF"/><sz val="11"/><name val="Calibri"/></font><font><color rgb="FF276749"/><sz val="11"/><name val="Calibri"/></font><font><color rgb="FF9B2C2C"/><sz val="11"/><name val="Calibri"/></font><font><b/><u val="single"/><sz val="20"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts><fills count="6"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF7C3AED"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFC6F6D5"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFFED7D7"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FF000000"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="2"><border/><border><left style="thin"/><right style="thin"/><top style="thin"/><bottom style="thin"/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="10"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment wrapText="1" vertical="top"/></xf><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment wrapText="1" vertical="top"/></xf><xf numFmtId="0" fontId="2" fillId="3" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment wrapText="1" vertical="top"/></xf><xf numFmtId="0" fontId="3" fillId="4" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment wrapText="1" vertical="top"/></xf><xf numFmtId="0" fontId="4" fillId="0" borderId="0" xfId="0" applyFont="1" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf><xf numFmtId="0" fontId="5" fillId="0" borderId="1" xfId="0" applyFont="1" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf><xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="0" fillId="5" borderId="0" xfId="0" applyFill="1"/><xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf></cellXfs></styleSheet>'''
    path = staged_output_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(path, "w", ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", package_rels)
        archive.writestr("xl/workbook.xml", workbook)
        archive.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        archive.writestr("xl/styles.xml", _ledger_styles(styles))
        for index, (_name, rows, columns, headers, cell_styles, report_summary, spec) in enumerate(prepared, 1):
            archive.writestr(f"xl/worksheets/sheet{index}.xml", _report_summary_worksheet(report_summary) if report_summary else _worksheet(rows, columns, headers, cell_styles,
                True, spec.get("mergeColumns"), spec.get("groupKey")))
    return [name for name, *_rest in prepared]


def write_xlsx(path: Path, rows: list[dict], columns: list[str] | None = None, headers: dict[str, str] | None = None) -> list[str]:
    """Write rows to a single-sheet XLSX workbook and return its columns."""
    columns = columns or list(dict.fromkeys(key for row in rows for key in row))
    write_xlsx_workbook(path, [{"name": "Data", "rows": rows, "columns": columns, "headers": headers or {}}])
    return columns
