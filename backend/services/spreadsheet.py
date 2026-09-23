"""Small dependency-free XLSX writer used by Config exports."""
from __future__ import annotations

import json
import re
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, tostring
from zipfile import ZIP_DEFLATED, ZipFile


MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
ILLEGAL_XML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
INVALID_SHEET_CHARS = re.compile(r"[\\/*?:\[\]]")


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


def _worksheet(rows: list[dict], columns: list[str], headers: dict[str, str], cell_styles: dict[str, dict[str, int]] | None = None) -> bytes:
    cell_styles = cell_styles or {}
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
            style = 1 if row_index == 1 else cell_styles.get(columns[column_index - 1], {}).get(_text(value), 2)
            cell = SubElement(row_node, "c", {"r": f"{_column_name(column_index)}{row_index}", "t": "inlineStr", "s": str(style)})
            inline = SubElement(cell, "is")
            SubElement(inline, "t").text = _text(value)
    if columns:
        SubElement(sheet, "autoFilter", {"ref": f"A1:{_column_name(len(columns))}{max(1, len(rows)+1)}"})
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
        prepared.append((safe_sheet_name(str(spec.get("name") or "Data"), used), rows, columns, dict(spec.get("headers") or {}), dict(spec.get("cellStyles") or {})))

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
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="4"><font><sz val="11"/><name val="Calibri"/></font><font><b/><color rgb="FFFFFFFF"/><sz val="11"/><name val="Calibri"/></font><font><color rgb="FF276749"/><sz val="11"/><name val="Calibri"/></font><font><color rgb="FF9B2C2C"/><sz val="11"/><name val="Calibri"/></font></fonts><fills count="5"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF7C3AED"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFC6F6D5"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFFED7D7"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="1"><border/></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="5"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment wrapText="1" vertical="top"/></xf><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment wrapText="1" vertical="top"/></xf><xf numFmtId="0" fontId="2" fillId="3" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment wrapText="1" vertical="top"/></xf><xf numFmtId="0" fontId="3" fillId="4" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment wrapText="1" vertical="top"/></xf></cellXfs></styleSheet>'''
    path.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(path, "w", ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", package_rels)
        archive.writestr("xl/workbook.xml", workbook)
        archive.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        archive.writestr("xl/styles.xml", styles)
        for index, (_name, rows, columns, headers, cell_styles) in enumerate(prepared, 1):
            archive.writestr(f"xl/worksheets/sheet{index}.xml", _worksheet(rows, columns, headers, cell_styles))
    return [name for name, *_rest in prepared]


def write_xlsx(path: Path, rows: list[dict], columns: list[str] | None = None, headers: dict[str, str] | None = None) -> list[str]:
    """Write rows to a single-sheet XLSX workbook and return its columns."""
    columns = columns or list(dict.fromkeys(key for row in rows for key in row))
    write_xlsx_workbook(path, [{"name": "Data", "rows": rows, "columns": columns, "headers": headers or {}}])
    return columns
