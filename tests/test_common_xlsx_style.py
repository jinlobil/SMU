from pathlib import Path
from xml.etree import ElementTree as ET
from zipfile import ZipFile

import pytest

from backend.services.spreadsheet import write_xlsx, write_xlsx_workbook
from backend.services.exporting import EXPORT_SCHEMAS, normalize_export_columns
from system_monitor.laborer import LaborerAgent
import system_monitor.laborer as laborer

NS = {'m': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}


def read_workbook(path):
    with ZipFile(path) as archive:
        assert archive.testzip() is None
        for name in archive.namelist():
            if name.endswith(('.xml', '.rels')): ET.fromstring(archive.read(name))
        return ET.fromstring(archive.read('xl/worksheets/sheet1.xml')), ET.fromstring(archive.read('xl/styles.xml'))


def assert_table_style(path):
    sheet, styles = read_workbook(path)
    xfs, fonts, fills, borders = (styles.find('m:' + name, NS) for name in ('cellXfs', 'fonts', 'fills', 'borders'))
    for cell in sheet.findall('m:sheetData/m:row/m:c', NS):
        xf = xfs[int(cell.attrib['s'])]
        assert xf.find('m:alignment', NS).attrib['vertical'] == 'center'
        border = borders[int(xf.attrib['borderId'])]
        assert all(border.find('m:' + edge, NS).attrib['style'] == 'thin' for edge in ('left', 'right', 'top', 'bottom'))
        if cell.attrib['r'].endswith('1'):
            assert fills[int(xf.attrib['fillId'])].find('m:patternFill/m:fgColor', NS).attrib['rgb'] == 'FF17365D'
            assert fonts[int(xf.attrib['fontId'])].find('m:color', NS).attrib['rgb'] == 'FFFFFFFF'
            assert fonts[int(xf.attrib['fontId'])].find('m:b', NS) is not None
            assert xf.find('m:alignment', NS).attrib['horizontal'] == 'center'
    assert sheet.find('m:autoFilter', NS) is not None
    assert sheet.find('m:sheetViews/m:sheetView/m:pane', NS).attrib['state'] == 'frozen'
    return sheet, styles


@pytest.mark.parametrize('kind', list(EXPORT_SCHEMAS))
def test_all_laborer_source_exports_reuse_ledger_writer(tmp_path, monkeypatch, kind):
    columns = normalize_export_columns(kind, None)
    row = {key: 'fixture' for key in columns}
    for cls, methods in [(laborer.DetectionService, ['_events']), (laborer.EmailSecurityService, ['_collect_xdr', '_collect_inbound']),
                         (laborer.FirewallDetectionService, ['_collect']), (laborer.TransferService, ['_collect_outbound', '_collect_dlp'])]:
        for method in methods:
            monkeypatch.setattr(cls, method, lambda *_args: ([('fixture-id', {}, row)], {}))
    agent = LaborerAgent.__new__(LaborerAgent); agent.root = tmp_path
    result = agent._export({'kind': kind, 'start': '2026-01-01', 'end': '2026-01-02'}, lambda _: None)
    sheet, _ = assert_table_style(result['path'])
    assert len(sheet.findall('m:sheetData/m:row/m:c', NS)) == 2 * len(columns)


def test_semantic_colors_are_limited_to_meaningful_columns(tmp_path):
    columns = ['status', 'action', 'direction', 'antivirus', 'description']
    rows = [dict(zip(columns, values)) for values in [
        ['Running', 'Allow', 'Inbound', 'Sophos', 'Fail'], ['비활성', 'Reject', 'Outbound', 'other', 'Sophos'],
        ['Success', 'Accept', 'other', '', 'Running'], ['Fail', 'Drop', '', '', 'Allow']]]
    path = tmp_path / 'semantic.xlsx'; write_xlsx(path, rows, columns)
    sheet, styles = assert_table_style(path)
    cells = {cell.attrib['r']: cell for cell in sheet.findall('m:sheetData/m:row/m:c', NS)}
    def color(ref):
        xf = styles.find('m:cellXfs', NS)[int(cells[ref].attrib['s'])]
        font = styles.find('m:fonts', NS)[int(xf.attrib['fontId'])]
        fill = styles.find('m:fills', NS)[int(xf.attrib['fillId'])]
        return fill.find('m:patternFill/m:fgColor', NS).attrib['rgb'], font.find('m:color', NS).attrib['rgb'], font.find('m:b', NS) is not None
    assert color('A2') == ('FF228B46', 'FFFFFFFF', True)
    assert color('A3') == ('FFC62828', 'FFFFFFFF', True)
    assert color('A4') == ('FF228B46', 'FFFFFFFF', True)
    assert color('A5') == ('FFC62828', 'FFFFFFFF', True)
    assert color('D2') == ('FF2463B5', 'FFFFFFFF', True)
    assert color('B2')[0] == color('B4')[0] == 'FFE2F0D9'
    assert color('B3')[0] == color('B5')[0] == 'FFFCE0E0'
    assert color('C2')[0] == 'FFDDEBF7' and color('C3')[0] == 'FFFCE4D6'
    assert all(color('E' + str(row)) == ('FFFFFFFF', 'FF000000', False) for row in range(2, 6))


def test_empty_workbook_and_future_exports_get_shared_style(tmp_path):
    path = tmp_path / 'empty.xlsx'
    write_xlsx_workbook(path, [{'name': 'Future', 'columns': ['status'], 'rows': []}])
    assert_table_style(path)


def test_timeline_retains_seven_sheets_with_shared_table_styles(tmp_path):
    from test_timeline_export import _database
    from backend.services.timeline_export import TimelineExportService, SHEET_ORDER
    _database(tmp_path, [])
    path = tmp_path / 'timeline.xlsx'
    result = TimelineExportService(tmp_path).export('fixture-user', '', set(SHEET_ORDER), path)
    assert result['sheets'] == ['Summary', *SHEET_ORDER]
    with ZipFile(path) as archive:
        assert archive.testzip() is None
        for name in archive.namelist():
            if name.endswith(('.xml', '.rels')): ET.fromstring(archive.read(name))
        for index in range(1, 8):
            sheet = ET.fromstring(archive.read(f'xl/worksheets/sheet{index}.xml'))
            assert sheet.find('m:sheetViews/m:sheetView/m:pane', NS).attrib['state'] == 'frozen'
            header = sheet.find("m:sheetData/m:row[@r='1']/m:c", NS)
            assert header.attrib['s'] == '10'
            if index > 1:
                assert sheet.find('m:autoFilter', NS) is not None
            else:
                # Summary remains a merged cover, not a table to filter.
                assert sheet.find('m:mergeCells/m:mergeCell', NS).attrib['ref'] == 'A1:B1'
                assert sheet.find('m:autoFilter', NS) is None
