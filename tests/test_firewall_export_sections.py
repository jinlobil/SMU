from pathlib import Path
from xml.etree import ElementTree as ET
from zipfile import ZipFile

import pytest

from backend.services.spreadsheet import write_xlsx_workbook
from backend.services.firewall_routes import parse_unicast_routes, route_cidr
from backend.services.firewall_path_check import parse_unicast_routes as path_routes

NS = {'m': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}


def text(row):
    return [cell.findtext('m:is/m:t', namespaces=NS) or '' for cell in row]


def test_existing_route_parser_is_shared_and_preserves_raw_fields():
    assert path_routes is parse_unicast_routes
    xml = '<Response><Status code="200">OK</Status><UnicastRoute><Destination>10.10.0.0</Destination><Netmask>255.255.0.0</Netmask><Gateway>192.0.2.1</Gateway><Interface>Port1</Interface><AdministrativeDistance>1</AdministrativeDistance><Status>Enable</Status><Description>fixture</Description></UnicastRoute></Response>'
    assert parse_unicast_routes(xml) == [{'destination': '10.10.0.0', 'netmask': '255.255.0.0', 'gateway': '192.0.2.1',
        'interface': 'Port1', 'distance': '', 'administrative_distance': '1', 'ip_family': '', 'blackhole': '', 'status': 'Enable', 'description': 'fixture'}]
    assert parse_unicast_routes('<Response><Status code="200">OK</Status></Response>') == []
    with pytest.raises(RuntimeError): parse_unicast_routes('<Response><Status code="529">Unavailable</Status></Response>')


@pytest.mark.parametrize('destination,mask,expected', [
    ('10.10.0.0', '255.255.0.0', '10.10.0.0/16'),
    ('10.10.1.7', '16', '10.10.0.0/16'),
    ('0.0.0.0', '0.0.0.0', '0.0.0.0/0'),
    ('192.0.2.1', '255.255.255.255', '192.0.2.1/32'),
    ('10.0.0.0', '255.0.255.0', ''), ('bad', '24', ''), ('10.0.0.0', '', ''),
])
def test_route_cidr_is_defensive(destination, mask, expected):
    assert route_cidr(destination, mask) == expected


def section_spec(name, kind):
    return {'name': name, 'columns': ['Name', 'Status', 'Description'], 'sections': [
        {'title': 'Cloud ' + kind, 'tableName': f'tbl_{name.lower()}_cloud', 'rows': [{'Name': 'Cloud fixture', 'Status': 'Enable', 'Description': 'line one\nline two'}]},
        {'title': 'Seoul ' + kind, 'tableName': f'tbl_{name.lower()}_seoul', 'rows': [], 'message': 'No data'},
        {'title': 'Icheon ' + kind, 'tableName': f'tbl_{name.lower()}_icheon', 'rows': [], 'message': '조회 실패 · Firewall API 529'},
        {'title': 'Anseong ' + kind, 'tableName': f'tbl_{name.lower()}_anseong', 'rows': [{'Name': 'Anseong fixture', 'Status': 'Disable'}]},
    ]}


def test_actual_xlsx_multiple_tables_spacing_styles_and_old_sheet_unchanged(tmp_path):
    original = {'name': 'Cloud', 'columns': ['Rule Name', 'Status'], 'rows': [{'Rule Name': 'Original', 'Status': '활성'}]}
    before = tmp_path / 'before.xlsx'; after = tmp_path / 'after.xlsx'
    write_xlsx_workbook(before, [original])
    write_xlsx_workbook(after, [original, section_spec('NAT', 'NAT Rules'), section_spec('Route', 'Static Routes')])
    with ZipFile(before) as old, ZipFile(after) as archive:
        assert archive.testzip() is None
        for name in archive.namelist():
            if name.endswith(('.xml', '.rels')): ET.fromstring(archive.read(name))
        assert old.read('xl/worksheets/sheet1.xml') == archive.read('xl/worksheets/sheet1.xml')
        old_styles = ET.fromstring(old.read('xl/styles.xml')).find('m:cellXfs', NS)
        styles = ET.fromstring(archive.read('xl/styles.xml')).find('m:cellXfs', NS)
        assert [ET.tostring(node) for node in styles[:len(old_styles)]] == [ET.tostring(node) for node in old_styles]
        assert len([name for name in archive.namelist() if name.startswith('xl/tables/table')]) == 8
        for index, kind in [(2, 'NAT Rules'), (3, 'Static Routes')]:
            sheet = ET.fromstring(archive.read(f'xl/worksheets/sheet{index}.xml'))
            rows = sheet.findall('m:sheetData/m:row', NS)
            titles = [row for row in rows if text(row) and text(row)[0].endswith(kind)]
            assert [text(row)[0] for row in titles] == [f'{name} {kind}' for name in ('Cloud', 'Seoul', 'Icheon', 'Anseong')]
            assert [int(row.attrib['r']) for row in rows if not len(row)] == [4, 8, 12]
            assert text(rows[6])[0] == 'No data' and text(rows[10])[0].startswith('조회 실패')
            assert sheet.find('m:autoFilter', NS) is None
            assert len(sheet.findall('m:tableParts/m:tablePart', NS)) == 4
            assert sheet.find('m:sheetViews/m:sheetView/m:pane', NS).get('topLeftCell') == 'A3'
            assert all(10 <= float(col.get('width')) <= 60 for col in sheet.findall('m:cols/m:col', NS))
            for cell in sheet.findall('m:sheetData/m:row/m:c', NS):
                alignment = styles[int(cell.get('s'))].find('m:alignment', NS)
                assert alignment.get('vertical') == 'top' and alignment.get('wrapText') == '1'
        table_names = []
        for i in range(1, 9):
            table = ET.fromstring(archive.read(f'xl/tables/table{i}.xml'))
            table_names.append(table.get('name'))
            assert table.find('m:autoFilter', NS).get('ref') == table.get('ref')
            assert len(table.findall('m:tableColumns/m:tableColumn', NS)) == 3
        assert len(set(table_names)) == 8


def test_duplicate_table_names_are_rejected(tmp_path):
    spec = section_spec('NAT', 'NAT Rules'); spec['sections'][1]['tableName'] = spec['sections'][0]['tableName']
    with pytest.raises(ValueError, match='unique'): write_xlsx_workbook(tmp_path / 'bad.xlsx', [spec])
