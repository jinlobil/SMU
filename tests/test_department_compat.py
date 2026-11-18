import ast
import copy
import json
from pathlib import Path

import pytest

from backend.services.departments import parse_department_display_name, department_names_with_directory
from backend.services.endpoints import EndpointService, directory_department
from backend.services.organizations import OrganizationService
from backend.clients.sophos import SophosClient


@pytest.mark.parametrize('value,code,name', [
    ('10009673', '10009673', '구매팀'),
    ('구매팀 (10009673)', '10009673', '구매팀'),
    ('구매팀 (10009673) (LOCKNLOCK)', '10009673', '구매팀'),
    (' 경영기획파트 (10000123) ', '10000123', '경영기획파트'),
    ('  구매팀 ( 10009673 ) (LOCKNLOCK)  ', '10009673', '구매팀'),
    ('구매팀 (00123)', '00123', '구매팀'),
])
def test_old_and_new_department_display_names(value, code, name):
    assert parse_department_display_name(value, {'10009673': '구매팀'}) == {'deptCode': code, 'deptName': name}


@pytest.mark.parametrize('value', [None, '', ' ', 'Some Security Group', 'Security (Admin)',
                                    'Group (123) trailing', 'Group (123) (OTHER)', [], {}, True])
def test_unrelated_or_malformed_group_does_not_create_department(value):
    assert parse_department_display_name(value) is None


def test_embedded_name_wins_and_numeric_mapping_fallback_is_unchanged():
    assert parse_department_display_name('구매팀 (10009673)', {'10009673': 'Old Name'})['deptName'] == '구매팀'
    assert parse_department_display_name('10009673', {'10009673': '구매팀'})['deptName'] == '구매팀'
    assert parse_department_display_name('12345') == {'deptCode': '12345', 'deptName': '12345'}


def user(display, source='activeDirectory'):
    return {'name': 'Fixture User', 'email': 'fixture@example.test', 'exchangeLogin': 'fixture',
            'source': {'type': source}, 'groups': {'items': [{'displayName': display}, {'displayName': 'Some Security Group'}]}}


@pytest.mark.parametrize('display', ['10009673', '구매팀 (10009673)', '구매팀 (10009673) (LOCKNLOCK)'])
def test_directory_fallback_retains_source_filter_reverse_selection_and_schema(display):
    value = user(display)
    original = copy.deepcopy(value)
    assert directory_department(value, {'10009673': '구매팀'}) == ('구매팀', '10009673')
    assert value == original
    assert directory_department(user(display, 'azureAD'), {'10009673': '구매팀'}) == ('미분류', '')
    value['groups']['items'].append({'displayName': '다른팀 (555)'})
    assert directory_department(value, {}) == ('다른팀', '555')
    assert directory_department(user('Some Security Group'), {}) == ('미분류', '')


@pytest.mark.parametrize('display', ['10009673', '구매팀 (10009673)', '구매팀 (10009673) (LOCKNLOCK)'])
def test_sophos_collection_keeps_existing_user_groups_schema(monkeypatch, display):
    client = SophosClient.__new__(SophosClient)
    monkeypatch.setattr(client, 'authenticate', lambda: None)
    raw_groups = [{'displayName': display, 'users': {'items': [{'name': 'Fixture User', 'id': 'fixture'}]}},
                  {'displayName': 'Some Security Group', 'users': {'items': []}}]
    raw_users = [user(display)]
    monkeypatch.setattr(client, 'paged_items', lambda path: raw_groups)
    monkeypatch.setattr(client, 'fetch_users', lambda: raw_users)
    before = copy.deepcopy(raw_groups)
    groups, users = client.fetch_organizations({'10009673': '구매팀'})
    assert groups == [{'deptCode': '10009673', 'deptName': '구매팀', 'users': [{'name': 'Fixture User', 'id': 'fixture'}]}]
    assert users == raw_users and raw_groups == before
    assert set(groups[0]) == {'deptCode', 'deptName', 'users'}


def write(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False))


@pytest.mark.parametrize('display', ['10009673', '구매팀 (10009673)', '구매팀 (10009673) (LOCKNLOCK)'])
@pytest.mark.parametrize('with_org', [False, True])
def test_endpoint_users_fallback_and_organization_display_do_not_become_unclassified(tmp_path, display, with_org):
    write(tmp_path / 'cache/endpoints.json', [{'hostname': 'fixture-host', 'associatedPerson': {'name': 'Fixture User', 'viaLogin': 'DOMAIN\\fixture'}}])
    write(tmp_path / 'cache/users.json', [user(display)])
    write(tmp_path / 'cache/user_groups.json', [{'deptCode': '10009673', 'deptName': '구매팀', 'users': [{'name': 'Fixture User'}]}] if with_org else [])
    env = tmp_path / 'env/User_group_env.txt'; env.parent.mkdir()
    env.write_text('10009673=구매팀\n' if display == '10009673' else '10009673=Old Name\n')
    before = {p: p.read_bytes() for p in (tmp_path / 'cache').glob('*.json')}
    endpoint = EndpointService(tmp_path).export_rows()[0]
    assert endpoint['dept'] == '구매팀'
    if with_org:
        assert OrganizationService(tmp_path).list_organizations()['items'][0] == {'deptCode': '10009673', 'deptName': '구매팀', 'user': 'Fixture User'}
    assert all(path.read_bytes() == content for path, content in before.items())
    assert env.read_text() == ('10009673=구매팀\n' if display == '10009673' else '10009673=Old Name\n')


def test_directory_overlay_is_memory_only_and_keeps_old_map_for_numeric_and_non_ad():
    names = {'10009673': 'Old Name', '555': 'Existing'}
    assert department_names_with_directory(names, [user('구매팀 (10009673)')]) == {'10009673': '구매팀', '555': 'Existing'}
    assert department_names_with_directory(names, [user('10009673')]) == names
    assert department_names_with_directory(names, [user('구매팀 (10009673)', 'azureAD')]) == names
    assert names == {'10009673': 'Old Name', '555': 'Existing'}


def test_desktop_directory_uses_same_parser_without_loading_ui():
    path = Path(__file__).resolve().parents[1] / 'uimain_window.py'
    tree = ast.parse(path.read_text())
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'get_directory_user_dept')
    namespace = {'DEPT_MAP': {'10009673': '구매팀'}}
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), 'exec'), namespace)
    for display in ('10009673', '구매팀 (10009673)', '구매팀 (10009673) (LOCKNLOCK)'):
        assert namespace['get_directory_user_dept'](user(display)) == ('구매팀', '10009673')


@pytest.mark.parametrize('display', ['10009673', '구매팀 (10009673)', '구매팀 (10009673) (LOCKNLOCK)'])
def test_directory_only_email_outbound_report_and_timeline_share_department(tmp_path, display):
    from datetime import date
    from backend.services.email_security import EmailSecurityService
    from backend.services.transfers import TransferService
    from backend.services.report import ReportService
    from backend.services.timeline import TimelineService
    from backend.services.indexing import IndexService
    from backend.services.event_list_index import EventListIndex
    write(tmp_path / 'cache/users.json', [user(display)])
    write(tmp_path / 'cache/user_groups.json', [])
    env = tmp_path / 'env/User_group_env.txt'; env.parent.mkdir()
    env.write_text('10009673=구매팀\n')
    email = EmailSecurityService(tmp_path)._directory_identity()['fixture@example.test']
    assert email['dept'] == '구매팀'
    day = date(2026, 11, 17)
    write(tmp_path / f'cache/sophos_outbound/{day}.json', [{'date': f'{day} 10:00:00', 'senderEmail': 'fixture@example.test', 'subject': 'fixture'}])
    assert TransferService(tmp_path)._collect_outbound(day, day)[0][0][2]['dept'] == '구매팀'
    timeline = TimelineService(tmp_path)
    assert timeline._identities()[0]['fixture@example.test']['dept'] == '구매팀'
    report = ReportService(tmp_path); report._configure_legacy_data(['outbound'])
    from backend.services import legacy_report
    assert legacy_report.DIRECTORY_USER_INDEX['fixture@example.test']['dept_name'] == '구매팀'
    assert legacy_report.DIRECTORY_USER_INDEX['fixture@example.test']['dept_code'] == '10009673'
    IndexService(tmp_path).rebuild_scope('events', lambda _: None)
    assert EventListIndex(tmp_path).rows_for_kind('outbound', day, day)[0]['dept'] == '구매팀'


def test_exception_overrides_new_department_without_changing_raw(tmp_path):
    from backend.services.exceptions import ExceptionService
    write(tmp_path / 'cache/users.json', [user('구매팀 (10009673)')])
    write(tmp_path / 'cache/endpoints.json', [{'hostname': 'fixture-host', 'associatedPerson': {'name': 'Fixture User', 'viaLogin': 'DOMAIN\\fixture'}}])
    service = ExceptionService(tmp_path)
    service.save('departments', {'matchType': 'principal', 'matchValue': 'DOMAIN\\fixture', 'department': 'Exception Department'})
    raw = (tmp_path / 'cache/users.json').read_bytes()
    assert EndpointService(tmp_path).export_rows()[0]['dept'] == 'Exception Department'
    assert (tmp_path / 'cache/users.json').read_bytes() == raw
