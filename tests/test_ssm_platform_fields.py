import copy
import json
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from backend.services.aws_assets import AwsAssetService
from backend.services.ssm_inventory import parse_inventory
from test_ssm_inventory import SsmClient, collector, instances, TODAY
from test_ssm_refresh import service


PLATFORMS = ('was_platform', 'web_platform', 'db_platform')
BASE = 'HOSTNAME=fixture-server\nOS=Example OS\nKERNEL=fixture-kernel\nOS_INSTALL_DATE=N/A\n'
CASES = [
    ('WAS=WebLogic|12.2.1.1.0|/srv/wls|running\nWAS=Tomcat|7.0.68|/srv/tomcat|running\nWAS_PLATFORM=Java 1.8.0_131\nWEB=None\nWEB_PLATFORM=None\nDB=Oracle|12.1.0|/srv/oracle|running\nDB_PLATFORM=Oracle 12.1.0',
     ('Java 1.8.0_131', None, 'Oracle 12.1.0'), ['WebLogic', 'Tomcat']),
    ('WAS=None\nWAS_PLATFORM=None\nWEB=Apache|2.2.22|/srv/apache/httpd|running\nWEB_PLATFORM=PHP 5.1.4\nDB=Oracle|10.2.0|/srv/oracle|running\nDB_PLATFORM=Oracle 10.2.0',
     (None, 'PHP 5.1.4', 'Oracle 10.2.0'), []),
    ('WAS=SAP Java|753 Patch 602|/srv/sap|running\nWAS_PLATFORM=Java 1.8.0_172\nWEB=None\nWEB_PLATFORM=None\nDB=Sybase|16.0.03.03|/srv/sybase|running\nDB_PLATFORM=ASE 16.0.03.03',
     ('Java 1.8.0_172', None, 'ASE 16.0.03.03'), ['SAP Java']),
    ('WAS=Tomcat|7.0.68|/srv/tomcat|running\nWEB=None\nDB=Oracle|12.1.0|/srv/oracle|running',
     (None, None, None), ['Tomcat']),
]


@pytest.mark.parametrize('output,platforms,names', CASES)
def test_requested_outputs_preserve_products_and_optional_platforms(output, platforms, names):
    row = parse_inventory(BASE + output)
    assert tuple(row[key] for key in PLATFORMS) == platforms
    assert [item['product'] for item in row['was']] == names
    if 'SAP Java' in names: assert row['was'][0]['version'] == '753 Patch 602'
    assert row['db'][0]['status'] == 'running'


@pytest.mark.parametrize('value', ['', 'None', 'N/A', 'unknown'])
def test_empty_platform_values_follow_existing_null_convention(value):
    row = parse_inventory(BASE + f'WAS=None\nWEB=None\nDB=None\nWAS_PLATFORM={value}\nWEB_PLATFORM={value}\nDB_PLATFORM={value}')
    assert all(row[key] is None for key in PLATFORMS)


def test_platform_full_strings_are_not_split_or_reinterpreted():
    values = ('Java 1.8.0_131; Java 17.0.12', 'PHP 5.1.4; Node.js 20.18.0', 'Oracle 12.1.0; ASE 16.0.03.03')
    output = BASE + 'WAS=None\nWEB=None\nDB=None\n' + '\n'.join(f'{key.upper()}={value}' for key, value in zip(PLATFORMS, values))
    row = parse_inventory('\ufeff' + output.replace('\n', '\r\n'))
    assert tuple(row[key] for key in PLATFORMS) == values
    special = parse_inventory(output.replace(values[1], '.NET 8.x; Go 1.x; runtime=fixture'))
    assert special['web_platform'] == '.NET 8.x; Go 1.x; runtime=fixture'


def test_collection_preserves_platforms_on_stale_and_daily_gate(tmp_path):
    client = SsmClient(1); identifier = instances(1)[0]['InstanceId']
    client.outputs[identifier] = BASE + CASES[0][0]
    target = collector(tmp_path, client)
    first = target.collect(instances(1)); original = copy.deepcopy(first)
    client.fail.add(identifier)
    failed = target.collect(instances(1), first, force=True)
    record = failed['instances'][identifier]
    assert record['status'] == 'stale' and first == original
    for key in PLATFORMS: assert record[key] == first['instances'][identifier][key]
    client.sent.clear()
    target.collect(instances(1), failed)
    assert client.sent == []
    collector(tmp_path, client, TODAY + timedelta(days=1)).collect(instances(1), failed)
    assert client.sent == [identifier]


def test_actual_refresh_atomic_json_and_instance_detail_api_use_cache_only(tmp_path, monkeypatch):
    import backend.app as app_module
    import boto3
    target, client, payload = service(tmp_path, monkeypatch)
    identifier = payload['instances'][0]['InstanceId']
    client.outputs[identifier] = BASE + CASES[0][0]
    target.refresh_aws(lambda _: None)
    path = tmp_path / 'cache/aws.json'
    before = path.read_text(); stored = json.loads(before)
    assert stored['ssm_inventory']['instances'][identifier]['was_platform'] == 'Java 1.8.0_131'
    assert stored['vpcs'] == payload['vpcs'] and not list(path.parent.glob('*.tmp'))
    monkeypatch.setattr(boto3, 'client', lambda *a, **kw: pytest.fail('API view called AWS/SSM'))
    monkeypatch.setattr(app_module, 'aws_asset_service', AwsAssetService(tmp_path))
    response = TestClient(app_module.app).get('/api/aws/instances/' + identifier)
    assert response.status_code == 200
    data = response.json()['data']
    assert data['instance']['InstanceId'] == identifier and 'attachedSecurityGroups' in data
    assert data['ssmInventory']['db_platform'] == 'Oracle 12.1.0'
    assert data['ssmInventory']['web_platform'] is None
    assert len(data['ssmInventory']['was']) == 2
    assert path.read_text() == before


@pytest.mark.parametrize('inventory', [None, {}, {'instances': {}}, {'instances': {'i-fixture': {'hostname': 'legacy', 'was': [], 'web': [], 'db': []}}}])
def test_legacy_or_missing_cache_requires_no_migration(tmp_path, inventory):
    cache = tmp_path / 'cache/aws.json'; cache.parent.mkdir()
    cache.write_text(json.dumps({'instances': [{'InstanceId': 'i-fixture'}], 'ssm_inventory': inventory}))
    before = cache.read_text()
    data = AwsAssetService(tmp_path).detail('i-fixture')
    assert all(data['ssmInventory'][key] is None for key in PLATFORMS)
    assert data['instance']['InstanceId'] == 'i-fixture'
    assert cache.read_text() == before
