import copy
import json
from zipfile import ZipFile
from xml.etree import ElementTree as ET

import pytest

from backend.services.ssm_inventory import parse_inventory, OutputParseError
from test_ssm_inventory import LINUX, WINDOWS, collector, SsmClient, instances
from test_aws_export_inventory import prepare, cells, text, NS

GIB = 1024 ** 3


def disk(ids='vol-a', device='/dev/xvdf', mount='/data', total=100, used=64, state='exact'):
    return f'DISK={ids}|{device}|{mount}|{int(total * GIB)}|{int(used * GIB)}|{state}'


@pytest.mark.parametrize('base', [LINUX, WINDOWS])
def test_optional_disks_without_ssm_raw_and_exact_roundtrip(base):
    assert 'SSM_RAW=' not in base
    legacy = parse_inventory(base)
    assert legacy['disks'] == []
    device, mount = ('disk:0', 'C:\\') if base == WINDOWS else ('/dev/nvme0n1', '/')
    parsed = parse_inventory(base + '\n' + disk(device=device, mount=mount))
    assert parsed == {**legacy, 'disks': [{'volume_ids': ['vol-a'], 'device': device, 'mount': mount,
                                        'total_bytes': 100 * GIB, 'used_bytes': 64 * GIB, 'state': 'exact'}]}


@pytest.mark.parametrize('bad', [
    'DISK=bad', 'DISK=vol-a|/dev/sdf|/|NaN|1|exact',
    'DISK=vol-a|/dev/sdf|/|10|-1|exact', 'DISK=vol-a|/dev/sdf|/|10|11|exact',
    'DISK=vol-a|/dev/sdf|/|0|0|exact', 'DISK=vol-a|/dev/sdf|/|10|1|other',
    'DISK=vol-a|/dev/sdf|/|10.5|1|exact', 'DISK=vol-a|/dev/sdf|/|10|1|exact|extra',
])
def test_bad_disk_is_ignored_without_changing_inventory(bad):
    assert parse_inventory(LINUX + '\n' + bad) == parse_inventory(LINUX)
    with pytest.raises(OutputParseError, match='invalid_product_record'):
        parse_inventory(LINUX + '\n' + bad + '\nWAS=Tomcat|9')


def setup_export(tmp_path, output, *, platform='Linux', status='success'):
    exporter, data = prepare(tmp_path)
    data['volumes'] = [
        {'VolumeId': 'vol-b', 'Size': 500, 'Attachments': [{'InstanceId': 'i-1', 'Device': '/dev/sdg', 'State': 'attached'}]},
        {'VolumeId': 'vol-a', 'Size': 100, 'Attachments': [{'InstanceId': 'i-1', 'Device': '/dev/sdf', 'State': 'attached'}]},
    ]
    data['ssm_inventory'] = {'instances': {'i-1': {**parse_inventory(output), 'status': status,
        'last_success_at': '2026-11-10T09:00:00+09:00', 'platform_type': platform}}}
    return exporter, data


def row_for(exporter, data):
    return exporter._ec2_sheets(data)[0]['rows'][0]


def test_sorted_multiple_mounts_real_xlsx_cache_only_and_other_sheets(tmp_path, monkeypatch):
    output = LINUX + '\n' + '\n'.join([
        disk('vol-b', '/dev/nvme1n1', '/data', 492, 411),
        disk('vol-a', '/dev/nvme0n1p1', '/', 98, 63),
        disk('vol-a', '/dev/nvme0n1p2', '/boot', 2, 1),
        disk('vol-a', '/dev/nvme0n1p2', '/boot', 2, 1),  # Duplicate does not inflate totals.
    ])
    exporter, data = setup_export(tmp_path, output)
    before = copy.deepcopy(data)
    import boto3
    import requests
    monkeypatch.setattr(boto3, 'client', lambda *a, **k: pytest.fail('Export invoked AWS'))
    monkeypatch.setattr(requests.sessions.Session, 'request', lambda *a, **k: pytest.fail('Export invoked network'))
    row = row_for(exporter, data)
    assert row['ebs'] == '600 GB'
    assert row['ebsVolumeMount'] == 'vol-a /, /boot\nvol-b /data'
    assert row['ebsUsed'] == '64.0 / 100.0 GB (64.0%)\n411.0 / 492.0 GB (83.5%)'
    no_disks = copy.deepcopy(data); no_disks['ssm_inventory'] = {}
    assert exporter._ec2_sheets(data)[1] == exporter._ec2_sheets(no_disks)[1]
    assert exporter._sg_sheets(data) == exporter._sg_sheets(no_disks)
    (tmp_path / 'cache/aws.json').write_text(json.dumps(data))
    with ZipFile(exporter.build('aws_ec2')['path']) as archive:
        sheet = ET.fromstring(archive.read('xl/worksheets/sheet1.xml')); refs = cells(sheet)
        assert [text(refs[f'{c}1']) for c in 'LMN'] == ['EBS', 'EBS Volume / Mount', 'EBS Used']
        assert [text(refs[f'{c}2']) for c in 'LMN'] == [row['ebs'], row['ebsVolumeMount'], row['ebsUsed']]
        assert sheet.find('m:autoFilter', NS).attrib['ref'] == 'A1:AF4'
    assert data == before == json.loads((tmp_path / 'cache/aws.json').read_text())


@pytest.mark.parametrize('platform,device,expected', [
    ('Linux', '/dev/xvdf', '64.0 / 100.0 GB (64.0%)\n-'),
    ('Linux', '/dev/sdf', '64.0 / 100.0 GB (64.0%)\n-'),
    ('Linux', '/dev/xvdf1', '-\n-'),
    ('Linux', '/dev/nvme0n1', '-\n-'),
    ('Windows', 'disk:0', '-\n-'),
])
def test_unmapped_fallback_is_linux_whole_device_only(tmp_path, platform, device, expected):
    exporter, data = setup_export(tmp_path, LINUX + '\n' + disk('', device, state='unmapped'), platform=platform)
    assert row_for(exporter, data)['ebsUsed'] == expected


def test_ambiguous_device_and_explicit_id_priority(tmp_path):
    exporter, data = setup_export(tmp_path, LINUX + '\n' + disk('', state='unmapped'))
    data['volumes'][0]['Attachments'][0]['Device'] = '/dev/xvdf'
    assert row_for(exporter, data)['ebsUsed'] == '-\n-'
    data['volumes'][0]['Attachments'][0]['Device'] = '/dev/sdg'
    record = data['ssm_inventory']['instances']['i-1']
    record['disks'] += parse_inventory(LINUX + '\n' + disk(used=20))['disks']
    assert row_for(exporter, data)['ebsUsed'] == '20.0 / 100.0 GB (20.0%)\n-'


def test_shared_never_duplicates_or_prorates_filesystem_usage(tmp_path):
    exporter, data = setup_export(tmp_path, LINUX + '\n' + disk('vol-b,vol-a', '/dev/mapper/data', '/data', 600, 400, 'shared'))
    row = row_for(exporter, data)
    assert row['ebsVolumeMount'] == 'vol-a /data\nvol-b /data'
    assert row['ebsUsed'] == 'Shared\nShared' and row['ebs'] == '600 GB'


@pytest.mark.parametrize('status', ['failed', 'offline', 'unsupported', 'missing', 'success'])
def test_aws_volume_ids_and_capacity_survive_missing_inventory(tmp_path, status):
    exporter, data = setup_export(tmp_path, LINUX, status=status)
    data['instances'][0]['State']['Name'] = 'stopped'
    if status == 'missing': data['ssm_inventory'] = {}
    row = row_for(exporter, data)
    assert row['ebs'] == '600 GB' and row['ebsVolumeMount'] == 'vol-a -\nvol-b -' and row['ebsUsed'] == '-\n-'


def test_force_collect_persists_disks_without_raw(tmp_path):
    client = SsmClient(1); identifier = instances(1)[0]['InstanceId']
    client.outputs[identifier] = LINUX + '\n' + disk()
    result = collector(tmp_path, client).collect(instances(1), force=True)
    assert result['instances'][identifier]['status'] == 'success'
    assert result['instances'][identifier]['disks'][0]['volume_ids'] == ['vol-a']
    content = next((tmp_path / 'runtime/ssm_raw').glob('*.txt')).read_text()
    assert 'Disk Record Counts: 1' in content and disk() in content
    assert 'SSM_RAW: NOT_FOUND' not in content


def test_windows_exact_volume_id_and_stale_inventory(tmp_path):
    exporter, data = setup_export(tmp_path, WINDOWS + '\n' + disk('vol-a', 'disk:0', 'C:\\'), platform='Windows', status='stale')
    row = row_for(exporter, data)
    assert row['ebsVolumeMount'] == 'vol-a C:\\\nvol-b -'
    assert row['ebsUsed'] == '64.0 / 100.0 GB (64.0%)\n-'


def test_supplied_linux_bytes_and_windows_bytes(tmp_path):
    exporter, data = setup_export(tmp_path, LINUX + '\nDISK=vol-a|/dev/nvme0n1|/|105226698752|68182605824|exact')
    assert row_for(exporter, data)['ebsUsed'] == '63.5 / 98.0 GB (64.8%)\n-'
    data['ssm_inventory']['instances']['i-1'].update(parse_inventory(
        WINDOWS + '\nDISK=vol-a|disk:0|C:\\|106300440576|68451041280|exact'))
    assert row_for(exporter, data)['ebsUsed'] == '63.8 / 99.0 GB (64.4%)\n-'


@pytest.mark.parametrize('aws_device,os_device,root,expected', [
    ('/dev/sda1', '/dev/xvda', '/dev/sda1', True),
    ('/dev/sda1', '/dev/xvda', None, False),
    ('/dev/sdf', '/dev/xvdf', '/dev/sda1', True),
    ('/dev/sdf1', '/dev/xvdf', '/dev/sda1', False),
    ('/dev/sda1', '/dev/xvda1', '/dev/sda1', False),
    ('/dev/nvme0n1', '/dev/nvme0n1', '/dev/nvme0n1', False),
])
def test_v165_root_attachment_partition_normalization(tmp_path, aws_device, os_device, root, expected):
    exporter, data = setup_export(tmp_path, LINUX + '\n' + disk('-', os_device, '/', state='unmapped'))
    data['volumes'][1]['Attachments'][0]['Device'] = aws_device
    if root: data['instances'][0]['RootDeviceName'] = root
    row = row_for(exporter, data)
    assert row['ebsUsed'] == ('64.0 / 100.0 GB (64.0%)\n-' if expected else '-\n-')
    assert row['ebsVolumeMount'] == ('vol-a /\nvol-b -' if expected else 'vol-a -\nvol-b -')


def test_shared_physical_devices_map_mounts_without_assigning_usage(tmp_path):
    exporter, data = setup_export(tmp_path, LINUX + '\n' + disk('-', '/dev/xvdf,/dev/xvdg', '/data', 600, 400, 'shared'))
    row = row_for(exporter, data)
    assert row['ebsVolumeMount'] == 'vol-a /data\nvol-b /data'
    assert row['ebsUsed'] == 'Shared\nShared'
    # An ambiguous physical device is left unmapped; the unique member remains Shared.
    data['volumes'].append({'VolumeId': 'vol-c', 'Size': 100, 'Attachments': [
        {'InstanceId': 'i-1', 'Device': '/dev/xvdf', 'State': 'attached'}]})
    row = row_for(exporter, data)
    assert row['ebsVolumeMount'] == 'vol-a -\nvol-b /data\nvol-c -'
    assert row['ebsUsed'] == '-\nShared\n-'


def test_duplicate_filesystem_device_alias_does_not_double_count(tmp_path):
    exporter, data = setup_export(tmp_path, LINUX + '\n' + '\n'.join([
        disk('vol-a', '/dev/sdf1', '/', 98, 63),
        disk('vol-a', '/dev/xvdf1', '/', 98, 63),
        disk('vol-a', '/dev/xvdf2', '/boot', 2, 1),
    ]))
    row = row_for(exporter, data)
    assert row['ebsVolumeMount'] == 'vol-a /, /boot\nvol-b -'
    assert row['ebsUsed'] == '64.0 / 100.0 GB (64.0%)\n-'


@pytest.mark.parametrize('platform,base,lines', [
    ('Linux', LINUX, [disk('vol-a', '/dev/nvme0n1', '/'), disk('-', '/dev/xvdf,/dev/xvdg', '/data', state='shared')]),
    ('Windows', WINDOWS, [disk('vol-a', 'disk:0', 'C:\\'), disk('-', 'disk:1', 'D:\\', state='unmapped')]),
])
def test_force_txt_contains_received_disk_lines_before_parsing(tmp_path, caplog, platform, base, lines):
    client = SsmClient(1); identifier = instances(1)[0]['InstanceId']
    client.information[identifier]['PlatformType'] = platform
    # Malformed DISK stays in TXT for diagnosis, but is excluded from inventory.
    bad = 'DISK=-|disk:9|fixture-mount|bad-number|0|unmapped'
    client.outputs[identifier] = base + '\n' + '\n'.join(lines + [bad])
    result = collector(tmp_path, client).collect(instances(1), force=True)
    content = next((tmp_path / 'runtime/ssm_raw').glob('*.txt')).read_text()
    assert 'Disk Record Counts: 3' in content
    assert all(line in content for line in lines + [bad])
    record = result['instances'][identifier]
    assert record['status'] == 'success' and len(record['disks']) == 2
    assert bad not in json.dumps(result) + caplog.text
    assert 'HOSTNAME=' not in content and 'SSM_RAW: NOT_FOUND' not in content


def test_v165_exact_unmapped_shared_lines_in_actual_xlsx(tmp_path):
    output = LINUX + '\n' + '\n'.join([
        disk('vol-a', '/dev/nvme1n1', '/exact', 100, 64),
        disk('-', '/dev/xvda', '/', 100, 20, 'unmapped'),
        disk('-', '/dev/xvdh,/dev/xvdi', '/data', 400, 300, 'shared'),
    ])
    exporter, data = setup_export(tmp_path, output)
    data['instances'][0]['RootDeviceName'] = '/dev/sda1'
    data['volumes'][0]['Size'] = 100
    data['volumes'][0]['Attachments'][0]['Device'] = '/dev/sda1'
    for identifier, device in [('vol-c', '/dev/sdh'), ('vol-d', '/dev/sdi')]:
        data['volumes'].append({'VolumeId': identifier, 'Size': 200, 'Attachments': [
            {'InstanceId': 'i-1', 'Device': device, 'State': 'attached'}]})
    (tmp_path / 'cache/aws.json').write_text(json.dumps(data))
    with ZipFile(exporter.build('aws_ec2')['path']) as archive:
        refs = cells(ET.fromstring(archive.read('xl/worksheets/sheet1.xml')))
        assert text(refs['L2']) == '600 GB'
        assert text(refs['M2']) == 'vol-a /exact\nvol-b /\nvol-c /data\nvol-d /data'
        assert text(refs['N2']) == '64.0 / 100.0 GB (64.0%)\n20.0 / 100.0 GB (20.0%)\nShared\nShared'
