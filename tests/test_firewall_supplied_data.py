"""Opt-in actual input replay. Private input paths/IPs stay in a local, ignored manifest.

SMU_FIREWALL_VALIDATION_INPUT=/path/to/local-input.json pytest tests/test_firewall_supplied_data.py
The permanent anonymized shape fixture is tested without this optional private input.
"""
import json
import os
from pathlib import Path

import pytest

from tools.validate_firewall_packet_workbook import load,unresolved_evidence
from backend.services.firewall_topology import network
from test_firewall_dynamic_packet import service


@pytest.fixture(scope='module')
def supplied():
    path=os.environ.get('SMU_FIREWALL_VALIDATION_INPUT')
    if not path:pytest.skip('Requires opt-in local supplied-data manifest')
    manifest=json.loads(Path(path).read_text())
    return manifest,load(Path(manifest['workbook'])),json.loads(Path(manifest['aws']).read_text())


def test_actual_resolved_objects_are_available_across_rule_and_nat_sheets(supplied):
    manifest,snapshots,aws=supplied
    reference=manifest['objectDefinitions']
    for name,value in reference['values'].items():
        assert snapshots[reference['firewall']]['objects'][name]==value


@pytest.mark.parametrize('index',[0,1])
def test_actual_scenarios_bind_exact_raw_eni_groups_without_online_calls(supplied,index,tmp_path,monkeypatch):
    manifest,snapshots,aws=supplied;query=manifest['scenarios'][index]
    from backend.services.firewall import FirewallClient
    import socket,boto3
    monkeypatch.setattr(FirewallClient,'get',lambda *a,**k:pytest.fail('online Firewall call'))
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:pytest.fail('online DNS'))
    monkeypatch.setattr(boto3,'client',lambda *a,**k:pytest.fail('online AWS call'))
    current=service(tmp_path,snapshots,aws)
    result=current.check(query['source'],query['destination'],'TCP',query['port'])
    endpoint=result['endpoints']['destination']
    assert endpoint['type']==query['kind']
    matches={eni['NetworkInterfaceId']:eni for eni in aws['network_interfaces']
        if any(item.get('PrivateIpAddress')==query['destination'] or (item.get('Association') or {}).get('PublicIp')==query['destination'] for item in eni.get('PrivateIpAddresses',[]))}
    assert len(matches)==1
    identifier,eni=next(iter(matches.items()))
    assert endpoint['aws']['eniId']==identifier
    assert set(endpoint['aws']['groupIds'])=={group['GroupId'] for group in eni['Groups']}
    assert all(any(group['GroupId']==gid for group in aws['security_groups']) for gid in endpoint['aws']['groupIds'])
    if query['kind']=='FIREWALL_PUBLIC_IP':
        association=next(item for item in eni['PrivateIpAddresses'] if (item.get('Association') or {}).get('PublicIp')==query['destination'])
        assert endpoint['aws']['private_ip']==association['PrivateIpAddress']
        owner=endpoint['owner'];row=next(row for row in snapshots[owner['firewall']]['interfaces']+snapshots[owner['firewall']]['aliases'] if row['Name']==owner['interface'])
        assert row['IP Address']==association['PrivateIpAddress']
        assert owner['zone']=='WAN'
    # Any remaining stop must identify an actual unresolved predicate, not identity failure.
    if query['port'] is None:
        assert result['summary']['status']=='WARNING'
        assert len(result['serviceResults'])>1
        assert any(scope['summary']['status']=='UNKNOWN' for scope in result['serviceResults'])
    else:
        assert result['summary']['status']=='UNKNOWN'
    assert unresolved_evidence(result,snapshots)
    assert not any('Object missing' in step['reason'] for step in result['analysisPath'])
    assert not any(step['type']=='aws_sg' for step in result['analysisPath'])
