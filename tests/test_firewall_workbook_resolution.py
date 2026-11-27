"""The supplied export's parallel names/resolved and cross-sheet reference shapes."""
from tools import validate_firewall_packet_workbook as workbook
from test_firewall_dynamic_packet import config,interface,nat,policy,service,check,aws_data,topology


def test_parallel_object_names_resolve_from_cells_not_display_names(tmp_path,monkeypatch):
    rows=[('Firewall',[
        ['Rule Name','Source Object','Source Resolved','Destination Object','Destination Resolved'],
        ['fixture','office','10.41.0.0/24','opaque-a\nopaque-b\nopaque-c','198.51.100.31\n198.51.100.32\n198.51.100.33']]),
        ('NAT',[['Firewall NAT Rules'],['Rule Name','Original Destination'],['publish','opaque-b']])]
    monkeypatch.setattr(workbook,'sheets',lambda path:iter(rows))
    result=workbook.load(tmp_path/'fixture.xlsx')
    assert set(result)=={'Firewall'}
    assert result['Firewall']['objects']['opaque-a']=='198.51.100.31/32'
    assert result['Firewall']['objects']['opaque-b']=='198.51.100.32/32'
    assert result['Firewall']['objects']['opaque-c']=='198.51.100.33/32'
    assert result['Firewall']['natRules'][0]['Original Destination']=='opaque-b'


def test_flat_group_and_mismatched_counts_are_not_guessed(tmp_path,monkeypatch):
    rows=[('Firewall',[
        ['Rule Name','Destination Object','Destination Resolved'],
        ['one','group-a\nother','member-x (198.51.100.1)\nmember-y (198.51.100.2)'],
        ['two','opaque-a\nopaque-b','198.51.100.3']])]
    monkeypatch.setattr(workbook,'sheets',lambda path:iter(rows))
    result=workbook.load(tmp_path/'fixture.xlsx')['Firewall']['objects']
    assert result['member-x']=='198.51.100.1/32'
    assert result['member-y']=='198.51.100.2/32'
    assert not any(key in result for key in ['group-a','other','opaque-a','opaque-b'])


def test_cross_sheet_service_and_object_resolution_is_unique_only(tmp_path,monkeypatch):
    header=['Rule Name','Destination Object','Destination Resolved','Service','Service Resolved / Protocol / Port']
    rows=[('One',[header,['one','resolved-host','198.51.100.2','datagram','Protocol: UDP | Destination: 6515'],['two','conflict','198.51.100.3','','']]),
        ('Two',[header,['two','conflict','198.51.100.4','','']]),('Three',[header,['three','other','198.51.100.5','','']])]
    monkeypatch.setattr(workbook,'sheets',lambda path:iter(rows))
    result=workbook.load(tmp_path/'fixture.xlsx')
    assert result['Three']['objects']['resolved-host']=='198.51.100.2/32'
    assert result['Three']['services']['datagram']=='Protocol: UDP | Destination: 6515'
    assert 'conflict' not in result['Three']['objects']


def test_resolved_datagram_excludes_unrelated_nat_from_tcp_without_guessing_unknown_host(tmp_path):
    snapshots=topology()
    snapshots['Edge']['natRules']=[nat('only datagram',dest='actually missing',snat='also missing',service='udp')]
    snapshots['Edge']['services']={'udp':'Protocol: UDP | Destination: 6515'}
    result=check(service(tmp_path,snapshots),'10.42.0.25')
    assert result['summary']['status']=='PASS'
    assert not any(step['type']=='snat' for step in result['analysisPath'])


def test_empty_object_placeholder_cannot_hide_actual_interface_alias(tmp_path):
    snapshots=topology()
    snapshots['Hub']['objects']={'#uplink:10':''}
    snapshots['Hub']['natRules']=[nat('publish','#uplink:10',dnat='10.42.0.25',inbound='uplink')]
    current=service(tmp_path,snapshots,aws_data())
    result=check(current,'8.8.4.5',source='9.9.9.9')
    assert result['summary']['status']=='PASS'
    assert any(step['type']=='dnat' for step in result['analysisPath'])
    index=current.configuration.indexes['Hub'].nat['Original Destination']
    from backend.services.firewall_topology import network
    assert 0 in index.find(network('10.43.0.12'))


def test_classified_rule_sheets_also_supply_resolved_evidence(tmp_path,monkeypatch):
    rows=[('One',[['Rule Name','Source Object','Source Resolved','Destination Object','Destination Resolved'],['one','','','known','198.51.100.1']]),
        ('ETC',[['Firewall','Rule Name','Source Object','Source Resolved','Destination Object','Destination Resolved'],['One','one','','','extra-a\nextra-b','198.51.100.2\n198.51.100.3']])]
    monkeypatch.setattr(workbook,'sheets',lambda path:iter(rows))
    result=workbook.load(tmp_path/'fixture.xlsx')['One']
    assert len(result['rules'])==1
    assert result['objects']['extra-a']=='198.51.100.2/32'
    assert result['objects']['extra-b']=='198.51.100.3/32'


def test_anonymized_uploaded_aws_shapes_resolve_exact_attached_groups(tmp_path):
    import json
    from pathlib import Path
    from backend.services.firewall_topology import network
    fixture=json.loads((Path(__file__).parent/'fixtures/firewall_uploaded_aws_shape.json').read_text())
    data=fixture['aws'];private=fixture['queries']['private_target'];public=fixture['queries']['public_target']
    hub=config('Hub',[interface('uplink',public['private'],'WAN')])
    current=service(tmp_path,{'Hub':hub},data)
    topo=current.configuration.topology
    endpoint=topo.resolve(network(private['address']))
    assert endpoint.kind=='AWS_PRIVATE_IP'
    assert endpoint.aws['eniId']==private['eni']
    assert endpoint.aws['instanceId']==private['instance']
    assert endpoint.aws['groupIds']==private['groups'] and len(private['groups'])==10
    endpoint=topo.resolve(network(public['address']))
    assert endpoint.kind=='FIREWALL_PUBLIC_IP'
    assert endpoint.aws['eniId']==public['eni']
    assert endpoint.aws['private_ip']==public['private']
    assert endpoint.aws['groupIds']==public['groups'] and len(public['groups'])==2
    assert endpoint.owner['interface']=='uplink' and endpoint.owner['zone']=='WAN'
    # All sampled rules retain attachment identity after anonymization.
    groups={row['GroupId'] for row in data['security_groups']}
    assert all(rule['GroupId'] in groups for rule in data['security_group_rules'])


def test_unresolved_evidence_identifies_missing_dns_values_not_missing_definition(tmp_path):
    snapshots=topology()
    snapshots['Edge']['rules']=[policy(destination='database')]
    snapshots['Edge']['rules'][0]['Destination Resolved']='database.example.invalid'
    result=check(service(tmp_path,snapshots))
    evidence=workbook.unresolved_evidence(result,snapshots)
    assert evidence==[{'firewall':'Edge','rule':'permit','side':'Destination','object':'database',
        'providedResolved':'database.example.invalid','missing':'resolved_fqdn_addresses'}]


def test_independent_control_diagnostics_do_not_bypass_forward_or_mutate_steps(tmp_path):
    import copy
    snapshots=topology();snapshots['Edge']['rules']=[policy(action='Drop')]
    current=service(tmp_path,snapshots,aws_data());result=check(current,'8.8.4.4')
    before=copy.deepcopy(result['analysisPath'])
    controls=workbook.independent_aws_checks(current,result,'10.41.0.25','8.8.4.4','TCP',443)
    assert controls and all(c['scope']=='INDEPENDENT_CONTROL_CHECK_NOT_FORWARD_REACHABILITY' for c in controls)
    assert result['analysisPath']==before
    assert not any(row['type']=='aws_sg' for row in result['analysisPath'])
    assert result['summary']['status']=='BLOCK'
