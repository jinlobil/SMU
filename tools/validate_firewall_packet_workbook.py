"""Offline verification of an exported workbook; no API/DNS calls or source-data constants.

Usage: python tools/validate_firewall_packet_workbook.py WORKBOOK --source IP --destination IP
Optional --aws-json points to already-collected, local AWS network evidence.
The workbook is parsed export evidence, not a replacement for original API XML.
"""
import argparse
import ipaddress
import json
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from zipfile import ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.services.firewall_configuration import ConfigurationIndex
from backend.services.firewall_path_check import FirewallPathCheckService, _networks
from backend.services.firewall_topology import TopologyIndex, network

NS = {'s': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}


def sheets(path):
    with ZipFile(path) as archive:
        shared = []
        if 'xl/sharedStrings.xml' in archive.namelist():
            shared = [''.join(item.itertext()) for item in ET.fromstring(archive.read('xl/sharedStrings.xml'))]
        rels = {row.attrib['Id']: row.attrib['Target'] for row in ET.fromstring(archive.read('xl/_rels/workbook.xml.rels'))}
        for item in ET.fromstring(archive.read('xl/workbook.xml')).find('s:sheets', NS):
            target = rels[item.attrib['{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id']]
            target = target.lstrip('/') if target.startswith('/') else 'xl/' + target
            rows = []
            for row in ET.fromstring(archive.read(target)).findall('s:sheetData/s:row', NS):
                cells = {}
                for cell in row:
                    column = ''.join(ch for ch in cell.attrib['r'] if ch.isalpha())
                    index = 0
                    for ch in column:
                        index = index * 26 + ord(ch) - 64
                    text = ''.join(cell.find('s:is', NS).itertext()) if cell.find('s:is', NS) is not None else cell.findtext('s:v', '', NS)
                    cells[index - 1] = shared[int(text)] if cell.attrib.get('t') == 's' else text
                rows.append([cells.get(i, '') for i in range(max(cells, default=-1) + 1)])
            yield item.attrib['name'], rows


def load(path):
    all_sheets = dict(sheets(path))
    snapshots = {}
    supplemental = {}
    for rows in all_sheets.values():
        if rows and {'Firewall','Rule Name','Source Resolved','Destination Resolved'} <= set(rows[0]):
            for values in rows[1:]:
                record=dict(zip(rows[0],values))
                supplemental.setdefault(record.get('Firewall'),[]).append(record)
    excluded = {'NAT', 'Route', 'Interface', 'Zone', 'Gateway', 'Summary', 'Errors', 'LAN ↔ OFFICE', 'LAN ↔ WAN', 'ETC'}
    for name, rows in all_sheets.items():
        if name in excluded or not rows or rows[0][0] != 'Rule Name':
            continue
        rules = [dict(zip(rows[0], row)) for row in rows[1:] if row and row[0]]
        snapshot = {'metadata': {'snapshot_id': 'offline-' + name}, 'checkedAt': 'offline-export',
            'rules': rules, 'routes': [], 'natRules': [], 'interfaces': [], 'aliases': [], 'zones': [], 'gateways': [],
            'configurationErrors': {}, 'objects': {}, 'services': {}, 'fqdnObjects': {}, 'resolvedFqdnAddresses': {}}
        for position, row in enumerate(rules + supplemental.get(name, []), 1):
            row['_Rule Position'] = str(position)
            for side in ('Source', 'Destination'):
                names = row.get(side + ' Object', '').splitlines()
                resolved = row.get(side + ' Resolved', '')
                row[side.lower() + '_wildcard'] = not names
                if len(names) == 1:
                    snapshot['objects'][names[0]] = '\n'.join(map(str, _networks(resolved)))
                # Direct host lists are exported in the same order as Object names.
                # Only zip complete bare-IP/CIDR lists, never infer addresses from names
                # or split flattened group/range records into guessed memberships.
                bare = [line.strip() for line in resolved.splitlines() if line.strip()]
                try:
                    addresses = [str(ipaddress.ip_network(value, strict=False)) for value in bare]
                except ValueError:
                    addresses = []
                if len(names) > 1 and len(names) == len(addresses):
                    for object_name, address in zip(names, addresses):
                        snapshot['objects'][object_name] = address
                for line in resolved.splitlines():
                    # Export resolution records have the form 'object name (address / mask)'.
                    if ' (' in line and line.endswith(')'):
                        key, value = line.split(' (', 1)
                        addresses = _networks(value[:-1])
                        if addresses:
                            snapshot['objects'][key] = '\n'.join(map(str, addresses))
                for key in names:
                    addresses = _networks(key)
                    if addresses and len(addresses) == 1 and key == str(addresses[0].network_address):
                        snapshot['objects'][key] = str(addresses[0])
            names = row.get('Service', '').splitlines()
            row['service_wildcard'] = not names
            lines = row.get('Service Resolved / Protocol / Port', '').splitlines()
            if len(names) == 1:
                snapshot['services'][names[0]] = '\n'.join(lines)
            for line in lines:
                if ' (' in line:
                    key, detail = line.split(' (', 1)
                    snapshot['services'][key] = detail.rstrip(')')
        snapshots[name] = snapshot
    fields = {'NAT': ('natRules', 'Rule Name'), 'Route': ('routes', 'Destination'),
        'Interface': ('interfaces', 'Name'), 'Zone': ('zones', 'Name'), 'Gateway': ('gateways', 'Name')}
    route_keys = {'Destination': 'destination', 'Netmask': 'netmask', 'Gateway': 'gateway', 'Interface': 'interface',
        'Distance': 'distance', 'Administrative Distance': 'administrative_distance', 'Status': 'status', 'Blackhole': 'blackhole'}
    for sheet, (field, first) in fields.items():
        current, headers = None, []
        for row in all_sheets.get(sheet, []):
            if len(row) == 1:
                current = next((name for name in snapshots if row[0].startswith(name + ' ')), current)
            elif row and row[0] == first:
                headers = row
            elif current and headers and row and row[0]:
                record = dict(zip(headers, row))
                if sheet == 'Route':
                    record = {route_keys[key]: value for key, value in record.items() if key in route_keys}
                selected = 'aliases' if sheet == 'Interface' and record.get('Type') == 'Alias' else field
                snapshots[current][selected].append(record)
    # Resolve references against all supplied parsed Rule sheets. Borrow only a
    # single consistent explicit definition; conflicts stay scoped/unresolved.
    for field in ('objects', 'services'):
        definitions = {}
        for snapshot in snapshots.values():
            for key, value in snapshot[field].items():
                if value:
                    definitions.setdefault(key, set()).add(value)
        for snapshot in snapshots.values():
            for key, values in definitions.items():
                if len(values) == 1 and not snapshot[field].get(key):
                    snapshot[field][key] = next(iter(values))
    return snapshots


def unresolved_evidence(result, snapshots):
    """Only unresolved predicates on actually evaluated policies, not global warnings."""
    evidence=[]
    from backend.services.fqdn import normalize_fqdn
    for hop in result.get('firewalls',[]):
        snapshot=snapshots[hop['firewall']]
        rows={row['Rule Name']:row for row in snapshot['rules']}
        for rule in hop['policy'].get('unresolvedRules',[]):
            row=rows[rule]
            evaluation=next(item for item in hop['policy']['evaluations'] if item['rule']==rule)
            for side in ('Source','Destination'):
                if not evaluation.get(side.lower()+'_resolver_failed'):continue
                resolved=row.get(side+' Resolved','')
                try:
                    normalize_fqdn(resolved,wildcard=True)
                    missing='resolved_fqdn_addresses'
                except ValueError:missing='resolved_object_members'
                evidence.append({'firewall':hop['firewall'],'rule':rule,'side':side,
                    'object':row.get(side+' Object',''),'providedResolved':resolved,'missing':missing})
            if not evaluation.get('serviceMatch') and not row.get('Service Resolved / Protocol / Port'):
                evidence.append({'firewall':hop['firewall'],'rule':rule,'side':'Service',
                    'object':row.get('Service',''),'missing':'resolved_service_conditions'})
    return evidence


def independent_aws_checks(service, result, source, destination, protocol, port):
    """Diagnostic control evaluation; never append assumed reachability to the path."""
    from backend.services.firewall_path_analysis import PathAnalysis
    from backend.services.aws_security_group_path import AwsSecurityGroupPathService
    analysis=PathAnalysis(service);topology=analysis.topology
    endpoint=topology.resolve(network(destination)).aws
    if not endpoint or network(source) is None or network(destination) is None:return []
    peers=[('original_source',network(source),'No claim that the forward path reached this ENI')]
    first,ingress=topology.first_firewall(topology.resolve(network(source)),topology.resolve(network(destination)))
    if first:
        snapshot=analysis.snapshots[first];route=topology.routes.select(first,network(destination))
        egress=analysis._interface(snapshot,route)
        if route and route.get('zone')=='WAN':
            reverse=topology.routes.select(first,network(source))
            match,issues,_=analysis._nat(snapshot,network(source),network(destination),protocol,port,'SNAT',
                ingress=ingress or analysis._interface(snapshot,reverse),egress=egress)
            if match and not issues:
                translated=network((egress or {}).get('IP Address')) if match['row']['Translated Source'].casefold()=='masq' else analysis._translated(match['row']['Translated Source'],snapshot)
                if translated is not None:
                    peers.append(('configured_snat_if_forward_allowed',translated,'Conditional on forward policy allowing the packet; not an applied path event'))
    slices=result.get('serviceResults') or [{'protocol':protocol,'fromPort':port,'toPort':port}]
    checks=[]
    for kind,peer,assumption in peers:
        controls=[]
        for scope in slices:
            value=AwsSecurityGroupPathService(service.root)._step('Inbound',endpoint,topology.resolve(peer).aws or {'state':'N/A'},peer,
                scope['protocol'],scope['fromPort'],scope.get('protocolNumber'),topology.aws_data,result.get('path',[]),False)
            controls.append({'protocol':scope['protocol'],'fromPort':scope['fromPort'],'toPort':scope['toPort'],
                'state':value['state'],'reason':value['reason'],'matchedRuleIds':[item.get('ruleId') for item in value.get('matches',[]) if item['match']=='MATCH'],
                'uncollectedPrefixListIds':sorted({item['prefixListId'] for item in value.get('matches',[]) if item.get('prefixListId') not in {None,'-',''}})})
        checks.append({'scope':'INDEPENDENT_CONTROL_CHECK_NOT_FORWARD_REACHABILITY','sourceKind':kind,'peer':str(peer),'assumption':assumption,
            'eniId':endpoint.get('eniId'),'attachedGroupIds':endpoint.get('groupIds'),'controls':controls})
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('workbook', type=Path)
    parser.add_argument('--aws-json', type=Path)
    parser.add_argument('--source', required=True)
    parser.add_argument('--destination', required=True)
    parser.add_argument('--port', type=int)
    parser.add_argument('--protocol', default='TCP')
    args = parser.parse_args()
    snapshots = load(args.workbook)
    aws = json.loads(args.aws_json.read_text()) if args.aws_json else {}
    with tempfile.TemporaryDirectory() as directory:
        service = FirewallPathCheckService(Path(directory))
        store = service.configuration
        store.snapshots = snapshots
        store.indexes = {name: ConfigurationIndex(row) for name, row in snapshots.items()}
        store.aws_data = aws
        store.topology = TopologyIndex(snapshots, store.indexes, aws)
        service.firewalls.configurations = lambda: [{'name': name, 'configured': True} for name in snapshots]
        result = service.check(args.source, args.destination, args.protocol, args.port)
        print(json.dumps({'summary': result['summary'], 'path': result['path'], 'endpoints': result['endpoints'],
            'forwardPath': result['forwardPath'], 'returnPath': result['returnPath'],
            'unresolvedEvidence': unresolved_evidence(result,snapshots),
            'independentAwsChecks':independent_aws_checks(service,result,args.source,args.destination,args.protocol,args.port),
            'steps': [{key: step.get(key) for key in ('type', 'firewall', 'status', 'reason', 'rule', 'matchedRule', 'route')} for step in result['analysisPath']],
            'serviceResults': [{key: case.get(key) for key in ('protocol', 'fromPort', 'toPort', 'summary')} for case in result.get('serviceResults', [])],
            'limitations': ['Offline validation only; independent control checks do not assert forward reachability.', 'Only unresolved predicates on evaluated rules are listed; no live DNS/API calls.', *([] if args.aws_json else ['No AWS cache supplied.'])]}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
