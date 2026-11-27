"""Hop-by-hop packet processing over one pinned configuration/topology generation."""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field

from backend.services.aws_security_group_path import AwsSecurityGroupPathService, firewall_step, policy_summary
from backend.services.firewall_path_decisions import decide_policy, progress
from backend.services.firewall_topology import network

log = logging.getLogger('smu.firewall.packet')


@dataclass
class PacketContext:
    original_source: object
    original_destination: object
    source: object
    destination: object
    protocol: str
    port: int | None
    protocol_number: int | None = None
    location: str = 'SOURCE'
    firewall: str | None = None
    ingress: dict | None = None
    ingress_zone: str | None = None
    egress: dict | None = None
    egress_zone: str | None = None
    route: dict | None = None
    gateway: str | None = None
    applied_dnat: list = field(default_factory=list)
    applied_snat: list = field(default_factory=list)
    visited: set = field(default_factory=set)
    visited_firewalls: list = field(default_factory=list)
    hop_count: int = 0
    forward_status: str = 'PROCESSING'
    destination_type: str = 'UNKNOWN_ENDPOINT'
    source_fqdn: str | None = None
    destination_fqdn: str | None = None
    hop_destination: object = None
    hop_port: int | None = None

    def state(self):
        return (self.firewall, str(self.source), str(self.destination), self.port,
            (self.ingress or {}).get('Name'), (self.egress or {}).get('Name'))


class ReturnPathAnalyzer:
    def __init__(self, topology):
        self.topology = topology

    def analyze(self, hops):
        results = []
        for hop in reversed(hops):
            route = self.topology.routes.select(hop['firewall'], hop['source'])
            expected = (hop.get('ingress') or {}).get('Parent Interface') or (hop.get('ingress') or {}).get('Name')
            if not route:
                state, reason = 'UNKNOWN', 'Return Static / Connected / Default Route가 없습니다 · BGP / OSPF / SD-WAN 미수집'
            elif route.get('blackhole', '').casefold() == 'enable':
                state, reason = 'BLOCK', 'Return Blackhole Route'
            elif route.get('ambiguous'):
                state, reason = 'WARNING', 'Return Route의 동등 우선순위 Next Hop이 여러 개입니다'
            elif expected and route.get('interface') != expected:
                state, reason = 'WARNING', 'Return Path 비대칭 가능성 · Forward Ingress와 Return Egress가 다릅니다'
            else:
                state, reason = 'PASS', '설정 기준 Return Routing 확인 · Stateful 응답 정책 재평가 없음'
            results.append({'firewall': hop['firewall'], 'status': state, 'reason': reason, 'route': route})
        status = next((state for state in ('BLOCK', 'UNKNOWN', 'WARNING') if any(row['status'] == state for row in results)), 'PASS')
        return {'required':bool(hops), 'status': status, 'reason': next((row['reason'] for row in results if row['status'] == status), '별도 관리 Firewall Return Hop 없음'), 'hops': results}


class DynamicPathBuilder:
    MAX_HOPS = 64

    def __init__(self, analysis):
        self.analysis, self.topology = analysis, analysis.topology
        self.steps, self.results, self.hops = [], [], []
        self.aws = {direction: {'kind': 'aws_sg', 'label': 'AWS SG ' + label, 'direction': label,
            'state': 'N/A', 'reason': '이 경로에서 AWS ENI를 통과하지 않음'} for direction, label in [('outbound', 'Outbound'), ('inbound', 'Inbound')]}
        self.sg = AwsSecurityGroupPathService(analysis.service.root)
        self.source_endpoint = self.destination_endpoint = None
        self.stopped = False

    def emit(self, kind, label, status, reason, **data):
        step = {'type': kind, 'label': label, 'status': status, 'reason': reason, 'evidence': {}, **data}
        self.steps.append(step)
        log.debug('packet-flow stage=%s firewall=%s status=%s reason_code=%s', kind, data.get('firewall'), status, data.get('reasonCode', kind + '_' + status.lower()))
        if status in {'BLOCK', 'UNKNOWN'}:
            self.stopped = True
        return step

    def aws_control(self, direction, endpoint, peer_query, context):
        if not endpoint:
            return True
        peer = self.topology.resolve(peer_query).aws or {'state': 'N/A'}
        value = self.sg._step(direction, endpoint, peer, peer_query, context.protocol, context.port,
            context.protocol_number, self.topology.aws_data, context.visited_firewalls, False)
        self.aws[direction.lower()] = value
        status = {'PASS': 'PASS', 'FAIL': 'BLOCK'}.get(value['state'], 'UNKNOWN')
        self.emit('aws_sg', value['label'], status, value['reason'], awsSg=value,
            evidence={'ENI': endpoint.get('eniId', ''), 'Instance': endpoint.get('instanceId', ''), 'Direction': direction,
                'Rule': '; '.join(row.get('description') or row.get('ruleId','') for row in value.get('matches',[]) if value['state']!='PASS' or row.get('match')=='MATCH')})
        return not self.stopped

    def _interface(self, firewall, route):
        if not route or route.get('ambiguous'):
            return None
        return self.topology.routes.interface(firewall, route.get('interface')) or (
            {'Name': route['interface'], 'Hardware': route['interface'], 'Zone': route.get('zone')} if route.get('interface') else None)

    def _nat(self, context, snapshot, phase, matched=None):
        # The matching implementation is shared; all selectors come from this context.
        return self.analysis._nat(snapshot, context.source, context.hop_destination if phase == 'SNAT' else context.destination, context.protocol, context.hop_port if phase == 'SNAT' else context.port,
            phase, matched_rule=matched, ingress=context.ingress, egress=context.egress, number=context.protocol_number)

    def dnat(self, context, snapshot):
        if 'NATRule' in snapshot.get('configurationErrors', {}):
            self.emit('configuration', context.firewall + ' NAT Configuration', 'UNKNOWN', 'NATRule Snapshot 수집 실패', firewall=context.firewall)
            return
        nat, issues, _ = self._nat(context, snapshot, 'DNAT')
        if issues:
            self.emit('configuration', context.firewall + ' DNAT', 'UNKNOWN', '; '.join(issues), firewall=context.firewall)
            return
        if not nat:
            return
        row = nat['row']
        target = self.analysis._translated(row.get('Translated Destination'), snapshot)
        translated_port = context.port
        if row.get('Translated Service', '').casefold() not in {'', 'original'}:
            from backend.services.firewall_path_check import PORT_RANGE
            value = snapshot.get('services', {}).get(row['Translated Service'], '')
            ports = PORT_RANGE.findall(value.split('Destination:', 1)[-1]) if 'Destination:' in value else []
            if len(ports) == 1 and (not ports[0][1] or ports[0][0] == ports[0][1]):
                translated_port = int(ports[0][0])
            else:
                target = None
        if target is None:
            self.emit('configuration', context.firewall + ' DNAT', 'UNKNOWN', 'DNAT 주소/서비스 변환을 단일 대상으로 결정할 수 없습니다', firewall=context.firewall)
            return
        old, old_port = context.destination, context.port
        context.destination, context.port = target, translated_port
        context.destination_fqdn = None
        context.applied_dnat.append(row['Rule Name'])
        self.emit('dnat', 'DNAT', 'PASS', f'{old} → {target}', firewall=context.firewall, rule=row['Rule Name'], nat=row,
            translation={'original': str(old), 'translated': str(target), 'originalPort': old_port, 'translatedPort': translated_port})

    def snat(self, context, snapshot, matched):
        nat, issues, _ = self._nat(context, snapshot, 'SNAT', matched)
        if issues:
            self.emit('configuration', context.firewall + ' SNAT', 'UNKNOWN', '; '.join(issues), firewall=context.firewall)
            return
        if not nat:
            return
        row = nat['row']; target = row.get('Translated Source', '')
        translated = network((context.egress or {}).get('IP Address')) if target.casefold() == 'masq' else self.analysis._translated(target, snapshot)
        if translated is None:
            self.emit('configuration', context.firewall + ' SNAT', 'UNKNOWN', 'NAT_UNKNOWN: SNAT Egress IP/Source Object가 Snapshot에 없습니다', firewall=context.firewall)
            return
        old = context.source; context.source = translated
        context.source_fqdn = None
        context.applied_snat.append(row['Rule Name'])
        self.emit('snat', 'SNAT', 'PASS', f'{old} → {target}', firewall=context.firewall, rule=row['Rule Name'], nat=row,
            translation={'original': str(old), 'translated': str(translated)})

    def local_endpoint(self, context, endpoint):
        owner = endpoint.owner or {}
        snapshot = self.analysis.snapshots[context.firewall]
        # Zone Device Access identifies enabled services, not arbitrary port numbers.
        # No service-port/Local ACL collection exists; never infer one from a query port.
        zone = next((row for row in snapshot.get('zones', []) if row.get('Name') == owner.get('zone')), {})
        context.forward_status = 'REACHED'
        self.hops.append({'firewall': context.firewall, 'source': context.source, 'ingress': context.ingress})
        self.emit('firewall_local', context.firewall + ' Local Endpoint', 'UNKNOWN',
            'Firewall Interface까지 도달 · Local Service 포트/ACL 설정 미수집으로 서비스 접근은 판정할 수 없습니다',
            firewall=context.firewall, reachedEndpoint=True, destinationType='FIREWALL_LOCAL_ENDPOINT',
            evidence={'Interface': owner.get('interface', ''), 'Zone': owner.get('zone', ''), 'Device Access': zone.get('Device Access', '')})

    def hop(self, context):
        name = context.firewall
        snapshot = self.analysis.snapshots.get(name)
        if not snapshot or 'FirewallRule' in snapshot.get('configurationErrors', {}):
            self.emit('configuration', name + ' Configuration', 'UNKNOWN', name + ' Configuration Snapshot 없음/수집 실패 · 최신 정보 다시 조회를 실행하세요', firewall=name)
            return None
        context.hop_count += 1
        context.visited_firewalls.append(name)
        if not context.ingress:
            reverse = self.topology.routes.select(name, context.source)
            context.ingress = self._interface(name, reverse)
        context.ingress_zone = (context.ingress or {}).get('Zone')
        arriving = self.topology.resolve(context.destination)
        # AWS EIP translation is applied on arrival, not at the source site's routing hop.
        if arriving.kind == 'FIREWALL_PUBLIC_IP' and arriving.owner['firewall'] == name:
            self.emit('public_address', 'AWS Public ENI', 'PASS', 'Public IP → ENI Private IP → Sophos Interface', firewall=name,
                evidence={'ENI': arriving.aws.get('eniId', ''), 'Interface': arriving.owner['interface'], 'Zone': arriving.owner['zone']})
            if not self.aws_control('Inbound', arriving.aws, context.source, context):
                return None
            context.destination = network(arriving.aws['private_ip'])
            context.ingress = self.topology.routes.interface(name, arriving.owner['parent_interface'])
            context.ingress_zone = arriving.owner['zone']
        context.hop_destination, context.hop_port = context.destination, context.port
        self.dnat(context, snapshot)
        if self.stopped:
            return None
        endpoint = self.topology.resolve(context.destination)
        if endpoint.owner and endpoint.kind in {'FIREWALL_INTERFACE', 'FIREWALL_ALIAS'} and endpoint.owner['firewall'] == name:
            self.local_endpoint(context, endpoint)
            return None
        route = self.topology.routes.select(name, context.destination)
        context.route = route
        context.egress = self._interface(name, route)
        context.egress_zone = (route or {}).get('zone') or (context.egress or {}).get('Zone')
        context.gateway = (route or {}).get('gateway')
        log.debug('packet-flow stage=route firewall=%s route_type=%s ingress_zone=%s egress_zone=%s egress_interface=%s', name, (route or {}).get('routeType'), context.ingress_zone, context.egress_zone, (context.egress or {}).get('Name'))
        state = context.state()
        if state in context.visited:
            self.emit('route', 'Routing Loop', 'UNKNOWN', 'ROUTING_LOOP_DETECTED', firewall=name, reasonCode='ROUTING_LOOP_DETECTED')
            return None
        context.visited.add(state)
        if route and not route.get('ambiguous') and route.get('blackhole', '').casefold() in {'enable', 'enabled', 'true'}:
            self.emit('route', name + ' Blackhole Route', 'BLOCK', 'Blackhole Route', firewall=name, route=route)
            return None
        # Resolve routing before policy; no transit policy can use imaginary Zones.
        if not route or route.get('ambiguous') or not context.egress_zone or not context.ingress_zone:
            reason = ('현재 Static / Connected / Default Route가 없습니다 · BGP / OSPF / SD-WAN 미수집' if not route else
                '동등 우선순위 Route의 Next Hop이 모호합니다' if route.get('ambiguous') else '선택된 Route의 Ingress/Egress Interface/Zone을 식별할 수 없습니다')
            self.emit('route', name + ' Route', 'UNKNOWN', reason, firewall=name, route=route)
            return None
        rows = self.analysis.policy_candidates(snapshot, context.source, context.destination, context.source_fqdn, context.destination_fqdn)
        policy, status, reason = decide_policy(rows, context.source, context.destination, context.protocol, context.port,
            context.ingress_zone, context.egress_zone, context.protocol_number, context.source_fqdn, context.destination_fqdn)
        matched = policy.get('matchedRule')
        step = self.emit('firewall', name + ' Firewall', status, reason, firewall=name,
            ingressZone=context.ingress_zone, egressZone=context.egress_zone, matchedRule=matched,
            action=(matched or {}).get('action'), candidateRules=policy.get('matches', []), route=route,
            confidence='CONFIRMED', natStatus='NOT_REQUIRED', natDecision='NAT_NOT_REQUIRED', evidence={'Ingress Interface': (context.ingress or {}).get('Name', ''), 'Egress Interface': (context.egress or {}).get('Name', '')})
        result = {'firewall': name, 'available': True, 'checkedAt': snapshot.get('checkedAt', ''),
            'expectedZones': {'source': context.ingress_zone, 'destination': context.egress_zone}, 'policy': policy,
            'routing': {'destination': route, 'return': None, 'returnStatus': 'NOT_REACHED'}, 'analysis': step}
        self.results.append(result)
        if self.stopped:
            return None
        self.hops.append({'firewall': name, 'source': context.source, 'ingress': context.ingress})
        self.emit('route', name + ' ' + route['routeType'] + ' Route', 'PASS',
            f"{route['network']} → {route.get('interface', '')}", firewall=name, route=route)
        before_nat=len(context.applied_snat)
        self.snat(context, snapshot, matched)
        if len(context.applied_snat)>before_nat:step.update(natStatus='PASS',natDecision='NAT_APPLIED')
        elif context.egress_zone=='WAN':step['natDecision']='NAT_NO_MATCH'
        if self.stopped:
            return None
        if context.egress_zone == 'WAN' and context.gateway:
            gateway = next((row for row in snapshot.get('gateways', []) if row.get('Gateway IP') == context.gateway),
                {'Name': context.gateway, 'Gateway IP': context.gateway})
            self.emit('gateway', gateway['Name'], 'PASS', '선택된 Route의 Gateway · 설정 기준', firewall=name, gateway=gateway, configurationOnly=True)
        peer, evidence = self.topology.next_firewall(name, context, route)
        if peer:
            context.location = 'VPN_TUNNEL' if context.egress_zone == 'VPN' else 'ANOTHER_FIREWALL'
            step['next_hop'] = {'type': context.location, 'firewall': peer, 'evidence': evidence}
            if evidence != 'gateway_owner':step['confidence']='INFERRED'
            return peer
        if evidence == 'vpn_peer_unresolved':
            self.emit('topology', 'VPN Next Hop', 'UNKNOWN', 'VPN Route는 확인했으나 원격 Firewall/Tunnel 연결을 결정할 수 없습니다', firewall=name)
            return None
        # An external WAN egress may enter our public ENI instead of ending at Internet.
        if endpoint.kind == 'FIREWALL_PUBLIC_IP' and endpoint.owner['firewall'] != name:
            step['next_hop'] = {'type': 'AWS_PUBLIC_ENI', 'firewall': endpoint.owner['firewall']}
            return endpoint.owner['firewall']
        return self.finish(context, endpoint)

    def finish(self, context, endpoint):
        if endpoint.kind == 'AWS_PUBLIC_IP':
            context.destination = network(endpoint.aws['private_ip'])
        if endpoint.aws and not self.aws_control('Inbound', endpoint.aws, context.source, context):
            return None
        if context.route and context.egress_zone == 'WAN' and endpoint.kind in {'MANAGED_HOST', 'SITE_NETWORK', 'AWS_PRIVATE_IP', 'UNKNOWN_ENDPOINT'}:
            self.emit('topology', 'Next Hop', 'UNKNOWN', 'WAN Route만으로 내부 Destination까지의 경로를 증명할 수 없습니다')
            return None
        context.forward_status = 'REACHED'
        context.location = 'FINAL_DESTINATION'
        return None

    def build(self, base, source, destination, protocol, port, number, source_fqdn=None, destination_fqdn=None):
        self.source_endpoint, self.destination_endpoint = self.topology.resolve(source), self.topology.resolve(destination)
        log.debug('packet-flow stage=resolve_destination endpoint_type=%s owner_firewall=%s interface=%s aws_eni_identified=%s', self.destination_endpoint.kind, (self.destination_endpoint.owner or {}).get('firewall'), (self.destination_endpoint.owner or {}).get('interface'), bool(self.destination_endpoint.aws))
        context = PacketContext(source, destination, source, destination, protocol, port, number,
            destination_type=self.destination_endpoint.kind, source_fqdn=source_fqdn, destination_fqdn=destination_fqdn)
        same_vpc = bool(self.source_endpoint.aws and self.destination_endpoint.aws and self.source_endpoint.aws.get('vpcId') and self.source_endpoint.aws.get('vpcId') == self.destination_endpoint.aws.get('vpcId') and self.source_endpoint.aws.get('addressKind') in {'private', 'ipv6'} and self.destination_endpoint.aws.get('addressKind') in {'private', 'ipv6'} and not self.source_endpoint.kind.startswith('FIREWALL_') and not self.destination_endpoint.kind.startswith('FIREWALL_'))
        if self.source_endpoint.aws and self.destination_endpoint.aws:
            self.aws['networkPath'] = {'mode': 'same_vpc' if same_vpc else 'unknown', 'path': [],
                'partialPath': not same_vpc, 'reason': '동일 VPC의 직접 경로' if same_vpc else 'AWS Routing 연결 증거 미수집'}
        if not self.aws_control('Outbound', self.source_endpoint.aws, destination, context):
            return self.complete(base, context)
        if self.source_endpoint.aws and self.destination_endpoint.aws and not same_vpc and self.source_endpoint.aws.get('addressKind') in {'private', 'ipv6'} and self.destination_endpoint.aws.get('addressKind') in {'private', 'ipv6'}:
            self.emit('topology', 'AWS Next Hop', 'UNKNOWN', 'AWS VPC 간 Routing/Transit 연결 정보 미수집 · Site 이름/주소 중첩으로 경로를 추정하지 않습니다')
            return self.complete(base, context)
        source_link = self.topology.connected_owner(source)
        destination_link = self.topology.connected_owner(destination)
        if not same_vpc and source_link and destination_link and (source_link[0], source_link[1].get('Name')) == (destination_link[0], destination_link[1].get('Name')) and not self.source_endpoint.kind.startswith('FIREWALL_') and not self.destination_endpoint.kind.startswith('FIREWALL_'):
            self.emit('network', 'Connected Network', 'PASS', '동일 Connected Network · Gateway Firewall Transit 불필요')
            self.finish(context, self.destination_endpoint)
            return self.complete(base, context)
        first, ingress = (None, None) if same_vpc else self.topology.first_firewall(self.source_endpoint, self.destination_endpoint)
        if first is None:
            if same_vpc:
                self.aws['networkPath'] = {'mode': 'same_vpc', 'path': [], 'partialPath': False, 'reason': '동일 VPC의 직접 경로'}
                self.finish(context, self.destination_endpoint)
            else:
                # Specific NAT publications are evidence of an inbound managed hop.
                candidates = []
                for name, snapshot in self.analysis.snapshots.items():
                    candidate, issues, _ = self.analysis._nat(snapshot, source, destination, protocol, port, 'DNAT', number=number)
                    if candidate and candidate['row'].get('Original Destination'):
                        candidates.append(name)
                if len(candidates) == 1:
                    first = candidates[0]
                else:
                    self.emit('topology', 'Source Next Hop', 'UNKNOWN', 'Source를 관리 Firewall/직접 AWS 경로에 연결할 수 없습니다')
        if first and not self.stopped:
            context.firewall, context.ingress = first, ingress
            while not self.stopped and context.forward_status != 'REACHED':
                if context.hop_count >= self.MAX_HOPS:
                    self.emit('route', 'Hop Limit', 'UNKNOWN', 'MAX_HOP_COUNT_EXCEEDED', reasonCode='MAX_HOP_COUNT_EXCEEDED')
                    break
                peer = self.hop(context)
                if not peer:
                    break
                context.firewall, context.ingress = peer, None
                context.egress, context.route, context.egress_zone = None, None, None
        return self.complete(base, context)

    def complete(self, base, context):
        from backend.services.firewall_path_analysis import _summary
        return_path = ReturnPathAnalyzer(self.topology).analyze(self.hops) if context.forward_status == 'REACHED' else {'status': 'NOT_REACHED', 'reason': 'Forward Path 미완료', 'hops': []}
        for hop in return_path['hops']:
            for result in self.results:
                if result['firewall'] == hop['firewall']:
                    result['routing'].update(returnStatus='FAIL' if hop['status'] == 'BLOCK' else hop['status'], **{'return': hop['route']})
                    result['analysis']['returnRoute'] = {'status': hop['status'], 'route': hop['route']}
        summary = _summary(self.steps, base['source']['input'], base['destination']['input'], context.protocol, base['port'], [], protocol_number=context.protocol_number)
        if any(step.get('confidence')=='INFERRED' for step in self.steps):summary['confidence']='INFERRED'
        if context.forward_status == 'REACHED' and summary['status'] == 'PASS' and return_path['status'] != 'PASS':
            summary.update(status=return_path['status'], primaryReason=return_path['reason'])
        if context.forward_status != 'REACHED':
            context.forward_status = 'BLOCKED' if any(step['status']=='BLOCK' for step in self.steps) else 'UNKNOWN'
        path_progress = progress(self.steps, base['source']['input'], str(context.destination) if context.destination != context.original_destination else base['destination']['input'])
        path_progress['nodes'][-1]['status'] = 'NOT_REACHED' if context.forward_status == 'BLOCKED' else 'UNKNOWN' if context.forward_status != 'REACHED' else summary['status']
        path_progress['links'][-1]['status'] = path_progress['nodes'][-1]['status']
        path_progress['links'][-1]['active'] = context.forward_status != 'BLOCKED'
        steps = ([self.aws['outbound']] if self.aws['outbound']['state'] != 'N/A' else []) + [firewall_step(item) for item in self.results] + ([self.aws['inbound']] if self.aws['inbound']['state'] != 'N/A' else [])
        base.update(mode='PATH', summary=summary, analysisPath=self.steps, pathSteps=self.steps, progress=path_progress,
            path=list(dict.fromkeys(context.visited_firewalls)), partialPath=(self.aws.get('networkPath') or {}).get('partialPath',context.forward_status not in {'REACHED', 'BLOCKED'}),
            firewalls=self.results, steps=steps, awsSecurityGroups=self.aws, policySummary=policy_summary(steps, context.forward_status != 'REACHED'),
            endpoints={'source': self.source_endpoint.public(), 'destination': self.destination_endpoint.public()}, returnPath=return_path,
            forwardPath={'status': context.forward_status, 'hopCount': context.hop_count}, findings=[],
            details={'candidateRules': {row['firewall']: row['policy'].get('matches', []) for row in self.results},
                'destinationOwners': [self.destination_endpoint.owner] if self.destination_endpoint.owner else [],
                'awsSg': self.aws, 'returnPath': return_path,
                'resolvedObjects': {name: {'addresses': self.analysis.snapshots[name].get('objects', {}), 'services': self.analysis.snapshots[name].get('services', {}), 'fqdns': self.analysis.snapshots[name].get('fqdnObjects', {})} for name in context.visited_firewalls}})
        return base
