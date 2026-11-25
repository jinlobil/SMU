"""Configuration-based path/reachability analysis. Never sends probe traffic."""
import copy
import ipaddress
import json
from datetime import datetime, timezone
from itertools import product

from backend.services.aws_security_group_path import AwsSecurityGroupPathService, firewall_step, policy_summary
from backend.services.firewall_network_mapping import NETWORK_MAPPINGS, resolve_input_network, expected_zones_for_path
from backend.services.firewall_rule_export import _restore_rule_order, is_wildcard_value
from backend.services.firewall_path_decisions import decide_policy, interface_network, service_slices, progress


def _unique(values): return list(dict.fromkeys(values))


def _summary(steps, source, destination, protocol, port, warnings, partial=False, protocol_number=None):
    reached = [step for step in steps if step['status'] != 'NOT_REACHED']
    block = next((step for step in reached if step['status'] == 'BLOCK'), None)
    unknown = next((step for step in reached if step['status'] == 'UNKNOWN'), None)
    status = 'BLOCK' if block else 'UNKNOWN' if unknown or not reached else 'WARNING' if warnings or any(step['status']=='WARNING' for step in reached) else 'PASS'
    reason = block['reason'] if block else unknown['reason'] if unknown else 'Configuration 기준 허용' if status=='PASS' else 'Configuration 기준 분석 완료 · 조건별 결과/경로 차이가 있습니다'
    matched = (block or {}).get('matchedRule') or {}
    return {'status':status,'source':source,'destination':destination,
        'service': f'IP / Protocol No. {protocol_number if protocol_number is not None else "ANY"}' if protocol=='IP' else f'{protocol} / {port if port is not None else "ANY"}',
        'primaryReason':reason,'blockedAt':((block.get('firewall') or block['label']) if block else None),
        'matchedRule':matched.get('rule'),'action':(block or {}).get('action'),
        'ingressZone':(block or {}).get('ingressZone'),'egressZone':(block or {}).get('egressZone'),
        'warnings':_unique(warnings),'confidence':'UNKNOWN' if unknown and not block else 'INFERRED' if warnings else 'CONFIRMED'}


class PathAnalysis:
    def __init__(self, service, refresh=False):
        self.service, self.refresh = service, refresh
        self.snapshots = {}
        self.configs = {item['name']: item for item in service.firewalls.configurations()}
        self.dns = {}
        self.aws_data = None

    def snapshot(self, name):
        if name not in self.snapshots:
            config = self.configs.get(name)
            if not config or not config.get('configured'): return None
            try: self.snapshots[name] = self.service._snapshot(config, self.refresh)
            except Exception:
                self.snapshots[name] = {'rules': [], 'routes': [], 'routeError': 'Configuration unavailable',
                                        'configurationErrors': {'FirewallRule': 'Configuration unavailable'}, 'checkedAt': ''}
        return self.snapshots[name]

    def endpoint(self, value, side):
        from backend.services.firewall_path_check import _query_endpoint
        key = value.strip()
        if key not in self.dns: self.dns[key] = _query_endpoint(key, side)
        return self.dns[key]

    def analyze(self, source, destination, protocol, port, protocol_number, _partition=True):
        from backend.services.firewall_path_check import normalize_service
        source, destination = str(source or '').strip(), str(destination or '').strip()
        if not source and not destination: raise ValueError('Source 또는 Destination을 입력하세요')
        protocol, port, number = normalize_service(protocol, port, protocol_number)
        if not source or not destination:
            return self.reachability(source, destination, protocol, port, number)
        src, dst = self.endpoint(source, 'Source'), self.endpoint(destination, 'Destination')
        if not src[1] and not dst[1] and src[0].version != dst[0].version:
            raise ValueError('Source/Destination은 같은 IP address family를 사용해야 합니다')
        base = self.service._check_legacy(source, destination, protocol, port, self.refresh, number,
                                          _snapshots=self.snapshots, _endpoints=(src, dst))
        if not src[1] and not dst[1]:
            if _partition and (src[0].num_addresses>1 or dst[0].num_addresses>1):
                scoped=self.network_analysis(base,src[0],dst[0],protocol,port,number)
                if scoped is not None:return scoped
            if protocol=='IP' and number in {1,6,17,58}:
                effective={1:'ICMP',6:'TCP',17:'UDP',58:'ICMPV6'}[number]
                result=self.service_analysis(base,src[0],dst[0],effective,None) if effective in {'TCP','UDP'} else self.enhance(base,src[0],dst[0],effective,None,None)
                result['summary']['service']=f'IP / Protocol No. {number}'
                return result
            if protocol == 'ANY' or protocol in {'TCP','UDP'} and port is None or protocol == 'IP' and number is None:
                return self.service_analysis(base, src[0], dst[0], protocol, number)
            return self.enhance(base, src[0], dst[0], protocol, port, number)
        sources = src[2] if src[1] else [str(src[0])]
        destinations = dst[2] if dst[1] else [str(dst[0])]
        variants = []
        for i, (s, d) in enumerate(product(sources, destinations)):
            if i >= 256: break
            a, b = ipaddress.ip_network(s), ipaddress.ip_network(d)
            if a.version != b.version:
                variants.append({'source': s, 'destination': d, 'summary': {'status':'UNKNOWN','primaryReason':'IP address family mismatch'}, 'analysisPath': []}); continue
            pair = self.service._check_legacy(s, d, protocol, port, self.refresh, number, _snapshots=self.snapshots)
            pair = self.service_analysis(pair, a, b, protocol, number, src[1], dst[1]) if protocol=='ANY' or protocol in {'TCP','UDP'} and port is None or protocol=='IP' and number is None else self.enhance(pair, a, b, protocol, port, number, src[1], dst[1])
            variants.append({'source':s, 'destination':d, 'summary':pair['summary'], 'analysisPath':pair['analysisPath'], 'details':pair['details'], 'progress':pair['progress'], 'serviceResults':pair.get('serviceResults',[])})
        total = len(sources) * len(destinations)
        signatures = {(item['summary']['status'], tuple((step.get('type'), step.get('firewall'), step.get('ingressZone'), step.get('egressZone'), step.get('status'), (step.get('matchedRule') or {}).get('rule'), step.get('rule'), (step.get('route') or {}).get('network')) for step in item['analysisPath'])) for item in variants}
        if variants:
            summary = copy.deepcopy(variants[0]['summary']); summary['source'], summary['destination'] = source, destination
            if len(signatures) > 1 or len(variants) != total:
                summary.update(status='WARNING', primaryReason='MIXED RESULT · Resolve IP별 경로/판정 결과가 다릅니다', blockedAt=None, matchedRule=None, action=None, confidence='CONFIRMED')
                summary['warnings'] = _unique(summary.get('warnings', []) + ['Resolve IP별 결과를 선택하여 해당 경로를 볼 수 있습니다'])
            base.update(summary=summary, analysisPath=variants[0]['analysisPath'], pathSteps=variants[0]['analysisPath'], pathContext=variants[0]['source']+' → '+variants[0]['destination'], details={'ipResults':variants})
        else:
            base.update(summary={'status':'UNKNOWN','source':source,'destination':destination,'service':f'{protocol} / {port or "ANY"}',
                'primaryReason':'FQDN Resolve 실패 · 주소 기반 경로 확인 불가','blockedAt':None,'warnings':['DNS가 유효한 주소를 반환하지 않았습니다'],'confidence':'UNKNOWN'}, analysisPath=[], details={'ipResults':[]})
        base['progress'] = variants[0].get('progress', {}) if variants else progress([], source, destination)
        base.update(mode='PATH', resolvedResults=variants, resolvedPairCount=total, analyzedPairCount=len(variants))
        return base

    def _networks(self, value, snapshot):
        from backend.services.firewall_path_check import _networks
        try: return [ipaddress.ip_network(value, strict=False)]
        except (ValueError, TypeError):
            if value in snapshot.get('objects', {}): return _networks(snapshot['objects'][value])
            if value in snapshot.get('fqdnObjects', {}):
                return [ipaddress.ip_network(address) for pattern in snapshot['fqdnObjects'][value] if '*' not in pattern for address in self.object_addresses(pattern)]
            for mapping in NETWORK_MAPPINGS:
                if value in (mapping.site,*mapping.aliases):return [mapping.network]
            for row in snapshot.get('interfaces', []) + snapshot.get('aliases', []):
                if value in {row.get('Name'), row.get('Hardware')}:
                    try: return [ipaddress.ip_network(row['IP Address'])]
                    except (ValueError, KeyError): pass
        return []

    def _route(self, snapshot, network):
        from backend.services.firewall_path_check import match_static_route
        if network is None: return None
        connected=[]
        for row in snapshot.get('interfaces',[]) + snapshot.get('aliases',[]):
            cidr=interface_network(row)
            if cidr is not None and network.version==cidr.version and network.subnet_of(cidr):
                connected.append({'network':str(cidr),'destination':str(cidr.network_address),'netmask':str(cidr.prefixlen),
                    'interface':row.get('Parent Interface') or row['Name'],'gateway':'','source':'connected_interface',
                    'routeType':'Connected','zone':row.get('Zone',''),'description':'Interface IP/Netmask로 계산한 직접 연결망'})
        static=match_static_route(snapshot.get('routes',[]),network)
        candidates=connected + ([{**static,'source':'static','routeType':'Static','description':static.get('description','Static longest-prefix match')}] if static else [])
        if not candidates: return None
        # Connected wins equal prefixes; a more specific static route still wins LPM.
        route=max(candidates,key=lambda row:(ipaddress.ip_network(row['network']).prefixlen,row['routeType']=='Connected'))
        if route['routeType']=='Static':
            alternatives=[match_static_route([row],network) for row in snapshot.get('routes',[])]
            alternatives=[row for row in alternatives if row and row['network']==route['network']]
            def distance(row):
                try:return int(row.get('distance') or row.get('administrative_distance') or 1)
                except (ValueError,TypeError):return 1
            best=min(map(distance,alternatives));alternatives=[row for row in alternatives if distance(row)==best]
            route={**min(alternatives,key=distance),'source':'static','routeType':'Static','description':route['description']}
            if len({(row.get('gateway',''),row.get('interface',''),row.get('blackhole','')) for row in alternatives})>1:
                route.update(ambiguous=True,alternatives=alternatives)
        interface=self._interface(snapshot,route)
        if interface:route['zone']=interface.get('Zone','')
        elif route.get('interface','').casefold().startswith('xfrm'):route['zone']='VPN'
        return route

    def _zone(self, snapshot, route, expected):
        interface=self._interface(snapshot,route)
        if interface and interface.get('Zone'):return interface['Zone'],interface,'CONFIRMED'
        if route and route.get('zone'):return route['zone'],interface,'CONFIRMED'
        if expected:
            candidates=[row for row in snapshot.get('interfaces',[]) if row.get('Zone')==expected]
            return expected,candidates[0] if len(candidates)==1 else None,'INFERRED'
        return None,None,'UNKNOWN'

    def _interface(self, snapshot, route):
        if (route or {}).get('ambiguous'): return None
        name = (route or {}).get('interface', '')
        matches = [row for row in snapshot.get('interfaces', []) if name in {row.get('Name'),row.get('Hardware')}]
        return matches[0] if len(matches) == 1 else None

    def _owners(self, network):
        owners = []
        if network is None or network.num_addresses != 1: return owners
        for name, config in self.configs.items():
            if not config.get('configured'): continue
            snapshot = self.snapshot(name) or {}
            for row in snapshot.get('interfaces', []) + snapshot.get('aliases', []):
                try: match = ipaddress.ip_address(row.get('IP Address','')) == network.network_address
                except ValueError: match = False
                if match: owners.append({'firewall':name, **row})
        return owners

    def _nat(self, snapshot, source, destination, protocol, port, phase, interface=None, matched_rule=None):
        from backend.services.firewall_path_check import service_match_details
        candidates = []
        for row in snapshot.get('natRules', []):
            if row.get('Status','').casefold() not in {'enable','enabled'}: continue
            field = 'Translated Destination' if phase == 'DNAT' else 'Translated Source'
            if row.get(field,'').casefold() in {'','original'}: continue
            uncertainty, rejected = [], False
            for key, query in [('Original Source',source),('Original Destination',destination)]:
                values = row.get(key,'').splitlines()
                if not values: uncertainty.append(key + ' omitted'); continue
                if any(is_wildcard_value(value) for value in values): continue
                networks = [net for value in values for net in self._networks(value, snapshot)]
                if not networks: uncertainty.append(key + ' unresolved'); continue
                if query is None or not any(query.version == net.version and query.subnet_of(net) for net in networks): rejected = True
            services = row.get('Original Service','').splitlines()
            if not services: uncertainty.append('Original Service omitted')
            elif not any(is_wildcard_value(value) for value in services):
                resolved = '\n'.join(snapshot.get('services',{}).get(value,'') for value in services)
                if not resolved: uncertainty.append('Original Service unresolved')
                elif not service_match_details(protocol, port, '\n'.join(services), resolved)['serviceMatch']: rejected = True
            selectors = row.get('Inbound Interface' if phase=='DNAT' else 'Outbound Interface','').splitlines()
            if selectors and not any(is_wildcard_value(value) for value in selectors):
                if not interface: uncertainty.append('Interface unresolved')
                elif not any(value in {interface.get('Name'), interface.get('Hardware')} for value in selectors): rejected = True
            if matched_rule and row.get('Linked Firewall Rule') and matched_rule['rule'] not in row['Linked Firewall Rule'].splitlines(): rejected = True
            if not rejected: candidates.append({'row':row, 'warnings':uncertainty})
        if len(candidates) > 1:
            # Restore against the complete NAT list, not just a subset of matches.
            complete = [{**row, '_Rule Position':row.get('Position',''), '_Rule After':row.get('After Rule','')} for row in snapshot.get('natRules', [])]
            from backend.services.firewall_path_check import _position
            numeric=[_position(row['_Rule Position']) for row in complete]
            if all(value is not None for value in numeric) and len(set(numeric))==len(numeric):
                for row,position in zip(complete,numeric):row['_Rule Order']=position
                reliable=True
            else:reliable=_restore_rule_order(complete)
            if reliable:
                positions = {row['Rule Name']:row['_Rule Order'] for row in complete}
                candidates.sort(key=lambda item: positions[item['row']['Rule Name']])
            else: return None, ['API에 NAT Position/After 순서가 없어 상충하는 NAT 우선순위를 결정할 수 없습니다'], candidates
        return (candidates[0] if candidates else None), [], candidates

    def _translated(self, value, snapshot):
        networks = self._networks(value, snapshot)
        return networks[0] if len(networks)==1 and networks[0].num_addresses==1 else None

    def object_addresses(self, pattern):
        try:return self.endpoint(pattern,'Object')[2]
        except (ValueError,OSError):return []

    def network_analysis(self, base, source, destination, protocol, port, number):
        from backend.services.firewall_path_check import _networks
        if not (base.get('awsSecurityGroups',{}).get('networkPath') and not base['path']):
            for name,config in self.configs.items():
                if config.get('configured'):self.snapshot(name)
        cuts=[]
        for snapshot in self.snapshots.values():
            cuts += [net for row in snapshot.get('interfaces',[])+snapshot.get('aliases',[]) if (net:=interface_network(row)) is not None]
            for row in snapshot.get('routes',[]):
                try:cuts.append(ipaddress.ip_network(row['destination'] if '/' in row['destination'] else row['destination']+'/'+(row.get('netmask') or '32'),strict=False))
                except (KeyError,ValueError):pass
            for row in snapshot.get('rules',[]):
                cuts += _networks(row.get('Source Resolved',''))+_networks(row.get('Destination Resolved',''))
            for row in snapshot.get('natRules',[]):
                cuts += [net for field in ('Original Source','Original Destination') for value in row.get(field,'').splitlines() for net in self._networks(value,snapshot)]
        def partition(network):
            pieces=[network]
            for cut in sorted(set(cuts),key=lambda item:item.prefixlen):
                if cut.version!=network.version:continue
                updated=[]
                for scope in pieces:
                    if cut!=scope and cut.subnet_of(scope):updated.extend([cut,*scope.address_exclude(cut)])
                    else:updated.append(scope)
                pieces=updated
            return sorted(pieces,key=lambda item:(int(item.network_address),item.prefixlen))
        sources,destinations=partition(source),partition(destination)
        if len(sources)==len(destinations)==1:return None
        cases=[]
        for index,(src,dst) in enumerate(product(sources,destinations)):
            if index>=256:break
            result=self.analyze(str(src),str(dst),protocol,port,number,_partition=False)
            cases.append({'source':str(src),'destination':str(dst),'target':str(src)+' → '+str(dst),
                'summary':result['summary'],'analysisPath':result['analysisPath'],'progress':result['progress'],
                'serviceResults':result.get('serviceResults',[]),'_result':result})
        representative=next((case for case in cases if case['summary']['status']=='BLOCK'),cases[0])
        original=(base['source'],base['destination'])
        base.update(representative['_result'])
        base['source'],base['destination']=original
        base['summary']=copy.deepcopy(representative['summary'])
        states={case['summary']['status'] for case in cases}
        total=len(sources)*len(destinations)
        if len(states)>1 or len(cases)!=total:
            base['summary'].update(status='WARNING',primaryReason='Network 분석 한도 256개를 초과하여 일부 범위는 미분석입니다' if len(cases)!=total else 'Network 범위별 결과 상이 · 주소 구간별 판정 결과를 제공합니다',blockedAt=None,matchedRule=None,action=None)
        base['summary'].update(source=original[0]['input'],destination=original[1]['input'])
        base['pathContext']='표시 경로: '+representative['target']
        for case in cases:case.pop('_result',None)
        base.update(networkResults=cases,networkCoverage={'total':total,'analyzed':len(cases)})
        return base

    def resolved_rules(self, snapshot, source_fqdn, destination_fqdn):
        from backend.services.fqdn import fqdn_matches
        rows=copy.deepcopy(snapshot.get('rules',[]))
        for row in rows:
            for side,typed in (('Source',source_fqdn),('Destination',destination_fqdn)):
                patterns=row.get('_'+side+' FQDNs',[])
                if not patterns or typed and any(fqdn_matches(typed,pattern) for pattern in patterns):continue
                addresses=[]
                for pattern in patterns:
                    if '*' in pattern:continue
                    addresses+=self.object_addresses(pattern)
                if addresses:row[side+' Resolved']='\n'.join(addresses)
                else:row.setdefault('_Object Resolution Errors',[]).append(side+' FQDN DNS Resolve 실패 또는 wildcard FQDN의 구체적 주소 데이터 없음')
        return rows

    def service_analysis(self, base, source, destination, protocol, number, source_fqdn=None, destination_fqdn=None):
        # Discover snapshots once before building interval boundaries, including NAT services.
        self.enhance(copy.deepcopy(base), source, destination, 'TCP' if protocol=='ANY' else protocol, 1 if protocol in {'ANY','TCP','UDP'} else None, number, source_fqdn, destination_fqdn)
        if self.aws_data is None:
            try:self.aws_data=json.loads((self.service.root/'cache/aws.json').read_text(encoding='utf-8'))
            except (OSError,ValueError):self.aws_data={}
        original_endpoints=(base['source'],base['destination'])
        original_service=(base['protocol'],base['port'],base.get('protocolNumber'))
        slices=service_slices(protocol,None,number,list(self.snapshots.values()),self.aws_data)
        cases=[]
        for current,start,end,coverage in slices[:1024]:
            numbers=list(coverage) if isinstance(coverage,tuple) else [coverage]
            num=numbers[0]
            pair=self.service._check_legacy(str(source),str(destination),current,start,self.refresh,num,_snapshots=self.snapshots)
            pair=self.enhance(pair,source,destination,current,start,num,source_fqdn,destination_fqdn)
            signature=(pair['summary']['status'],tuple((step['type'],step.get('firewall'),step['status'],(step.get('matchedRule') or {}).get('rule'),step.get('rule')) for step in pair['analysisPath']))
            if cases and cases[-1]['protocol']==current and cases[-1]['protocolNumber']==num and cases[-1]['_signature']==signature and start is not None and cases[-1]['toPort']==start-1:
                cases[-1]['toPort']=end
            else:
                cases.append({'protocol':current,'fromPort':start,'toPort':end,'protocolNumber':num,'protocolNumbers':numbers if current=='IP' else [],'summary':pair['summary'],
                    'analysisPath':pair['analysisPath'],'progress':pair['progress'],'_signature':signature,'_result':pair})
        # Group IP protocol numbers with identical outcomes without losing coverage.
        merged=[]
        for case in cases:
            signature=case.pop('_signature')
            if case['protocol']=='IP' and merged and merged[-1]['protocol']=='IP' and merged[-1].get('_signature')==signature:
                merged[-1]['protocolNumbers'].extend(case['protocolNumbers'])
            else:
                case['_signature']=signature
                if case['protocol']=='IP':case.setdefault('protocolNumbers',[case['protocolNumber']])
                merged.append(case)
        for case in merged:case.pop('_signature',None)
        representative=next((case for case in merged if case['summary']['status']=='BLOCK'),merged[0])
        base.update(representative['_result'])
        base['source'],base['destination']=original_endpoints
        base['protocol'],base['port'],base['protocolNumber']=original_service
        for case in merged:case.pop('_result',None)
        base.update(summary=copy.deepcopy(representative['summary']),analysisPath=representative['analysisPath'],progress=representative['progress'],serviceResults=merged,mode='PATH')
        states={case['summary']['status'] for case in merged}
        base['summary']['service']=f'{protocol} / ANY'
        if len(states)>1 or len(slices)>1024:
            base['summary'].update(status='WARNING',primaryReason='서비스 분석 한도 1024개를 초과하여 일부 범위는 미분석입니다' if len(slices)>1024 else '서비스별 결과 상이 · 서비스 범위별 판정 결과를 제공합니다',blockedAt=None,matchedRule=None,action=None,ingressZone=None,egressZone=None,confidence='CONFIRMED')
        elif states=={'BLOCK'}:
            base['summary']['primaryReason']='전체 요청 서비스 범위가 차단됩니다 · '+representative['summary']['primaryReason']
        base['pathContext']=f"표시 경로: {representative['protocol']} / {representative['fromPort'] if representative['fromPort']==representative['toPort'] else str(representative['fromPort'])+'–'+str(representative['toPort'])}"
        base.setdefault('details',{})['serviceCoverage']={'partitionCount':len(slices),'analyzedCount':min(len(slices),1024)}
        base['summary']['source']=base['source']['input'];base['summary']['destination']=base['destination']['input']
        return base

    def enhance(self, base, source, destination, protocol, port, number, source_fqdn=None, destination_fqdn=None):
        packet_source,packet_destination,packet_port=source,destination,port
        warnings,path_steps,results,returns,notes=[],[],[],[],[]
        path=list(base['path'])
        # Legacy mapping can return the first site overlapping a broad CIDR.
        # An overlap is not ownership of the entire requested address scope.
        valid_site_hops=set()
        invalid_site_hops=set()
        for endpoint,network in ((base['source'],source),(base['destination'],destination)):
            firewall=endpoint.get('managedFirewall')
            if not firewall:continue
            contained=any(mapping.site==endpoint.get('site') and network.version==mapping.network.version and network.subnet_of(mapping.network) for mapping in NETWORK_MAPPINGS)
            (valid_site_hops if contained else invalid_site_hops).add(firewall)
        path=[name for name in path if name not in invalid_site_hops-valid_site_hops]
        aws_direct=bool(base.get('awsSecurityGroups',{}).get('networkPath')) and not path
        owners=[] if aws_direct else self._owners(destination)
        for owner in owners:
            if owner['firewall'] not in path:path.append(owner['firewall'])
        if not path and not aws_direct:
            published=[]
            for name,snapshot in self.snapshots.items():
                candidate,issues,_=self._nat(snapshot,source,destination,protocol,port,'DNAT')
                if candidate and not issues and not any(is_wildcard_value(value) for value in candidate['row'].get('Original Destination','').splitlines()):published.append(name)
            if len(published)==1:path.append(published[0])
        if not path and not aws_direct:
            connected=[]
            for name,snapshot in self.snapshots.items():
                for row in snapshot.get('interfaces',[]):
                    network=interface_network(row)
                    if network is not None and source.version==network.version and source.subnet_of(network):connected.append((network.prefixlen,name))
            if connected:
                longest=max(prefix for prefix,name in connected)
                candidates=_unique(name for prefix,name in connected if prefix==longest)
                if len(candidates)==1:path.append(candidates[0])
        for name in path:
            snapshot=self.snapshot(name)
            if snapshot is None:
                path_steps.append({'type':'firewall','firewall':name,'label':name+' Firewall','status':'UNKNOWN',
                    'reason':name+' Firewall API 연결 설정/응답이 없어 정책을 조회하지 못했습니다','confidence':'UNKNOWN'})
                results.append({'firewall':name,'available':False,'policy':{'state':'unavailable'},'routing':{'destination':None,'return':None}})
                continue
            errors=snapshot.get('configurationErrors',{})
            warnings.extend(f'{name} {entity} API 조회 실패: {message}' for entity,message in errors.items())
            expected=expected_zones_for_path(base['source'],base['destination'],path).get(name,(None,None))
            return_route=self._route(snapshot,packet_source)
            source_zone,ingress,ingress_confidence=self._zone(snapshot,return_route,expected[0])
            original_destination,original_port=packet_destination,packet_port
            nat,nat_warnings,candidates=self._nat(snapshot,packet_source,packet_destination,protocol,packet_port,'DNAT',ingress)
            warnings.extend(f'{name} {message}' for message in nat_warnings)
            nat_status='UNKNOWN' if nat_warnings or 'NATRule' in errors else 'NOT_REQUIRED'
            nat_steps=[]
            if nat:
                row=nat['row'];translated=self._translated(row['Translated Destination'],snapshot)
                nat_status='PASS' if translated is not None and not nat['warnings'] else 'UNKNOWN'
                old=packet_destination
                if translated is not None:packet_destination=translated
                if row.get('Translated Service','').casefold() not in {'','original'}:
                    from backend.services.firewall_path_check import PORT_RANGE
                    text=snapshot.get('services',{}).get(row['Translated Service'],'')
                    ports=PORT_RANGE.findall(text.split('Destination:',1)[-1]) if 'Destination:' in text else []
                    if len(ports)==1 and (not ports[0][1] or ports[0][0]==ports[0][1]):packet_port=int(ports[0][0])
                    else:nat_status='UNKNOWN'
                reason=f'{old} → {packet_destination}' if nat_status=='PASS' else 'DNAT에 필요한 주소/서비스 Object가 API 결과에 없거나 단일 변환을 결정할 수 없습니다'
                event={'type':'dnat','firewall':name,'label':'DNAT','status':nat_status,'reason':reason,'rule':row['Rule Name'],'nat':row,
                    'translation':{'original':str(old),'translated':str(packet_destination),'originalPort':original_port,'translatedPort':packet_port}}
                path_steps.append(event);nat_steps.append(event)
            route=self._route(snapshot,packet_destination)
            if route and not route.get('ambiguous') and route.get('gateway') and len(path)<len(self.configs):
                try:peers=self._owners(ipaddress.ip_network(route['gateway']))
                except ValueError:peers=[]
                next_hops=_unique(peer['firewall'] for peer in peers if peer['firewall']!=name)
                if len(next_hops)==1 and next_hops[0] not in path:path.append(next_hops[0])
            destination_zone,egress,egress_confidence=self._zone(snapshot,route,expected[1])
            target_site=resolve_input_network(str(packet_destination)) or {}
            target_firewall=target_site.get('managedFirewall')
            if route and route.get('routeType')=='Static' and destination_zone=='VPN' and target_firewall and target_firewall not in path and len(path)<len(self.configs):
                path.append(target_firewall)
            confidence='CONFIRMED' if ingress_confidence==egress_confidence=='CONFIRMED' else 'INFERRED'
            if expected and (source_zone,destination_zone)!=expected and any(expected):notes.append(f'{name} 실제 Interface Zone을 Topology 예상 Zone보다 우선 적용했습니다')
            policy,status,reason=decide_policy(self.resolved_rules(snapshot,source_fqdn,None if nat else destination_fqdn),packet_source,packet_destination,protocol,packet_port,
                source_zone,destination_zone,number,source_fqdn,None if nat else destination_fqdn)
            matched=policy.get('matchedRule')
            if 'FirewallRule' in errors:status='UNKNOWN';reason=f'{name} FirewallRule API 조회 실패로 정책 판정이 불가능합니다'
            elif nat_status=='UNKNOWN':status='UNKNOWN';reason=f'{name} NAT API/참조 Object/우선순위 데이터가 없어 변환 후 정책을 계산할 수 없습니다'
            elif not source_zone or not destination_zone:
                # Any-zone rules remain decidable even without a route-derived zone.
                from backend.services.firewall_path_check import zone_match
                relevant=[row for row in policy.get('evaluations',[]) if row.get('addressCandidate') and row.get('serviceMatch')]
                if any(not zone_match('unresolved-zone',row['sourceZone'] if not source_zone else 'Any') or not zone_match('unresolved-zone',row['destinationZone'] if not destination_zone else 'Any') for row in relevant):
                    status='UNKNOWN';reason='필요한 Ingress/Egress Zone의 Interface/Route 데이터가 없습니다'
            step={'type':'firewall','firewall':name,'label':name+' Firewall','status':status,'reason':reason,
                'ingressZone':source_zone,'egressZone':destination_zone,'ingressInterface':ingress,'egressInterface':egress,
                'matchedRule':matched,'action':(matched or {}).get('action',''),'route':route,'confidence':confidence,
                'candidateRules':policy.get('matches',[]),'nat':nat_steps,'natStatus':nat_status,
                'evidence':{'Source Zone':source_zone,'Destination Zone':destination_zone,'Source Match':(matched or {}).get('sourceObject'),
                    'Destination Match':(matched or {}).get('destinationObject'),'Service Match':(matched or {}).get('service'), 'Action':(matched or {}).get('action')}}
            path_steps.append(step)
            route_status='UNKNOWN' if not route else 'WARNING' if route.get('ambiguous') else 'BLOCK' if route.get('blackhole','').casefold()=='enable' else 'PASS'
            route_reason=('현재 Static / Connected Route에 목적지 경로가 없습니다. BGP / OSPF / SD-WAN Route는 수집 범위 밖이므로 이후 경로를 판정할 수 없습니다' if not route else
                '동일 Prefix/Distance의 복수 Route로 ECMP 경로가 존재합니다' if route.get('ambiguous') else 'Destination Blackhole Route' if route_status=='BLOCK' else
                f"{route['routeType']} {route['network']} → {route.get('interface','')}")
            path_steps.append({'type':'route','firewall':name,'label':'Destination Route','status':route_status,'reason':route_reason,'route':route})
            snat,snat_warnings,_=self._nat(snapshot,packet_source,original_destination,protocol,original_port,'SNAT',egress,matched)
            warnings.extend(f'{name} {message}' for message in snat_warnings)
            if snat:
                row=snat['row'];target=row['Translated Source'];translated=self._translated(target,snapshot)
                if target.casefold()=='masq' and egress:
                    try:translated=ipaddress.ip_network(egress.get('IP Address',''))
                    except ValueError:translated=None
                old=packet_source
                if translated is not None:packet_source=translated
                snat_status='PASS' if translated is not None and not snat['warnings'] else 'UNKNOWN'
                path_steps.append({'type':'snat','firewall':name,'label':'SNAT','status':snat_status,
                    'reason':f'{old} → {target}' if snat_status=='PASS' else 'SNAT 변환에 필요한 Source Object/Interface IP가 API 결과에 없습니다',
                    'rule':row['Rule Name'],'nat':row,'translation':{'original':str(old),'translated':str(packet_source)}})
            elif snat_warnings:
                path_steps.append({'type':'snat','firewall':name,'label':'SNAT','status':'WARNING','reason':'; '.join(snat_warnings)})
            gateway=next((row for row in snapshot.get('gateways',[]) if egress and row.get('Name')==egress.get('Gateway Name')),None)
            if gateway:
                path_steps.append({'type':'gateway','firewall':name,'label':gateway['Name'],'status':'PASS',
                    'reason':f"{gateway.get('Gateway IP','')} · {gateway.get('Type','')} · 설정 기준",'gateway':gateway,'configurationOnly':True})
            return_status='UNKNOWN' if not return_route else 'WARNING' if return_route.get('ambiguous') else 'FAIL' if return_route.get('blackhole','').casefold()=='enable' else 'PASS'
            return_reason=('Return Static / Connected Route가 없습니다. Site/Zone은 식별했으나 미수집 BGP / OSPF / SD-WAN 경로를 추정하지 않습니다' if not return_route else
                'Return Blackhole Route' if return_status=='FAIL' else f"Return {return_route['routeType']} {return_route['network']} → {return_route.get('interface','')}")
            returns.insert(0,{'type':'return_route','firewall':name,'label':name+' Return Route','status':'BLOCK' if return_status=='FAIL' else return_status,'reason':return_reason,'route':return_route})
            step['returnRoute']={'status':return_status,'route':return_route}
            results.append({'firewall':name,'available':True,'checkedAt':snapshot.get('checkedAt',''),'expectedZones':{'source':source_zone,'destination':destination_zone},
                'policy':policy,'routing':{'destination':route,'return':return_route,'returnStatus':return_status,'error':snapshot.get('routeError','')},'analysis':step})
        aws=AwsSecurityGroupPathService(self.service.root).check(packet_source,packet_destination,protocol,packet_port,number,path,base['partialPath'])
        aws['outbound']=base['awsSecurityGroups']['outbound']
        def sg_step(item):return {'type':'aws_sg','label':item['label'],'status':{'PASS':'PASS','FAIL':'BLOCK'}.get(item['state'],'UNKNOWN'),'reason':item['reason'],'awsSg':item}
        if aws['outbound']['state']!='N/A':path_steps.insert(0,sg_step(aws['outbound']))
        if aws['inbound']['state']!='N/A':path_steps.append(sg_step(aws['inbound']))
        path_steps+=returns
        if not path_steps:
            path_steps.append({'type':'network','label':'Network Path','status':'UNKNOWN','reason':(base.get('awsSecurityGroups',{}).get('networkPath') or {}).get('reason') or 'Source/Destination을 연결하는 Firewall/Cloud network 경로 데이터가 없습니다'})
        path_progress=progress(path_steps,base['source']['input'],str(packet_destination) if packet_destination!=destination else base['destination']['input'])
        summary=_summary(path_steps,base['source']['input'],base['destination']['input'],protocol,port,warnings,False,number)
        legacy_steps=([aws['outbound']] if aws['outbound']['state']!='N/A' else [])+[firewall_step(item) for item in results]+([aws['inbound']] if aws['inbound']['state']!='N/A' else [])
        base.update(mode='PATH',summary=summary,analysisPath=path_steps,progress=path_progress,pathSteps=path_steps,
            findings=[{'severity':'WARNING','message':message} for message in _unique(warnings)]+[{'severity':'INFO','message':message} for message in _unique(notes)],path=path,firewalls=results,
            steps=legacy_steps,awsSecurityGroups=aws,policySummary=policy_summary(legacy_steps,base['partialPath']),
            details={'candidateRules':{item['firewall']:item['policy'].get('matches',[]) for item in results},
                'routes':{name:snapshot.get('routes',[]) for name,snapshot in self.snapshots.items()},
                'returnRoutes':{item['firewall']:item['routing'] for item in results},
                'natRules':{name:snapshot.get('natRules',[]) for name,snapshot in self.snapshots.items()},
                'interfaces':{name:snapshot.get('interfaces',[])+snapshot.get('aliases',[]) for name,snapshot in self.snapshots.items()},
                'zones':{name:snapshot.get('zones',[]) for name,snapshot in self.snapshots.items()},
                'resolvedObjects':{name:{'addresses':snapshot.get('objects',{}),'services':snapshot.get('services',{}),'fqdns':snapshot.get('fqdnObjects',{})} for name,snapshot in self.snapshots.items()},
                'gateways':{name:snapshot.get('gateways',[]) for name,snapshot in self.snapshots.items()},'awsSg':aws,'destinationOwners':owners})
        return base

    def reachability(self, source, destination, protocol, port, number):
        from backend.services.firewall_path_check import _networks, _query_address_match, service_match_details, zone_match
        mode='SOURCE_REACHABILITY' if source else 'DESTINATION_EXPOSURE'
        value=source or destination; endpoint=self.endpoint(value,'Source' if source else 'Destination')
        known, fqdn, addresses, site=endpoint
        units={}; publications=[]
        for name, config in self.configs.items():
            if not config.get('configured'):continue
            snapshot=self.snapshot(name) or {}
            for row in self.resolved_rules(snapshot,fqdn if source else None,fqdn if not source else None):
                side='Source' if source else 'Destination'; other='Destination' if source else 'Source'
                queries = [known] if known is not None else [ipaddress.ip_network(value) for value in addresses] or [None]
                if not source:
                    translated_queries = []
                    for query in queries:
                        for nat in snapshot.get('natRules', []):
                            if nat.get('Status','').casefold() not in {'enable','enabled'}: continue
                            originals = [net for value in nat.get('Original Destination','').splitlines() for net in self._networks(value,snapshot)]
                            translated = self._translated(nat.get('Translated Destination',''),snapshot)
                            if query is not None and translated is not None and any(query.version==net.version and query.subnet_of(net) for net in originals): translated_queries.append(translated)
                    queries += translated_queries
                matches = [_query_address_match(query,fqdn,row,side,True) for query in queries]
                match = {'match':'full' if all(item['match']=='full' for item in matches) else 'partial' if any(item['match']!='none' for item in matches) else 'none'}
                if match['match']=='none' or row.get('Status','').casefold() not in {'enable','enabled','활성'}:continue
                if not service_match_details(protocol,port,row.get('Service',''),row.get('Service Resolved / Protocol / Port',''),row.get('service_wildcard') is True,number)['serviceMatch']:continue
                names=row.get(other+' Object','').splitlines() or ['ANY'] if row.get(other.lower()+'_wildcard') else row.get(other+' Object','').splitlines()
                for object_name in names:
                    wildcard=is_wildcard_value(object_name) or row.get(other.lower()+'_wildcard') is True
                    networks=self._networks(object_name,snapshot) or _networks(row.get(other+' Resolved','')) if len(names)==1 else self._networks(object_name,snapshot)
                    patterns=snapshot.get('fqdnObjects',{}).get(object_name,[]) or row.get('_'+other+' FQDNs',[])
                    key=(object_name,tuple(map(str,networks)),tuple(patterns),row.get(other+' Zone',''))
                    unit=units.setdefault(key,{'label':'ANY / Internet / Other Networks' if wildcard else object_name,'object':object_name,
                        'networks':list(map(str,networks)),'fqdns':patterns,'zone':row.get(other+' Zone',''),'site':'','wildcard':wildcard,'partialKnown':False,'firewalls':[]})
                    unit['partialKnown'] = unit['partialKnown'] or match['match']=='partial'
                    unit['site'] = '; '.join(_unique(resolve_input_network(str(net)).get('site','') for net in networks if resolve_input_network(str(net)).get('site') != '미확인'))
                    if name not in unit['firewalls']:unit['firewalls'].append(name)
            if not source:
                for nat in snapshot.get('natRules',[]):
                    translated=self._translated(nat.get('Translated Destination',''),snapshot)
                    if translated is not None and known is not None and translated.version==known.version and translated.overlaps(known):
                        publications.append({'firewall':name,'rule':nat['Rule Name'],'publishedVia':nat.get('Original Destination',''),
                                             'originalService':nat.get('Original Service',''),'target':str(translated),'status':nat.get('Status','')})
        groups=[]
        # Partition the wildcard domain at collected route/object boundaries.
        # Every CIDR is checked as a whole; no individual IP is enumerated.
        def wildcard_targets(unit):
            version=known.version if known is not None else 4
            remaining=[ipaddress.ip_network('0.0.0.0/0' if version==4 else '::/0')]
            cuts=[]
            for snap in self.snapshots.values():
                cuts += [net for row in snap.get('interfaces',[])+snap.get('aliases',[]) if (net:=interface_network(row)) is not None]
                cuts += [net for row in snap.get('rules',[]) for side in ('Source','Destination') for net in _networks(row.get(side+' Resolved',''))]
                for row in snap.get('routes',[]):
                    try:cuts.append(ipaddress.ip_network(row['destination']+'/'+(row.get('netmask') or '32'),strict=False))
                    except (KeyError,ValueError):pass
            for cut in sorted(set(cuts),key=lambda net:net.prefixlen):
                if cut.version!=version or cut.prefixlen==0:continue
                updated=[]
                for scope in remaining:
                    if cut.subnet_of(scope) and cut!=scope:updated.extend([cut,*scope.address_exclude(cut)])
                    else:updated.append(scope)
                remaining=updated
            # A zone selector narrows wildcard addresses to actual interface/route zones.
            selected=[]
            for scope in sorted(remaining,key=lambda net:(int(net.network_address),net.prefixlen)):
                zones=[]
                for firewall in unit['firewalls']:
                    snapshot=self.snapshots.get(firewall,{})
                    route=self._route(snapshot,scope)
                    zone=(route or {}).get('zone')
                    if zone:zones.append(zone)
                if not zones or any(zone_match(zone,unit['zone']) for zone in zones):selected.append(str(scope))
            return selected
        for unit in list(units.values())[:500]:
            targets=wildcard_targets(unit) if unit['wildcard'] else unit['networks'] or [value for value in unit['fqdns'] if '*' not in value]
            cases=[]
            for target in targets:
                try:
                    result=self.analyze(value if source else target,target if source else value,protocol,port,number)
                    cases.append({'target':target,'source':value if source else target,'destination':target if source else value,
                        'summary':result['summary'],'analysisPath':result['analysisPath'],'progress':result.get('progress',{}),
                        'serviceResults':result.get('serviceResults',[]),'networkResults':result.get('networkResults',[]),'details':result.get('details',{})})
                except ValueError:cases.append({'target':target,'summary':{'status':'UNKNOWN','primaryReason':'Object에 유효한 주소/FQDN이 없습니다'},'analysisPath':[]})
            states={case['summary']['status'] for case in cases}
            state=next(iter(states)) if len(states)==1 else 'WARNING' if states else 'UNKNOWN'
            reason='정책 Object/Zone 범위를 실제 Path Engine으로 분석했습니다' if cases else 'API 결과에 Object 주소/FQDN이 없어 분석할 수 없습니다'
            if unit['wildcard']:reason='ANY를 수집된 Route/Object 경계로 분할하여 전체 범위를 분석했습니다'
            if cases and len(states)>1:reason='범위별 결과 상이 · 각 Network의 허용/차단 결과를 제공합니다'
            if unit['partialKnown'] and state=='WARNING':reason='입력 Network/Resolve 범위별 허용/차단 결과가 다릅니다'
            groups.append({**unit,'status':state,'reason':reason,'results':cases})
            if not source:
                for publication in publications:
                    snapshot=self.snapshots[publication['firewall']]
                    published=[str(net) for item in publication['publishedVia'].splitlines() for net in self._networks(item,snapshot)]
                    for address in published:
                        exposure_cases=[]
                        for target in targets:
                            result=self.analyze(target,address,protocol,port,number)
                            exposure_cases.append({'target':target,'source':target,'destination':address,'summary':result['summary'],
                                'analysisPath':result['analysisPath'],'progress':result.get('progress',{}),'serviceResults':result.get('serviceResults',[])})
                        states={case['summary']['status'] for case in exposure_cases}
                        groups.append({**unit,'label':unit['label']+' → Published '+address,'publication':publication,
                            'status':next(iter(states)) if len(states)==1 else 'WARNING' if states else 'UNKNOWN',
                            'reason':'DNAT 공개 주소를 통한 실제 경로 분석','results':exposure_cases})
        warnings=[]
        if len(units)>500:warnings.append('500개 그룹 분석 한도 · 나머지 범위 미확인')
        failures=[f'{name} {entity}: {message}' for name,snapshot in self.snapshots.items() for entity,message in snapshot.get('configurationErrors',{}).items()]
        warnings.extend(failures)
        summary={'status':'UNKNOWN' if not groups else 'WARNING' if warnings or len({group['status'] for group in groups}) > 1 or any(group['status'] in {'WARNING','UNKNOWN'} for group in groups) else 'BLOCK' if all(group['status']=='BLOCK' for group in groups) else 'PASS',
            'source':source,'destination':destination,'service':f'{protocol} / {port if port is not None else "ANY"}',
            'primaryReason':'정책 Object/Network/Zone별 접근 범위 분석 완료' if groups else '입력에 대응하는 정책 Object/접근 범위가 수집된 API 결과에 없습니다', 'blockedAt':None,'warnings':_unique(warnings),'confidence':'INFERRED'}
        if not groups and failures:summary['primaryReason']='접근 범위 분석에 필요한 API 조회 실패: '+failures[0]
        return {'mode':mode,'summary':summary,'groups':groups,'analysisPath':[], 'details':{'publishedServices':publications,
            'configurationErrors':failures},'progress':{'nodes':[],'links':[]},'source':site if source else None,'destination':site if destination else None,
            'protocol':protocol,'port':port,'protocolNumber':number,'checkedAt':datetime.now(timezone.utc).isoformat()}
