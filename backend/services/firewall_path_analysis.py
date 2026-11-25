"""Configuration-based path/reachability analysis. Never sends probe traffic."""
import copy
import ipaddress
import json
import time
from datetime import datetime, timezone
from itertools import product

from backend.services.aws_security_group_path import AwsSecurityGroupPathService, firewall_step, policy_summary
from backend.services.firewall_network_mapping import NETWORK_MAPPINGS, resolve_input_network, expected_zones_for_path
from backend.services.firewall_rule_export import _restore_rule_order, is_wildcard_value
from backend.services.firewall_path_decisions import decide_policy, interface_network, service_slices, progress, normalized_service_lines


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
        self.snapshots = service.analysis_snapshots()
        from backend.services.firewall_configuration import ConfigurationIndex
        with service.configuration.lock:
            self.indexes={name:service.configuration.indexes[name] if service.configuration.snapshots.get(name) is snapshot and name in service.configuration.indexes else ConfigurationIndex(snapshot) for name,snapshot in self.snapshots.items()}
        self.metrics=dict.fromkeys(('normalize_ms','policy_lookup_ms','nat_match_ms','route_match_ms','path_decision_ms'),0.0)
        self.configs = {item['name']:{**item,'configured':item.get('configured') or item['name'] in self.snapshots} for item in service.firewalls.configurations()}
        self.dns = {}
        self.aws_data = None
        self._service_slices = {}

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
        if key not in self.dns:
            from backend.services.fqdn import normalize_fqdn
            try:normalized=normalize_fqdn(key)
            except ValueError:normalized=key
            cached=next((snapshot.get('resolvedFqdnAddresses',{})[normalized] for snapshot in self.snapshots.values() if normalized in snapshot.get('resolvedFqdnAddresses',{})),None)
            self.dns[key]=_query_endpoint(key,side,cached)
        return self.dns[key]

    def analyze(self, source, destination, protocol, port, protocol_number, _partition=True):
        from backend.services.firewall_path_check import normalize_service
        source, destination = str(source or '').strip(), str(destination or '').strip()
        if not source and not destination: raise ValueError('Source 또는 Destination을 입력하세요')
        protocol, port, number = normalize_service(protocol, port, protocol_number)
        if not source or not destination:
            return self.reachability(source, destination, protocol, port, number)
        started=time.perf_counter()
        src, dst = self.endpoint(source, 'Source'), self.endpoint(destination, 'Destination')
        self.metrics['normalize_ms']+=(time.perf_counter()-started)*1000
        if not src[1] and not dst[1] and src[0].version != dst[0].version:
            raise ValueError('Source/Destination은 같은 IP address family를 사용해야 합니다')
        base = self.service._check_legacy(source, destination, protocol, port, self.refresh, number,
                                          _snapshots=self.snapshots, _indexes=self.indexes, _endpoints=(src, dst))
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
            pair = self.service._check_legacy(s, d, protocol, port, self.refresh, number, _snapshots=self.snapshots, _indexes=self.indexes)
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
                return [ipaddress.ip_network(address) for pattern in snapshot['fqdnObjects'][value] for address in snapshot.get('resolvedFqdnAddresses',{}).get(pattern,[])]
            for mapping in NETWORK_MAPPINGS:
                if value in (mapping.site,*mapping.aliases):return [mapping.network]
            for row in snapshot.get('interfaces', []) + snapshot.get('aliases', []):
                if value in {row.get('Name'), row.get('Hardware')}:
                    try: return [ipaddress.ip_network(row['IP Address'])]
                    except (ValueError, KeyError): pass
        return []

    def _route(self,snapshot,network):
        started=time.perf_counter()
        try:return self._route_calculate(snapshot,network)
        finally:self.metrics['route_match_ms']+=(time.perf_counter()-started)*1000

    def _route_calculate(self, snapshot, network):
        from backend.services.firewall_path_check import match_static_route
        if network is None: return None
        connected=[]
        for row in snapshot.get('interfaces',[]) + snapshot.get('aliases',[]):
            cidr=interface_network(row)
            if cidr is not None and network.version==cidr.version and network.subnet_of(cidr):
                connected.append({'network':str(cidr),'destination':str(cidr.network_address),'netmask':str(cidr.prefixlen),
                    'interface':row.get('Parent Interface') or row['Name'],'gateway':'','source':'connected_interface',
                    'routeType':'Connected','zone':row.get('Zone',''),'description':'Interface IP/Netmask로 계산한 직접 연결망'})
        index=next((self.indexes[name] for name,value in self.snapshots.items() if value is snapshot),None)
        route_rows=[snapshot['routes'][i] for i in index.routes.find(network)] if index else snapshot.get('routes',[])
        static=match_static_route(route_rows,network)
        candidates=connected + ([{**static,'source':'static','routeType':'Static','description':static.get('description','Static longest-prefix match')}] if static else [])
        if not candidates: return None
        # Connected wins equal prefixes; a more specific static route still wins LPM.
        route=max(candidates,key=lambda row:(ipaddress.ip_network(row['network']).prefixlen,row['routeType']=='Connected'))
        if route['routeType']=='Static':
            alternatives=[match_static_route([row],network) for row in route_rows]
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

    def _nat(self,snapshot,source,destination,protocol,port,phase,interface=None,matched_rule=None,ingress=None,egress=None,number=None):
        from backend.services.firewall_path_check import service_match_details, _position
        started=time.perf_counter();candidates=[];uncertain=[]
        if phase=='DNAT':ingress=ingress or interface
        else:egress=egress or interface
        index=next((self.indexes[name] for name,value in self.snapshots.items() if value is snapshot),None)
        ids=(index.nat['Original Source'].find(source)|index.natUnresolved['Original Source'])&(index.nat['Original Destination'].find(destination)|index.natUnresolved['Original Destination']) if index else range(len(snapshot.get('natRules',[])))
        # Omitted selectors are unrestricted; unresolved references stay candidates for explicit diagnosis.
        if index:
            ids.update(i for i,row in enumerate(snapshot.get('natRules',[])) if not row.get('Original Source') or not row.get('Original Destination'))
        for i in sorted(ids):
            row=snapshot.get('natRules',[])[i]
            if row.get('Status','').casefold() not in {'enable','enabled'}:continue
            field='Translated Destination' if phase=='DNAT' else 'Translated Source'
            if row.get(field,'').casefold() in {'','original'}:continue
            missing=[];reject=False
            for key,query in [('Original Source',source),('Original Destination',destination)]:
                values=row.get(key,'').splitlines()
                if not values or any(is_wildcard_value(value) for value in values):continue
                networks=[net for value in values for net in self._networks(value,snapshot)]
                if not networks:missing.append(key+' Object missing');continue
                if query is None or not any(query.version==net.version and query.subnet_of(net) for net in networks):reject=True
            services=row.get('Original Service','').splitlines()
            if services and not any(is_wildcard_value(value) for value in services):
                resolved='\n'.join(snapshot.get('services',{}).get(value,'') for value in services)
                if not resolved:missing.append('Original Service Object missing')
                elif not any(service_match_details(protocol,port,'\n'.join(services),line,False,number)['serviceMatch'] for line in normalized_service_lines(resolved,protocol)):reject=True
            candidate_egress=egress
            if phase=='DNAT' and not candidate_egress:
                target=self._translated(row.get('Translated Destination',''),snapshot)
                route=self._route(snapshot,target) if target is not None else None
                candidate_egress=self._interface(snapshot,route) or ({'Name':route['interface'],'Hardware':route['interface']} if route and not route.get('ambiguous') and route.get('interface') else None)
            for key,actual in [('Inbound Interface',ingress),('Outbound Interface',candidate_egress)]:
                selectors=row.get(key,'').splitlines()
                if not selectors or any(is_wildcard_value(value) for value in selectors):continue
                if not actual:missing.append(key+' unavailable');continue
                names={actual.get('Name'),actual.get('Hardware'),actual.get('Parent Interface')}
                if not any(value in names for value in selectors):reject=True
            linked=row.get('Linked Firewall Rule','').splitlines()
            if phase=='SNAT' and linked and (not matched_rule or matched_rule.get('rule') not in linked):reject=True
            if reject:continue
            item={'row':row,'warnings':missing}
            (uncertain if missing else candidates).append(item)
        all_candidates=candidates+uncertain
        if len(all_candidates)>1:
            complete=[{**row,'_Rule Position':row.get('Position',''),'_Rule After':row.get('After Rule','')} for row in snapshot.get('natRules',[])]
            numeric=[_position(row['_Rule Position']) for row in complete]
            if all(value is not None for value in numeric) and len(set(numeric))==len(numeric):
                for row,position in zip(complete,numeric):row['_Rule Order']=position
                reliable=True
            else:reliable=_restore_rule_order(complete)
            if not reliable:
                self.metrics['nat_match_ms']+=(time.perf_counter()-started)*1000
                return None,['API에 NAT Position/After 순서가 없어 적용 NAT를 선택할 수 없습니다'],all_candidates
            order={row['Rule Name']:row['_Rule Order'] for row in complete}
            all_candidates.sort(key=lambda item:order[item['row']['Rule Name']])
        self.metrics['nat_match_ms']+=(time.perf_counter()-started)*1000
        if not all_candidates:return None,[],[]
        first=all_candidates[0]
        return (None,first['warnings'],all_candidates) if first['warnings'] else (first,[],all_candidates)

    def _translated(self, value, snapshot):
        networks = self._networks(value, snapshot)
        return networks[0] if len(networks)==1 and networks[0].num_addresses==1 else None

    def network_analysis(self, base, source, destination, protocol, port, number):
        from backend.services.firewall_path_check import _networks
        if not (base.get('awsSecurityGroups',{}).get('networkPath') and not base['path']):
            for name,config in self.configs.items():
                if config.get('configured'):self.snapshot(name)
        cuts=[network for index in self.indexes.values() for network in index.cuts]
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
        signatures={tuple((step['type'],step.get('firewall'),step['status'],(step.get('matchedRule') or {}).get('rule'),(step.get('route') or {}).get('network'),step.get('rule')) for step in case['analysisPath']) for case in cases}
        uniform=len(signatures)==1 and len(cases)==total
        if uniform:
            base['pathContext']='전체 주소 범위에서 동일한 경로/판정'
            base['progress']=copy.deepcopy(base['progress'])
            base['progress']['nodes'][0]['reason']=original[0]['input']
            if not any(step['type']=='dnat' for step in base['analysisPath']):base['progress']['nodes'][-1]['reason']=original[1]['input']
        base.update(networkResults=[] if uniform else cases,networkCoverage={'total':total,'analyzed':len(cases),'uniform':uniform})
        return base

    def policy_candidates(self,snapshot,source,destination,source_fqdn=None,destination_fqdn=None):
        started=time.perf_counter()
        index=next((self.indexes[name] for name,value in self.snapshots.items() if value is snapshot),None)
        if index:
            ids=index.rules('Source',source,source_fqdn)&index.rules('Destination',destination,destination_fqdn)
            rows=[index.ordered_rules[i] for i in sorted(ids)]
        else:rows=snapshot.get('rules',[])
        self.metrics['policy_lookup_ms']+=(time.perf_counter()-started)*1000
        return rows

    def service_analysis(self, base, source, destination, protocol, number, source_fqdn=None, destination_fqdn=None):
        # Discover snapshots once before building interval boundaries, including NAT services.
        self.enhance(copy.deepcopy(base), source, destination, 'TCP' if protocol=='ANY' else protocol, 1 if protocol in {'ANY','TCP','UDP'} else None, number, source_fqdn, destination_fqdn)
        if self.aws_data is None:
            try:self.aws_data=json.loads((self.service.root/'cache/aws.json').read_text(encoding='utf-8'))
            except (OSError,ValueError):self.aws_data={}
        original_endpoints=(base['source'],base['destination'])
        original_service=(base['protocol'],base['port'],base.get('protocolNumber'))
        key=(protocol,number)
        if key not in self._service_slices:self._service_slices[key]=service_slices(protocol,None,number,list(self.snapshots.values()),self.aws_data)
        slices=self._service_slices[key]
        cases=[]
        for current,start,end,coverage in slices[:1024]:
            numbers=list(coverage) if isinstance(coverage,tuple) else [coverage]
            num=numbers[0]
            pair=self.service._check_legacy(str(source),str(destination),current,start,self.refresh,num,_snapshots=self.snapshots, _indexes=self.indexes)
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
        warnings,path_steps,results,returns,notes,nat_failures=[],[],[],[],[],[]
        source_translation_unknown=False
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
                candidate,issues,potential=self._nat(snapshot,source,destination,protocol,port,'DNAT')
                candidate=candidate or (potential[0] if len(potential)==1 else None)
                if candidate and not any(is_wildcard_value(value) for value in candidate['row'].get('Original Destination','').splitlines()):published.append(name)
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
            ingress_selector=self._interface(snapshot,return_route) or ({'Name':return_route['interface'],'Hardware':return_route['interface'],'Zone':source_zone} if return_route and not return_route.get('ambiguous') and return_route.get('interface') else None)
            original_destination,original_port=packet_destination,packet_port
            nat,nat_warnings,candidates=self._nat(snapshot,packet_source,packet_destination,protocol,packet_port,'DNAT',ingress_selector,number=number)
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
                if nat_status=='PASS':path_steps.append(event);nat_steps.append(event)
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
            decision_started=time.perf_counter()
            policy,status,reason=decide_policy(self.policy_candidates(snapshot,packet_source,packet_destination,source_fqdn,None if nat else destination_fqdn),packet_source,packet_destination,protocol,packet_port,
                source_zone,destination_zone,number,source_fqdn,None if nat else destination_fqdn)
            self.metrics['path_decision_ms']+=(time.perf_counter()-decision_started)*1000
            matched=policy.get('matchedRule')
            if source_translation_unknown:status='UNKNOWN';reason='앞 Firewall의 SNAT 변환 Source가 Snapshot에 없어 후속 Source 조건을 판정할 수 없습니다'
            if 'FirewallRule' in errors:status='UNKNOWN';reason=f'{name} Configuration Snapshot 없음 · 최신 정보 다시 조회로 수집하세요' if not snapshot.get('checkedAt') and 'Snapshot' in str(errors['FirewallRule']) else f'{name} FirewallRule API 조회 실패로 정책 판정이 불가능합니다'
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
                'candidateRules':policy.get('matches',[]),'nat':nat_steps,'natStatus':nat_status,'natDecision':{'NOT_REQUIRED':'NAT_NOT_REQUIRED','PASS':'NAT_APPLIED','UNKNOWN':'NAT_UNKNOWN'}.get(nat_status,'NAT_NO_MATCH'),
                'evidence':{'Source Zone':source_zone,'Destination Zone':destination_zone,'Source Match':(matched or {}).get('sourceObject'),
                    'Destination Match':(matched or {}).get('destinationObject'),'Service Match':(matched or {}).get('service'), 'Action':(matched or {}).get('action')}}
            path_steps.append(step)
            route_status='UNKNOWN' if not route else 'WARNING' if route.get('ambiguous') else 'BLOCK' if route.get('blackhole','').casefold()=='enable' else 'PASS'
            route_reason=('현재 Static / Connected Route에 목적지 경로가 없습니다. BGP / OSPF / SD-WAN Route는 수집 범위 밖이므로 이후 경로를 판정할 수 없습니다' if not route else
                '동일 Prefix/Distance의 복수 Route로 ECMP 경로가 존재합니다' if route.get('ambiguous') else 'Destination Blackhole Route' if route_status=='BLOCK' else
                f"{route['routeType']} {route['network']} → {route.get('interface','')}")
            path_steps.append({'type':'route','firewall':name,'label':'Destination Route','status':route_status,'reason':route_reason,'route':route})
            snat,snat_warnings,_=self._nat(snapshot,packet_source,original_destination,protocol,original_port,'SNAT',self._interface(snapshot,route) or ({'Name':route['interface'],'Hardware':route['interface'],'Zone':destination_zone} if route and not route.get('ambiguous') and route.get('interface') else None),matched,ingress=ingress_selector,number=number)
            warnings.extend(f'{name} {message}' for message in snat_warnings)
            if snat:
                row=snat['row'];target=row['Translated Source'];translated=self._translated(target,snapshot)
                if target.casefold()=='masq' and egress:
                    try:translated=ipaddress.ip_network(egress.get('IP Address',''))
                    except ValueError:translated=None
                old=packet_source
                if translated is not None:packet_source=translated
                snat_status='PASS' if translated is not None and not snat['warnings'] else 'UNKNOWN'
                if snat_status=='PASS':
                    step['natDecision']='NAT_APPLIED'
                    path_steps.append({'type':'snat','firewall':name,'label':'SNAT','status':'PASS','reason':f'{old} → {target}',
                        'rule':row['Rule Name'],'nat':row,'translation':{'original':str(old),'translated':str(packet_source)}})
                else:
                    source_translation_unknown=True
                    step['natDecision']='NAT_UNKNOWN'
                    nat_failures.append(name+' NAT_UNKNOWN: SNAT에 필요한 Source Object/실제 Egress IP가 Snapshot에 없습니다')
            elif snat_warnings:
                step['natDecision']='NAT_UNKNOWN'
                source_translation_unknown=True
                nat_failures.extend(name+' NAT_UNKNOWN: '+message for message in snat_warnings)
            if step['natDecision']=='NAT_NOT_REQUIRED' and destination_zone=='WAN':step['natDecision']='NAT_NO_MATCH'
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
        def sg_step(item):return {'type':'aws_sg','label':item['label'],'status':'UNKNOWN' if source_translation_unknown and item is aws['inbound'] else {'PASS':'PASS','FAIL':'BLOCK'}.get(item['state'],'UNKNOWN'),'reason':'앞 단계 Source Translation 데이터가 없어 Inbound peer 조건을 계산할 수 없습니다' if source_translation_unknown and item is aws['inbound'] else item['reason'],'awsSg':item}
        if aws['outbound']['state']!='N/A':path_steps.insert(0,sg_step(aws['outbound']))
        if aws['inbound']['state']!='N/A':path_steps.append(sg_step(aws['inbound']))
        path_steps+=returns
        if not path_steps:
            path_steps.append({'type':'network','label':'Network Path','status':'UNKNOWN','reason':(base.get('awsSecurityGroups',{}).get('networkPath') or {}).get('reason') or 'Source/Destination을 연결하는 Firewall/Cloud network 경로 데이터가 없습니다'})
        path_progress=progress(path_steps,base['source']['input'],str(packet_destination) if packet_destination!=destination else base['destination']['input'])
        summary=_summary(path_steps,base['source']['input'],base['destination']['input'],protocol,port,warnings,False,number)
        if nat_failures and summary['status']!='BLOCK':
            summary.update(status='UNKNOWN',primaryReason=nat_failures[0],confidence='UNKNOWN')
            path_progress['nodes'][-1]['status']='UNKNOWN'
            path_progress['links'][-1]['status']='UNKNOWN'
        warnings.extend(nat_failures)
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
        units={}; publications=[];related_policies={};unresolved_search=[]
        for name, config in self.configs.items():
            if not config.get('configured'):continue
            snapshot=self.snapshot(name) or {}
            side='Source' if source else 'Destination';other='Destination' if source else 'Source'
            queries=[known] if known is not None else [ipaddress.ip_network(item) for item in addresses] or [None]
            index=self.indexes[name]
            nat_ids=set()
            fields=('Original Source','Translated Source') if source else ('Original Destination','Translated Destination')
            for field in fields:
                for query in queries:nat_ids.update(index.nat[field].find(query))
            for nat_id in nat_ids:
                nat=snapshot.get('natRules',[])[nat_id]
                if nat.get('Status','').casefold() not in {'enable','enabled'}:continue
                related_field='Original Source' if source else 'Translated Destination'
                queries += [net for item in nat.get(related_field,'').splitlines() for net in self._networks(item,snapshot)]
            ids=set()
            for query in queries:ids.update(index.rules(side,query,fqdn))
            for row_id in sorted(ids):
                row=snapshot['rules'][row_id]
                matches = [_query_address_match(query,fqdn,row,side,True) for query in queries]
                match = {'match':'full' if all(item['match']=='full' for item in matches) else 'partial' if any(item['match']!='none' for item in matches) else 'none'}
                if row.get('Status','').casefold() not in {'enable','enabled','활성'}:continue
                if match['match']=='none':
                    if any(item.get('resolverFailed') for item in matches) or row.get('_'+side+' Missing Objects'):
                        unresolved_search.append(name+' '+side+' Object 주소 데이터가 Snapshot에 없습니다')
                    continue
                resolved_service=row.get('Service Resolved / Protocol / Port','')
                if not any(service_match_details(protocol,port,row.get('Service',''),line,row.get('service_wildcard') is True,number)['serviceMatch'] for line in normalized_service_lines(resolved_service,protocol) or ['']) and not row.get('_Missing Services'):continue
                policy_ref={'id':name+':'+str(row_id),'firewall':name,'rule':row.get('Rule Name',''),'action':row.get('Action',''),
                    'source':row.get('Source Object',''),'destination':row.get('Destination Object',''),'service':row.get('Service',''),
                    'status':row.get('Status',''),'snapshotId':index.snapshot_id}
                related_policies[policy_ref['id']]=policy_ref
                names=row.get(other+' Object','').splitlines() or ['ANY'] if row.get(other.lower()+'_wildcard') else row.get(other+' Object','').splitlines()
                for object_name in names:
                    wildcard=is_wildcard_value(object_name) or row.get(other.lower()+'_wildcard') is True
                    networks=self._networks(object_name,snapshot) or _networks(row.get(other+' Resolved','')) if len(names)==1 else self._networks(object_name,snapshot)
                    patterns=snapshot.get('fqdnObjects',{}).get(object_name,[]) or row.get('_'+other+' FQDNs',[])
                    key=(object_name,tuple(map(str,networks)),tuple(patterns),row.get(other+' Zone',''))
                    unit=units.setdefault(key,{'label':('Internet' if row.get(other+' Zone','').casefold()=='wan' else 'ANY / 모든 네트워크') if wildcard else object_name,'object':object_name,
                        'networks':list(map(str,networks)),'fqdns':patterns,'zone':row.get(other+' Zone',''),'site':'','wildcard':wildcard,'partialKnown':False,'firewalls':[],'relatedPolicies':[]})
                    if policy_ref not in unit['relatedPolicies']:unit['relatedPolicies'].append(policy_ref)
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
        def mini_path(cases,state):
            value=copy.deepcopy(cases[0].get('progress',{})) if cases else {'nodes':[],'links':[]}
            if state=='WARNING':
                value['mixed']=True
                for node in value.get('nodes',[]):
                    if node.get('type')!='source':node['status']='WARNING'
                for link in value.get('links',[]):link.update(active=True,status='WARNING')
            return value
        # Partition the wildcard domain at collected route/object boundaries.
        # Every CIDR is checked as a whole; no individual IP is enumerated.
        def wildcard_targets(unit):
            version=known.version if known is not None else 4
            remaining=[ipaddress.ip_network('0.0.0.0/0' if version==4 else '::/0')]
            cuts=[network for index in self.indexes.values() for network in index.cuts]
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
                        'serviceResults':result.get('serviceResults',[]),'networkResults':result.get('networkResults',[]),'resolvedResults':result.get('resolvedResults',[]),'pathContext':result.get('pathContext'),'details':result.get('details',{})})
                except ValueError:cases.append({'target':target,'summary':{'status':'UNKNOWN','primaryReason':'Object에 유효한 주소/FQDN이 없습니다'},'analysisPath':[]})
            states={case['summary']['status'] for case in cases}
            state=next(iter(states)) if len(states)==1 else 'WARNING' if states else 'UNKNOWN'
            reason='정책 Object/Zone 범위를 실제 Path Engine으로 분석했습니다' if cases else 'API 결과에 Object 주소/FQDN이 없어 분석할 수 없습니다'
            if unit['wildcard']:reason='ANY를 수집된 Route/Object 경계로 분할하여 전체 범위를 분석했습니다'
            if cases and len(states)>1:reason='범위별 결과 상이 · 각 Network의 허용/차단 결과를 제공합니다'
            if unit['partialKnown'] and state=='WARNING':reason='입력 Network/Resolve 범위별 허용/차단 결과가 다릅니다'
            groups.append({**unit,'status':state,'reason':reason,'results':cases,'policyCount':len(unit['relatedPolicies']),'miniPath':mini_path(cases,state)})
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
                            'reason':'DNAT 공개 주소를 통한 실제 경로 분석','results':exposure_cases,'policyCount':len(unit['relatedPolicies']),'miniPath':mini_path(exposure_cases,next(iter(states)) if len(states)==1 else 'WARNING')})
        warnings=[]
        if len(units)>500:warnings.append('500개 그룹 분석 한도 · 나머지 범위 미확인')
        failures=[f'{name} {entity}: {message}' for name,snapshot in self.snapshots.items() for entity,message in snapshot.get('configurationErrors',{}).items()]
        warnings.extend(failures)
        summary={'status':('UNKNOWN' if not self.snapshots or failures or unresolved_search else 'BLOCK') if not groups else 'WARNING' if warnings or len({group['status'] for group in groups}) > 1 or any(group['status'] in {'WARNING','UNKNOWN'} for group in groups) else 'BLOCK' if all(group['status']=='BLOCK' for group in groups) else 'PASS',
            'source':source,'destination':destination,'service':f'{protocol} / {port if port is not None else "ANY"}',
            'primaryReason':'정책 Object/Network/Zone별 접근 범위 분석 완료' if groups else '입력에 대응하는 정책 Object/접근 범위가 수집된 API 결과에 없습니다', 'blockedAt':None,'warnings':_unique(warnings),'confidence':'INFERRED'}
        if not groups and self.snapshots and not failures and not unresolved_search:summary['primaryReason']='수집된 방화벽 정책에 입력/서비스와 일치하는 항목이 없습니다 · 기본 Drop 기준'
        if not groups and unresolved_search:summary['primaryReason']=unresolved_search[0]
        if not groups and failures:summary['primaryReason']='접근 범위 분석에 필요한 API 조회 실패: '+failures[0]
        return {'mode':mode,'analysisMode':'SOURCE_ONLY' if source else 'DESTINATION_ONLY','relatedPolicies':list(related_policies.values()),'policyCount':len(related_policies),'summary':summary,'groups':groups,'analysisPath':[], 'details':{'publishedServices':publications,
            'configurationErrors':failures},'progress':{'nodes':[],'links':[]},'source':site if source else None,'destination':site if destination else None,
            'protocol':protocol,'port':port,'protocolNumber':number,'checkedAt':datetime.now(timezone.utc).isoformat()}
