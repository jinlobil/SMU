"""Configuration-based path/reachability analysis. Never sends probe traffic."""
import copy
import ipaddress
import time
from datetime import datetime, timezone
from itertools import product

from backend.services.firewall_network_mapping import NETWORK_MAPPINGS, resolve_input_network
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
        from backend.services.firewall_configuration import ConfigurationIndex
        # Pin Firewall snapshots, indexes and AWS topology under the same generation lock.
        with service.configuration.lock:
            self.snapshots = service.analysis_snapshots()
            self.indexes = {name: service.configuration.indexes[name] if service.configuration.snapshots.get(name) is snapshot and name in service.configuration.indexes else ConfigurationIndex(snapshot) for name, snapshot in self.snapshots.items()}
            self.topology = service.configuration.topology
            if self.topology is None or set(self.topology.snapshots) != set(self.snapshots) or any(self.topology.snapshots.get(name) is not row for name, row in self.snapshots.items()):
                from backend.services.firewall_topology import TopologyIndex
                self.topology = TopologyIndex(self.snapshots, self.indexes, service.configuration.aws_data)
        self.metrics = dict.fromkeys(('normalize_ms','policy_lookup_ms','nat_match_ms','route_match_ms','path_decision_ms'), 0.0)
        self.configs = {name: {'name':name,'configured':True} for name in self.snapshots}
        self.metrics.update(dict.fromkeys(('endpoint_lookup_ms','object_index_lookup_ms','group_lookup_ms','service_index_lookup_ms','nat_index_lookup_ms','policy_validation_ms','dynamic_path_ms'),0.0))
        self.metrics.update(candidate_rule_count=0,candidate_nat_count=0,total_rule_count=sum(len(i.ordered_rules) for i in self.indexes.values()))
        self._candidate_rules=set();self._candidate_nats=set()
        self.dns = {}
        self.aws_data = self.topology.aws_data
        self._service_slices = {}
        self._path_cache={}

    def snapshot(self, name):
        return self.snapshots.get(name)

    def endpoint(self, value, side):
        from backend.services.firewall_path_check import _query_endpoint
        started=time.perf_counter()
        key = value.strip()
        if key not in self.dns:
            from backend.services.fqdn import normalize_fqdn
            try:normalized=normalize_fqdn(key)
            except ValueError:normalized=key
            cached=next((snapshot.get('resolvedFqdnAddresses',{})[normalized] for snapshot in self.snapshots.values() if normalized in snapshot.get('resolvedFqdnAddresses',{})),None)
            self.dns[key]=_query_endpoint(key,side,(cached or []))
        self.metrics['endpoint_lookup_ms']+=(time.perf_counter()-started)*1000
        return self.dns[key]

    def analyze(self,source,destination,protocol,port,protocol_number,_partition=True):
        key=(str(source),str(destination),protocol,port,protocol_number,_partition)
        if key in self._path_cache:return copy.deepcopy(self._path_cache[key])
        result=self._analyze(source,destination,protocol,port,protocol_number,_partition)
        if len(self._path_cache)<256:self._path_cache[key]=copy.deepcopy(result)
        return result

    def _analyze(self, source, destination, protocol, port, protocol_number, _partition=True):
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
        base = self.base(source, destination, protocol, port, number, src, dst)
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
                pair=self.base(s,d,protocol,port,number)
                pair.update(summary={'status':'UNKNOWN','primaryReason':'IP address family mismatch'},analysisPath=[],progress=progress([],s,d),details={})
                variants.append({'source':s,'destination':d,'summary':pair['summary'],'analysisPath':[],'progress':pair['progress'],'_result':pair});continue
            pair = self.base(s, d, protocol, port, number)
            pair = self.service_analysis(pair, a, b, protocol, number, src[1], dst[1]) if protocol=='ANY' or protocol in {'TCP','UDP'} and port is None or protocol=='IP' and number is None else self.enhance(pair, a, b, protocol, port, number, src[1], dst[1])
            variants.append({'source':s, 'destination':d, 'summary':pair['summary'], 'analysisPath':pair['analysisPath'], 'details':pair['details'], 'progress':pair['progress'], 'returnPath':pair.get('returnPath'), 'serviceResults':pair.get('serviceResults',[]), '_result':pair})
        total = len(sources) * len(destinations)
        signatures = {(item['summary']['status'], tuple((step.get('type'), step.get('firewall'), step.get('ingressZone'), step.get('egressZone'), step.get('status'), (step.get('matchedRule') or {}).get('rule'), step.get('rule'), (step.get('route') or {}).get('network')) for step in item['analysisPath'])) for item in variants}
        if variants:
            inputs=(base['source'],base['destination'])
            base.update(variants[0]['_result'])
            base['source'],base['destination']=inputs
            for variant in variants:variant.pop('_result',None)
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
        index=next((index for name,index in self.indexes.items() if self.snapshots[name] is snapshot),None)
        if index and value in index.object_networks and index.object_networks[value]:return list(index.object_networks[value])
        try:
            return [ipaddress.ip_network(value, strict=False)]
        except (ValueError, TypeError):
            # SFOS #Interface references are authoritative even if an export's
            # unresolved Object table contains an empty placeholder for the name.
            rows=snapshot.get('interfaces', []) + snapshot.get('aliases', [])
            if isinstance(value,str) and value.startswith('#'):
                for row in rows:
                    if value[1:] in {row.get('Name'),row.get('Hardware')}:
                        try:return [ipaddress.ip_network(row['IP Address'])]
                        except (ValueError,KeyError):return []
                return []
            resolved=_networks(snapshot.get('objects',{}).get(value,''))
            if resolved:return resolved
            if value in snapshot.get('fqdnObjects', {}):
                return [ipaddress.ip_network(address) for pattern in snapshot['fqdnObjects'][value] for address in snapshot.get('resolvedFqdnAddresses',{}).get(pattern,[])]
            for row in rows:
                if value in {row.get('Name'),row.get('Hardware')}:
                    try:return [ipaddress.ip_network(row['IP Address'])]
                    except (ValueError,KeyError):pass
            for mapping in NETWORK_MAPPINGS:
                if value in (mapping.site,*mapping.aliases):return [mapping.network]
        return []

    def base(self, source, destination, protocol, port, number, src=None, dst=None):
        src = src or self.endpoint(source, 'Source')
        dst = dst or self.endpoint(destination, 'Destination')
        return {'source': src[3], 'destination': dst[3], 'protocol': protocol, 'port': port,
            'protocolNumber': number, 'path': [], 'partialPath': False, 'firewalls': [], 'steps': [], 'pathSteps': [],
            'awsSecurityGroups': {}, 'policySummary': {'state':'UNKNOWN','label':'경로 확인 불가'},
            'checkedAt': datetime.now(timezone.utc).isoformat()}

    def _route(self, snapshot, query):
        name = next((name for name, value in self.snapshots.items() if value is snapshot), None)
        started = time.perf_counter()
        try:
            return self.topology.routes.select(name, query) if name else None
        finally:
            self.metrics['route_match_ms'] += (time.perf_counter() - started) * 1000

    def _interface(self, snapshot, route):
        name = next((name for name, value in self.snapshots.items() if value is snapshot), None)
        return self.topology.routes.interface(name, (route or {}).get('interface'))

    def _nat(self,snapshot,source,destination,protocol,port,phase,interface=None,matched_rule=None,ingress=None,egress=None,number=None):
        from backend.services.firewall_path_check import service_match_details, _position
        started=time.perf_counter();candidates=[];uncertain=[]
        if phase=='DNAT':ingress=ingress or interface
        else:egress=egress or interface
        index=next((self.indexes[name] for name,value in self.snapshots.items() if value is snapshot),None)
        lookup=time.perf_counter()
        ids=(index.nat['Original Source'].find(source)|index.natUnresolved['Original Source'])&(index.nat['Original Destination'].find(destination)|index.natUnresolved['Original Destination']) if index else set()
        if index:ids &= index.nat_phases[phase] & index.nat_service_index.find(protocol,port,number)
        self.metrics['nat_index_lookup_ms']+=(time.perf_counter()-lookup)*1000
        self._candidate_nats.update((id(snapshot),i) for i in ids)
        self.metrics['candidate_nat_count']=len(self._candidate_nats)
        for i in sorted(ids):
            row=index.nat_rows[i]
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
                if not any(value.lstrip('#') in names for value in selectors):reject=True
            linked=row.get('Linked Firewall Rule','').splitlines()
            if phase=='SNAT' and linked and (not matched_rule or matched_rule.get('rule') not in linked):reject=True
            if reject:continue
            item={'row':row,'warnings':missing}
            (uncertain if missing else candidates).append(item)
        all_candidates=candidates+uncertain
        if len(all_candidates)>1:
            if not index.nat_order_reliable:
                self.metrics['nat_match_ms']+=(time.perf_counter()-started)*1000
                return None,['API에 NAT Position/After 순서가 없어 적용 NAT를 선택할 수 없습니다'],all_candidates
            by_name={row['Rule Name']:i for i,row in ((i,index.nat_rows[i]) for i in ids)}
            all_candidates.sort(key=lambda item:index.nat_order[by_name[item['row']['Rule Name']]])
        self.metrics['nat_match_ms']+=(time.perf_counter()-started)*1000
        if not all_candidates:return None,[],[]
        first=all_candidates[0]
        return (None,first['warnings'],all_candidates) if first['warnings'] else (first,[],all_candidates)

    def _translated(self, value, snapshot):
        networks = self._networks(value, snapshot)
        return networks[0] if len(networks)==1 and networks[0].num_addresses==1 else None

    def network_analysis(self, base, source, destination, protocol, port, number):
        from backend.services.firewall_path_check import _networks
        sources={source};destinations={destination};cuts=set()
        for _ in range(4):
            old=(len(sources),len(destinations))
            for name,index in self.indexes.items():
                ids=(set().union(*(index.nat['Original Source'].find(q) for q in sources))|index.natUnresolved['Original Source']) & (set().union(*(index.nat['Original Destination'].find(q) for q in destinations))|index.natUnresolved['Original Destination']) & index.nat_service_index.find(protocol,port,number)
                for i in ids:
                    row=index.nat_rows[i]
                    sources.update(self._networks(row.get('Translated Source',''),self.snapshots[name]))
                    destinations.update(self._networks(row.get('Translated Destination',''),self.snapshots[name]))
            if old==(len(sources),len(destinations)):break
        for name,index in self.indexes.items():
            src_ids=set().union(*(index.rules('Destination',q) for q in destinations)) & index.service_index.find(protocol,port,number)
            dst_ids=set().union(*(index.rules('Source',q) for q in sources)) & index.service_index.find(protocol,port,number)
            cuts.update(net for i in src_ids for net in index.ordered_rules[i]['_Source Networks'])
            cuts.update(net for i in dst_ids for net in index.ordered_rules[i]['_Destination Networks'])
            cuts.update(index.route_cuts);cuts.update(row['_cidr'] for row in index.connected_records.values())
        cuts.update(ipaddress.ip_network(value) for value in self.topology.aws_addresses)
        cuts.update(ipaddress.ip_network(value) for value in self.topology.addresses)
        def partition(network):
            low,high=int(network.network_address),int(network.broadcast_address)+1
            points={low,high}
            for cut in cuts:
                if cut.version==network.version:
                    a,b=int(cut.network_address),int(cut.broadcast_address)+1
                    if low<a<high:points.add(a)
                    if low<b<high:points.add(b)
            address=ipaddress.IPv4Address if network.version==4 else ipaddress.IPv6Address
            bounds=sorted(points)
            return [scope for a,b in zip(bounds,bounds[1:]) for scope in ipaddress.summarize_address_range(address(a),address(b-1))]
        sources,destinations=partition(source),partition(destination)
        if len(sources)==len(destinations)==1:return None
        cases=[]
        for index,(src,dst) in enumerate(product(sources,destinations)):
            if index>=256:break
            result=self.analyze(str(src),str(dst),protocol,port,number,_partition=False)
            cases.append({'source':str(src),'destination':str(dst),'target':str(src)+' → '+str(dst),
                'summary':result['summary'],'analysisPath':result['analysisPath'],'progress':result['progress'],
                'returnPath':result.get('returnPath'),'serviceResults':result.get('serviceResults',[]),'_result':result})
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

    def policy_candidates(self,snapshot,source,destination,source_fqdn=None,destination_fqdn=None,protocol=None,port=None,number=None,published_destination=None):
        started=time.perf_counter()
        index=next((self.indexes[name] for name,value in self.snapshots.items() if value is snapshot),None)
        if not index:return []
        source_ids=index.rules('Source',source,source_fqdn)
        destination_ids=index.rules('Destination',destination,destination_fqdn)
        if published_destination is not None:
            refs=index.interface_by_address.get(str(published_destination.network_address),[])
            destination_ids |= set().union(*(index.interface_rules[row['Name']] for row in refs)) if refs else set()
        ids=source_ids & destination_ids
        self.metrics['object_index_lookup_ms']+=(time.perf_counter()-started)*1000
        service_started=time.perf_counter()
        if protocol is not None:ids &= index.service_index.find(protocol,port,number)
        self.metrics['service_index_lookup_ms']+=(time.perf_counter()-service_started)*1000
        self._candidate_rules.update((id(snapshot),i) for i in ids)
        self.metrics['candidate_rule_count']=len(self._candidate_rules)
        self.metrics['policy_lookup_ms']+=(time.perf_counter()-started)*1000
        return [index.ordered_rules[i] for i in sorted(ids)]

    def scoped_service_slices(self,source,destination,protocol,number):
        """Collect bounds from address candidates and reachable NAT translations only."""
        sources={source};destinations={destination};policy_ids={};nat_ids={}
        for _ in range(4):
            old=(len(sources),len(destinations))
            for name,index in self.indexes.items():
                src=set().union(*(index.nat['Original Source'].find(q) for q in sources))|index.natUnresolved['Original Source']
                dst=set().union(*(index.nat['Original Destination'].find(q) for q in destinations))|index.natUnresolved['Original Destination']
                ids=src&dst;nat_ids.setdefault(name,set()).update(ids)
                for i in ids:
                    row=index.nat_rows[i]
                    for field,target in [('Translated Source',sources),('Translated Destination',destinations)]:
                        if row.get(field,'').casefold()=='masq':continue
                        target.update(self._networks(row.get(field,''),self.snapshots[name]))
            if old==(len(sources),len(destinations)):break
        subsets=[]
        for name,index in self.indexes.items():
            ids=set().union(*(index.rules('Source',q) for q in sources)) & set().union(*(index.rules('Destination',q) for q in destinations))
            policy_ids[name]=ids
            rows=[index.ordered_rules[i] for i in sorted(ids)]
            for i in nat_ids.get(name,()):
                row=index.nat_rows[i]
                rows.append({'Service':row.get('Original Service',''),'Service Resolved / Protocol / Port':row.get('_Service Resolved','')})
            rows += [{'Service':svc.get('service','local'),'Service Resolved / Protocol / Port':'Protocol: '+svc.get('protocol','')+' | Destination: '+str(svc['port'])} for svc in self.snapshots[name].get('localServices',[]) if isinstance(svc.get('port'),int)]
            subsets.append({'rules':rows})
        groups={g for q in sources|destinations for g in (self.topology.resolve(q).aws or {}).get('groupIds',[])}
        sg_rows=[row for g in groups for direction in (False,True) for row in self.topology.sg_rules.get((g,direction),[])]
        key=(protocol,number,tuple((n,tuple(sorted(ids))) for n,ids in policy_ids.items()),tuple((n,tuple(sorted(ids))) for n,ids in nat_ids.items()),tuple(sorted(groups)))
        with self.topology.cache_lock:
            cached=self.topology.partition_cache.get(key)
        if cached is not None:return cached
        slices=service_slices(protocol,None,number,subsets,{'security_group_rules':sg_rows})
        with self.topology.cache_lock:
            self.topology.partition_cache[key]=slices
            if len(self.topology.partition_cache)>256:self.topology.partition_cache.popitem(last=False)
        return slices

    def service_analysis(self, base, source, destination, protocol, number, source_fqdn=None, destination_fqdn=None):
        original_endpoints=(base['source'],base['destination'])
        original_service=(base['protocol'],base['port'],base.get('protocolNumber'))
        key=(str(source),str(destination),protocol,number)
        if key not in self._service_slices:self._service_slices[key]=self.scoped_service_slices(source,destination,protocol,number)
        slices=self._service_slices[key]
        cases=[]
        for current,start,end,coverage in slices[:1024]:
            numbers=list(coverage) if isinstance(coverage,tuple) else [coverage]
            num=numbers[0]
            pair=self.base(str(source),str(destination),current,start,num)
            pair=self.enhance(pair,source,destination,current,start,num,source_fqdn,destination_fqdn)
            signature=(pair['summary']['status'],tuple((step['type'],step.get('firewall'),step['status'],(step.get('matchedRule') or {}).get('rule'),step.get('rule')) for step in pair['analysisPath']))
            if cases and cases[-1]['protocol']==current and cases[-1]['protocolNumber']==num and cases[-1]['_signature']==signature and start is not None and cases[-1]['toPort']==start-1:
                cases[-1]['toPort']=end
            else:
                cases.append({'protocol':current,'fromPort':start,'toPort':end,'protocolNumber':num,'protocolNumbers':numbers if current=='IP' else [],'summary':pair['summary'],
                    'analysisPath':pair['analysisPath'],'progress':pair['progress'],'returnPath':pair.get('returnPath'),'_signature':signature,'_result':pair})
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
        path_signatures={tuple((step['type'],step.get('firewall'),step['status'],(step.get('matchedRule') or {}).get('rule'),step.get('rule')) for step in case['analysisPath']) for case in merged}
        if len(states)>1 or len(path_signatures)>1 or len(slices)>1024:
            base['summary'].update(status='WARNING',primaryReason='서비스 분석 한도 1024개를 초과하여 일부 범위는 미분석입니다' if len(slices)>1024 else '서비스별 결과 상이 · 서비스 범위별 판정 결과를 제공합니다',blockedAt=None,matchedRule=None,action=None,ingressZone=None,egressZone=None,confidence='CONFIRMED')
        elif states=={'BLOCK'}:
            base['summary']['primaryReason']='전체 요청 서비스 범위가 차단됩니다 · '+representative['summary']['primaryReason']
        base['pathContext']=f"표시 경로: {representative['protocol']} / {representative['fromPort'] if representative['fromPort']==representative['toPort'] else str(representative['fromPort'])+'–'+str(representative['toPort'])}"
        base.setdefault('details',{})['serviceCoverage']={'partitionCount':len(slices),'analyzedCount':min(len(slices),1024)}
        base['summary']['source']=base['source']['input'];base['summary']['destination']=base['destination']['input']
        return base

    def enhance(self, base, source, destination, protocol, port, number, source_fqdn=None, destination_fqdn=None):
        from backend.services.firewall_packet import DynamicPathBuilder
        started = time.perf_counter()
        try:
            return DynamicPathBuilder(self).build(base, source, destination, protocol, port, number, source_fqdn, destination_fqdn)
        finally:
            elapsed=(time.perf_counter()-started)*1000
            self.metrics['path_decision_ms']+=elapsed;self.metrics['dynamic_path_ms']+=elapsed

    def reachability(self, source, destination, protocol, port, number):
        from backend.services.firewall_path_check import _networks, _query_address_match, service_match_details, zone_match
        mode='SOURCE_REACHABILITY' if source else 'DESTINATION_EXPOSURE'
        value=source or destination; endpoint=self.endpoint(value,'Source' if source else 'Destination')
        known, fqdn, addresses, site=endpoint
        units={}; publications=[];related_policies={};unresolved_search=[];discovery_queries=set()
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
            discovery_queries.update(q for q in queries if q is not None)
            ids=set()
            lookup=time.perf_counter()
            for query in queries:ids.update(index.rules(side,query,fqdn))
            self.metrics['object_index_lookup_ms']+=(time.perf_counter()-lookup)*1000
            lookup=time.perf_counter()
            ids &= index.service_index.find(protocol,port,number)
            self.metrics['service_index_lookup_ms']+=(time.perf_counter()-lookup)*1000
            self._candidate_rules.update((id(snapshot),i) for i in ids)
            self.metrics['candidate_rule_count']=len(self._candidate_rules)
            for row_id in sorted(ids):
                row=index.ordered_rules[row_id]
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
                publication_ids=set().union(*(index.nat['Translated Destination'].find(query) for query in queries))
                for nat_id in publication_ids:
                    nat=index.nat_rows[nat_id]
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
        wildcard_cache={}
        def wildcard_targets(unit):
            cache_key=(tuple(sorted(unit['firewalls'])),unit['zone'])
            if cache_key in wildcard_cache:return wildcard_cache[cache_key]
            if 'classes' in wildcard_cache:
                value=[(target,coverage) for target,coverage,zones in wildcard_cache['classes'] if not any(zones.get(name) for name in unit['firewalls']) or any(zone_match(zones.get(name),unit['zone']) for name in unit['firewalls'] if zones.get(name))]
                wildcard_cache[cache_key]=value;return value
            version=known.version if known is not None else 4
            cuts=set();known_ids={}
            side='Source' if source else 'Destination';other='Destination' if source else 'Source'
            for name,index in self.indexes.items():
                ids=set().union(*(index.rules(side,q,fqdn) for q in (discovery_queries or {None}))) & index.service_index.find(protocol,port,number)
                known_ids[name]=ids
                for i in ids:cuts.update(index.ordered_rules[i]['_'+other+' Networks'])
                cuts.update(index.route_cuts)
                for field in index.nat:
                    # Prefix keys, not NAT record scans; isolate translation/publication boundaries.
                    if ('Source' in field) == bool(source):continue
                    for (v,prefix),addresses in index.nat[field].prefixes.items():
                        if v==version:cuts.update(ipaddress.ip_network((address,prefix)) for address in addresses)
            cuts.update(ipaddress.ip_network(value) for value in self.topology.aws_addresses)
            cuts.update(ipaddress.ip_network(value) for value in self.topology.addresses)
            cuts.update(mapping.network for mapping in NETWORK_MAPPINGS)
            for index in self.indexes.values():cuts.update(row['_cidr'] for row in index.connected_records.values())
            address_type=ipaddress.IPv4Address if version==4 else ipaddress.IPv6Address
            cuts.update(getattr(address_type._constants,'_private_networks',()))
            shared=getattr(address_type._constants,'_public_network',None)
            if shared is not None:cuts.add(shared)
            bits=32 if version==4 else 128
            points={0,1<<bits}
            for cut in cuts:
                if cut.version==version:points.update((int(cut.network_address),int(cut.broadcast_address)+1))
            boundaries=sorted(points)
            address=ipaddress.IPv4Address if version==4 else ipaddress.IPv6Address
            grouped={}
            for low,high in zip(boundaries,boundaries[1:]):
                scope=ipaddress.ip_network(address(low))
                zones={};fingerprint=[]
                for name,index in self.indexes.items():
                    snapshot=self.snapshots[name];route=self._route(snapshot,scope)
                    if route and route.get('zone'):zones[name]=route['zone']
                    rows=index.rules(other,scope)&known_ids[name]
                    field='Original Destination' if source else 'Original Source'
                    fixed='Original Source' if source else 'Original Destination'
                    fixed_ids=set().union(*(index.nat[fixed].find(q) for q in (discovery_queries or {None})))|index.natUnresolved[fixed]
                    nat_candidates=tuple(sorted((index.nat[field].find(scope)|index.natUnresolved[field]) & fixed_ids & index.nat_service_index.find(protocol,port,number)))
                    fingerprint.append((name,tuple(sorted(rows)),(route or {}).get('network'),(route or {}).get('interface'),(route or {}).get('gateway'),nat_candidates))
                endpoint=self.topology.resolve(scope)
                owner=endpoint.owner or {};aws=endpoint.aws or {}
                fingerprint.append((endpoint.kind,owner.get('firewall'),owner.get('interface'),aws.get('eniId'),str(scope) if aws else None))
                group=grouped.setdefault(tuple(fingerprint),[str(scope),[],zones])
                group[1].extend(str(net) for net in ipaddress.summarize_address_range(address(low),address(high-1)))
            wildcard_cache['classes']=list(grouped.values())
            value=[(target,coverage) for target,coverage,zones in wildcard_cache['classes'] if not any(zones.get(name) for name in unit['firewalls']) or any(zone_match(zones.get(name),unit['zone']) for name in unit['firewalls'] if zones.get(name))]
            wildcard_cache[cache_key]=value
            return value
        for unit in list(units.values())[:500]:
            scopes=wildcard_targets(unit) if unit['wildcard'] else [(target,[target]) for target in (unit['networks'] or [value for value in unit['fqdns'] if '*' not in value])]
            targets=[target for target,coverage in scopes]
            cases=[]
            for target,coverage in scopes:
                try:
                    result=self.analyze(value if source else target,target if source else value,protocol,port,number,_partition=not unit['wildcard'])
                    cases.append({'target':target,'coveredNetworks':coverage,'source':value if source else target,'destination':target if source else value,
                        'summary':result['summary'],'analysisPath':result['analysisPath'],'progress':result.get('progress',{}),'returnPath':result.get('returnPath'),
                        'serviceResults':result.get('serviceResults',[]),'networkResults':result.get('networkResults',[]),'resolvedResults':result.get('resolvedResults',[]),'pathContext':result.get('pathContext'),'details':result.get('details',{})})
                except ValueError:cases.append({'target':target,'summary':{'status':'UNKNOWN','primaryReason':'Object에 유효한 주소/FQDN이 없습니다'},'analysisPath':[]})
            states={case['summary']['status'] for case in cases}
            state=next(iter(states)) if len(states)==1 else 'WARNING' if states else 'UNKNOWN'
            reason='정책 Object/Zone 범위를 실제 Path Engine으로 분석했습니다' if cases else 'API 결과에 Object 주소/FQDN이 없어 분석할 수 없습니다'
            if unit['wildcard']:reason='전체 주소 범위를 같은 정책/경로 조건별로 묶어 분석했습니다'
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
