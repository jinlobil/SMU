"""Configuration-based path/reachability analysis. Never sends probe traffic."""
import copy
import ipaddress
from datetime import datetime, timezone
from itertools import product

from backend.services.aws_security_group_path import AwsSecurityGroupPathService, firewall_step, policy_summary
from backend.services.firewall_network_mapping import NETWORK_MAPPINGS, resolve_input_network, expected_zones_for_path
from backend.services.firewall_rule_export import _restore_rule_order, is_wildcard_value


def _unique(values): return list(dict.fromkeys(values))


def _summary(steps, source, destination, protocol, port, warnings, partial=False, protocol_number=None):
    block = next((step for step in steps if step['status'] == 'BLOCK'), None)
    unknown = any(step['status'] == 'UNKNOWN' for step in steps)
    status = 'BLOCK' if block else 'UNKNOWN' if not steps or all(step['status'] == 'UNKNOWN' for step in steps) else 'WARNING' if warnings or partial or unknown else 'PASS'
    reason = block['reason'] if block else '일부 Configuration 확인 필요' if status in {'WARNING','UNKNOWN'} else '현재 Configuration 기준 허용'
    return {'status': status, 'source': source, 'destination': destination,
            'service': f'IP / Protocol No. {protocol_number if protocol_number is not None else "ANY"}' if protocol=='IP' else f'{protocol} / {port if port is not None else "ANY"}',
            'primaryReason': reason, 'blockedAt': (block.get('firewall') or block.get('label')) if block else None,
            'warnings': _unique(warnings), 'confidence': 'UNKNOWN' if unknown else 'INFERRED' if warnings or partial else 'CONFIRMED'}


class PathAnalysis:
    def __init__(self, service, refresh=False):
        self.service, self.refresh = service, refresh
        self.snapshots = {}
        self.configs = {item['name']: item for item in service.firewalls.configurations()}
        self.dns = {}

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

    def analyze(self, source, destination, protocol, port, protocol_number):
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
        if not src[1] and not dst[1]: return self.enhance(base, src[0], dst[0], protocol, port, number)
        sources = src[2] if src[1] else [str(src[0])]
        destinations = dst[2] if dst[1] else [str(dst[0])]
        variants = []
        for i, (s, d) in enumerate(product(sources, destinations)):
            if i >= 256: break
            a, b = ipaddress.ip_network(s), ipaddress.ip_network(d)
            if a.version != b.version:
                variants.append({'source': s, 'destination': d, 'summary': {'status':'UNKNOWN','primaryReason':'IP address family mismatch'}, 'analysisPath': []}); continue
            pair = self.service._check_legacy(s, d, protocol, port, self.refresh, number, _snapshots=self.snapshots)
            pair = self.enhance(pair, a, b, protocol, port, number, src[1], dst[1])
            variants.append({'source':s, 'destination':d, 'summary':pair['summary'], 'analysisPath':pair['analysisPath'], 'details':pair['details']})
        total = len(sources) * len(destinations)
        signatures = {(item['summary']['status'], tuple((step.get('type'), step.get('firewall'), step.get('ingressZone'), step.get('egressZone'), step.get('status'), (step.get('matchedRule') or {}).get('rule'), step.get('rule'), (step.get('route') or {}).get('network')) for step in item['analysisPath'])) for item in variants}
        if variants:
            summary = copy.deepcopy(variants[0]['summary']); summary['source'], summary['destination'] = source, destination
            if len(signatures) > 1 or len(variants) != total:
                summary.update(status='WARNING', primaryReason='MIXED RESULT · Resolve IP별 결과/경로 확인 필요', blockedAt=None)
                summary['warnings'] = _unique(summary.get('warnings', []) + ['복수 Resolve 결과 또는 분석 한도 확인 필요'])
            base.update(summary=summary, analysisPath=variants[0]['analysisPath'], details={'ipResults':variants})
        else:
            base.update(summary={'status':'UNKNOWN','source':source,'destination':destination,'service':f'{protocol} / {port or "ANY"}',
                'primaryReason':'FQDN Resolve 실패 · 주소 기반 경로 확인 불가','blockedAt':None,'warnings':['DNS 확인 필요'],'confidence':'UNKNOWN'}, analysisPath=[], details={'ipResults':[]})
        base.update(mode='PATH', resolvedResults=variants, resolvedPairCount=total, analyzedPairCount=len(variants))
        return base

    def _networks(self, value, snapshot):
        from backend.services.firewall_path_check import _networks
        try: return [ipaddress.ip_network(value, strict=False)]
        except (ValueError, TypeError):
            if value in snapshot.get('objects', {}): return _networks(snapshot['objects'][value])
            for row in snapshot.get('interfaces', []) + snapshot.get('aliases', []):
                if value in {row.get('Name'), row.get('Hardware')}:
                    try: return [ipaddress.ip_network(row['IP Address'])]
                    except (ValueError, KeyError): pass
        return []

    def _route(self, snapshot, network):
        from backend.services.firewall_path_check import match_static_route
        if network is None: return None
        route = match_static_route(snapshot.get('routes', []), network)
        if route:
            alternatives = [match_static_route([item], network) for item in snapshot.get('routes', [])]
            alternatives = [item for item in alternatives if item and item['network'] == route['network']]
            if len({(item.get('gateway',''), item.get('interface',''), item.get('blackhole','')) for item in alternatives}) > 1:
                route = {**route, 'ambiguous': True, 'alternatives': alternatives}
        for row in snapshot.get('interfaces', []) + snapshot.get('aliases', []):
            try: connected = ipaddress.ip_interface(row['CIDR']).network
            except (ValueError, KeyError): continue
            if network.version == connected.version and network.subnet_of(connected):
                if route and ipaddress.ip_network(route['network']).prefixlen >= connected.prefixlen: continue
                route = {'network':str(connected), 'destination':str(connected.network_address), 'netmask':str(connected.prefixlen),
                         'interface':row.get('Parent Interface') or row['Name'], 'gateway':'', 'source':'connected_interface'}
        return route

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
            if _restore_rule_order(complete):
                positions = {row['Rule Name']:row['_Rule Order'] for row in complete}
                candidates.sort(key=lambda item: positions[item['row']['Rule Name']])
            else: return None, ['NAT Rule 평가 순서 확인 필요'], candidates
        return (candidates[0] if candidates else None), [], candidates

    def _translated(self, value, snapshot):
        networks = self._networks(value, snapshot)
        return networks[0] if len(networks)==1 and networks[0].num_addresses==1 else None

    def enhance(self, base, source, destination, protocol, port, number, source_fqdn=None, destination_fqdn=None):
        from backend.services.firewall_path_check import match_rules
        packet_source, packet_destination, packet_port = source, destination, port
        warnings, path_steps, results = [], [], []
        path = list(base['path'])
        same_vpc = bool(base.get('awsSecurityGroups',{}).get('networkPath')) and not path
        owners = [] if same_vpc else self._owners(destination)
        for owner in owners:
            if owner['firewall'] not in path: path.append(owner['firewall'])
        if not path and not same_vpc:
            connected = []
            for name, snapshot in self.snapshots.items():
                for interface in snapshot.get('interfaces', []):
                    try: network = ipaddress.ip_interface(interface.get('CIDR','')).network
                    except ValueError: continue
                    if source.version == network.version and source.subnet_of(network): connected.append((network.prefixlen, name))
            if connected:
                longest = max(item[0] for item in connected)
                candidates = _unique(name for prefix, name in connected if prefix == longest)
                if len(candidates) == 1: path.append(candidates[0])
                else: warnings.append('Source의 연결 Firewall 후보가 복수입니다')
        if protocol == 'ANY' or (protocol in {'TCP','UDP'} and port is None): warnings.append('Service 범위가 넓음 · 서비스별 정책이 다를 수 있습니다')
        for name in path:
            snapshot = self.snapshot(name)
            if snapshot is None:
                step={'type':'firewall','firewall':name,'label':name+' Firewall','status':'UNKNOWN','reason':'Firewall Configuration unavailable','confidence':'UNKNOWN'}
                path_steps.append(step)
                results.append({'firewall':name,'available':False,'policy':{'state':'unavailable'},'routing':{'destination':None,'return':None}})
                continue
            errors = snapshot.get('configurationErrors', {})
            warnings.extend(f'{name} {entity} 확인 불가: {message}' for entity,message in errors.items())
            expected = expected_zones_for_path(base['source'], base['destination'], path).get(name,(None,None))
            return_route = self._route(snapshot, packet_source)
            ingress = self._interface(snapshot, return_route)
            source_zone = ingress.get('Zone') if ingress else 'VPN' if (return_route or {}).get('interface','').casefold().startswith('xfrm') else expected[0]
            confidence = 'CONFIRMED' if ingress else 'INFERRED'
            if not ingress: warnings.append(f'{name} Ingress Zone에 Topology 추론 포함')
            original_destination, original_port = packet_destination, packet_port
            nat, nat_warnings, candidates = self._nat(snapshot, packet_source, packet_destination, protocol, packet_port, 'DNAT', ingress)
            warnings.extend(f'{name} {warning}' for warning in nat_warnings)
            certain = not nat_warnings and 'NATRule' not in errors
            nat_steps = []
            if nat:
                row = nat['row']; translated = self._translated(row['Translated Destination'], snapshot)
                certain = certain and not nat['warnings'] and translated is not None
                old_destination = packet_destination
                if translated is not None: packet_destination = translated
                target_firewall = resolve_input_network(str(packet_destination)).get('managedFirewall') if translated is not None else None
                if target_firewall and target_firewall not in path and len(path) < len(self.configs):
                    path.append(target_firewall); warnings.append('DNAT 대상 Topology Seed로 다음 Firewall 후보 추가')
                if row.get('Translated Service','').casefold() not in {'','original'}:
                    from backend.services.firewall_path_check import PORT_RANGE
                    resolved = snapshot.get('services',{}).get(row['Translated Service'],'')
                    matches = PORT_RANGE.findall(resolved.split('Destination:',1)[-1]) if 'Destination:' in resolved else []
                    if len(matches)==1 and (not matches[0][1] or matches[0][0]==matches[0][1]): packet_port=int(matches[0][0])
                    else: certain=False; warnings.append(f'{name} PAT service 변환 확인 필요')
                if not certain: warnings.append(f'{name} DNAT 선택/대상 확인 필요')
                nat_step={'type':'dnat','firewall':name,'label':'DNAT','status':'PASS' if certain else 'UNKNOWN',
                    'reason':f'{old_destination} → {packet_destination if translated is not None else row["Translated Destination"]}', 'rule':row['Rule Name'], 'nat':row}
                path_steps.append(nat_step);nat_steps.append(nat_step)
            route = self._route(snapshot, packet_destination)
            if route and route.get('gateway') and len(path) < len(self.configs):
                try: peers = self._owners(ipaddress.ip_network(route['gateway']))
                except ValueError: peers = []
                next_hops = _unique(peer['firewall'] for peer in peers if peer['firewall'] != name)
                if len(next_hops) == 1 and next_hops[0] not in path:
                    path.append(next_hops[0]); warnings.append(f'{name} Route Gateway로 Firewall 후보 경로 확장')
            egress = self._interface(snapshot, route)
            destination_zone = egress.get('Zone') if egress else 'VPN' if (route or {}).get('interface','').casefold().startswith('xfrm') else expected[1]
            if not egress: confidence='INFERRED'; warnings.append(f'{name} Egress Zone에 Topology 추론 포함')
            if (source_zone,destination_zone) != expected and any(expected): warnings.append(f'{name} 예상 경로와 실제 Firewall Configuration이 일치하지 않습니다')
            policy = match_rules(snapshot.get('rules',[]), packet_source, packet_destination, protocol, packet_port,
                source_zone, destination_zone, number, None if nat else destination_fqdn, source_fqdn, True)
            state = policy['state']; matched = policy.get('matchedRule')
            status = 'PASS' if state=='allow' else 'BLOCK' if state in {'deny','no_matching_rule'} and not policy.get('broadQuery') else 'UNKNOWN'
            reason = 'Matched Rule 기준 허용' if status=='PASS' else '명시적 차단 Rule' if state=='deny' else '일치 Allow Rule 없음' if status=='BLOCK' else 'Rule 순서/서비스 범위 확인 필요'
            if state == 'no_matching_rule' and any(item.get('sourceMatch') == 'partial' or item.get('destinationMatch') == 'partial' for item in policy.get('evaluations', [])):
                status='UNKNOWN'; reason='CIDR 일부 범위만 정책과 일치 · 전체 차단으로 단정하지 않습니다'
            unresolved = [item for item in policy.get('evaluations', [])
                if item.get('status','').casefold() in {'enable','enabled','활성'}
                and item.get('source_zone_match') and item.get('destination_zone_match')
                and item.get('serviceMatch')
                and (item.get('source_resolver_failed') or item.get('destination_resolver_failed'))]
            if unresolved:
                status='UNKNOWN'; reason='미해석 Rule Object로 우선 매칭 정책 확인 필요'
                warnings.append(f'{name} Rule Object 해석 실패')
            if confidence != 'CONFIRMED' and status == 'BLOCK':
                status='UNKNOWN'; reason='추론 Zone 기준 정책 불일치 · 실제 Zone 확인 필요'
            if 'FirewallRule' in errors or not certain:
                status='UNKNOWN'; reason='Rule/NAT Configuration 확인 필요'
            if route and not route.get('ambiguous') and route.get('blackhole','').casefold()=='enable' and status!='BLOCK': status='BLOCK';reason='Destination Blackhole Route'
            return_status = 'UNKNOWN' if not return_route or return_route.get('ambiguous') else 'FAIL' if return_route.get('blackhole','').casefold()=='enable' else 'PASS'
            if not route: warnings.append(f'{name} Destination Route 미확인')
            if route and route.get('ambiguous'): warnings.append(f'{name} 동등 Prefix Route 후보가 복수입니다')
            if return_status!='PASS': warnings.append(f'{name} Return Route {return_status}')
            if return_status=='FAIL' and status=='PASS': status='BLOCK'; reason='Return Blackhole Route'
            if status=='PASS' and (not route or return_status!='PASS' or confidence!='CONFIRMED' or errors): status='WARNING'
            gateway = next((row for row in snapshot.get('gateways',[]) if egress and row.get('Name')==egress.get('Gateway Name')), None)
            step={'type':'firewall','firewall':name,'label':name+' Firewall','status':status,'reason':reason,
                  'ingressZone':source_zone,'egressZone':destination_zone,'ingressInterface':ingress,'egressInterface':egress,
                  'matchedRule':matched,'action':(matched or {}).get('action',''),'route':route,'returnRoute':{'status':return_status,'route':return_route},
                  'gateway':gateway,'confidence':confidence,'candidateRules':policy.get('matches',[]),'nat':nat_steps}
            path_steps.append(step)
            if route: path_steps.append({'type':'route','firewall':name,'label':'Destination Route','status':'UNKNOWN' if route.get('ambiguous') else 'BLOCK' if route.get('blackhole','').casefold()=='enable' else 'PASS','reason':route['network'],'route':route})
            snat, snat_warnings, snat_candidates = self._nat(snapshot, packet_source, original_destination, protocol, original_port, 'SNAT', egress, matched)
            warnings.extend(snat_warnings)
            if snat:
                row=snat['row']; target=row['Translated Source']
                translated=self._translated(target,snapshot)
                if target.casefold()=='masq' and egress:
                    try: translated=ipaddress.ip_network(egress.get('IP Address',''))
                    except ValueError: translated=None
                old_source=packet_source
                if translated is not None: packet_source=translated
                else: warnings.append(f'{name} SNAT 이후 실제 Source 주소 확인 필요')
                if snat['warnings']: warnings.append(f'{name} SNAT 선택 조건 확인 필요')
                snat_step={'type':'snat','firewall':name,'label':'SNAT','status':'PASS' if translated and not snat['warnings'] else 'UNKNOWN',
                           'reason':f'{old_source} → {target}','rule':row['Rule Name'],'nat':row}
                path_steps.append(snat_step);nat_steps.append(snat_step)
            if gateway: path_steps.append({'type':'gateway','firewall':name,'label':gateway['Name'],'status':'PASS','reason':gateway.get('Gateway IP',''),'gateway':gateway,'configurationOnly':True})
            results.append({'firewall':name,'available':True,'checkedAt':snapshot.get('checkedAt',''),
                'expectedZones':{'source':source_zone,'destination':destination_zone},'policy':policy,
                'routing':{'destination':route,'return':return_route,'returnStatus':return_status,'error':snapshot.get('routeError','')},'analysis':step})
        aws=AwsSecurityGroupPathService(self.service.root).check(packet_source,packet_destination,protocol,packet_port,number,path,base['partialPath'])
        # Source SG evaluates the original outgoing packet, destination SG the post-NAT packet.
        aws['outbound'] = base['awsSecurityGroups']['outbound']
        def sg_step(item):return {'type':'aws_sg','label':item['label'],'status':{'PASS':'PASS','FAIL':'BLOCK'}.get(item['state'],'UNKNOWN'),'reason':item['reason'],'awsSg':item}
        if aws['outbound']['state']!='N/A':path_steps.insert(0,sg_step(aws['outbound']))
        if aws['inbound']['state']!='N/A':path_steps.append(sg_step(aws['inbound']))
        reached=True
        for step in path_steps:
            step['reached']=reached
            if not reached:step['notReachedReason']='Not reached due to upstream firewall/SG block'
            if step['status']=='BLOCK':reached=False
        summary=_summary(path_steps,base['source']['input'],base['destination']['input'],protocol,port,warnings,base['partialPath'] and not owners, number)
        if summary['status']=='PASS' and warnings:summary['status']='WARNING'
        legacy_steps=([aws['outbound']] if aws['outbound']['state']!='N/A' else [])+[firewall_step(item) for item in results]+([aws['inbound']] if aws['inbound']['state']!='N/A' else [])
        base.update(mode='PATH',summary=summary,analysisPath=path_steps,path=path,firewalls=results,
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
        from backend.services.firewall_path_check import _networks, _query_address_match, service_match_details
        mode='SOURCE_REACHABILITY' if source else 'DESTINATION_EXPOSURE'
        value=source or destination; endpoint=self.endpoint(value,'Source' if source else 'Destination')
        known, fqdn, addresses, site=endpoint
        units={}; publications=[]
        for name, config in self.configs.items():
            if not config.get('configured'):continue
            snapshot=self.snapshot(name) or {}
            for row in snapshot.get('rules',[]):
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
                if match['match']=='none':continue
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
        for unit in list(units.values())[:500]:
            targets=unit['networks'] or [value for value in unit['fqdns'] if '*' not in value]
            cases=[]
            for target in targets:
                if unit['wildcard']:break
                try:
                    result=self.analyze(value if source else target,target if source else value,protocol,port,number)
                    cases.append({'target':target,'summary':result['summary'],'analysisPath':result['analysisPath'],'details':result.get('details',{})})
                except ValueError:cases.append({'target':target,'summary':{'status':'UNKNOWN','primaryReason':'주소/서비스 확인 필요'},'analysisPath':[]})
            states={case['summary']['status'] for case in cases}
            state=next(iter(states)) if len(states)==1 else 'WARNING' if states else 'UNKNOWN'
            reason='정책 Object 전체 범위에 대한 Configuration 분석' if cases else 'ANY/FQDN/Object 범위 · 단일 Path 확정 불가'
            if unit['wildcard']:state='WARNING';reason='ANY 정책 범위 · Internet 전체 허용을 확정하지 않습니다'
            if unit['partialKnown']:state='WARNING';reason='입력 CIDR/Resolve 주소 일부만 정책 대상입니다'
            groups.append({**unit,'status':state,'reason':reason,'results':cases})
        warnings=['Service 범위가 넓음'] if protocol=='ANY' or protocol in {'TCP','UDP'} and port is None else []
        if len(units)>500:warnings.append('500개 그룹 분석 한도 · 나머지 범위 미확인')
        failures=[f'{name} {entity}: {message}' for name,snapshot in self.snapshots.items() for entity,message in snapshot.get('configurationErrors',{}).items()]
        warnings.extend(failures)
        summary={'status':'UNKNOWN' if not groups else 'WARNING' if warnings or len({group['status'] for group in groups}) > 1 or any(group['status'] in {'WARNING','UNKNOWN'} for group in groups) else 'BLOCK' if all(group['status']=='BLOCK' for group in groups) else 'PASS',
            'source':source,'destination':destination,'service':f'{protocol} / {port if port is not None else "ANY"}',
            'primaryReason':'정책 Object/Network별 분석 · 미표시 범위를 허용으로 간주하지 마세요', 'blockedAt':None,'warnings':_unique(warnings),'confidence':'INFERRED'}
        return {'mode':mode,'summary':summary,'groups':groups,'analysisPath':[], 'details':{'publishedServices':publications,
            'configurationErrors':failures},'source':site if source else None,'destination':site if destination else None,
            'protocol':protocol,'port':port,'protocolNumber':number,'checkedAt':datetime.now(timezone.utc).isoformat()}
