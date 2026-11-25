"""Decision helpers for Path Analysis; export parsers and legacy matchers stay unchanged."""
import copy
import ipaddress
import re

from backend.services.firewall_path_check import match_rules
from backend.services.firewall_rule_export import _restore_rule_order


def decide_policy(rows, source, destination, protocol, port, source_zone, destination_zone,
                  number=None, source_fqdn=None, destination_fqdn=None):
    rows = copy.deepcopy(rows)
    _restore_rule_order(rows)
    # Keep service records correlated: a TCP protocol on one member must not
    # combine with a UDP destination port from another member of the group.
    for row in rows:
        lines = row.get('Service Resolved / Protocol / Port', '').splitlines()
        normalized=[]
        for line in lines:
            match=re.search(r'Protocol:\s*IP\s*\|\s*Protocol Number:\s*(\d+)\b',line,re.I)
            if match and int(match.group(1)) in {1,6,17,58}:
                actual={1:'ICMP',6:'TCP',17:'UDP',58:'ICMPV6'}[int(match.group(1))]
                if protocol==actual:
                    line=re.sub(r'Protocol:\s*IP\b','Protocol: '+actual,line,flags=re.I)
                    if actual in {'TCP','UDP'} and 'Destination:' not in line:line+=' | Destination: 1:65535'
            line=re.sub(r'Destination:\s*(?:Any|All|\*)(?=\s*(?:\||$))','Destination: 1:65535',line,flags=re.I)
            normalized.append(line)
        lines=normalized
        row['Service Resolved / Protocol / Port'] = '\n'.join(line for line in lines
            if not re.search(r'Protocol:\s*([^|]+)', line, re.I)
            or re.search(r'Protocol:\s*([^|]+)', line, re.I).group(1).strip().upper() == protocol)
    policy = match_rules(rows, source, destination, protocol, port, source_zone, destination_zone,
                         number, destination_fqdn, source_fqdn, True)
    matched = policy.get('matchedRule')
    position = (matched or {}).get('position')
    unresolved = []
    for item in policy.get('evaluations', []):
        if item.get('status','').casefold() not in {'enable','enabled','활성'}: continue
        if not item['source_zone_match'] or not item['destination_zone_match']: continue
        service_unknown = bool(item['service']) and not item['serviceResolved'] and not item['anyService']
        if not item['serviceMatch'] and not service_unknown: continue
        if not (item['source_resolver_failed'] or item['destination_resolver_failed'] or service_unknown): continue
        if item['sourceMatch'] == 'none' and not item['source_resolver_failed']: continue
        if item['destinationMatch'] == 'none' and not item['destination_resolver_failed']: continue
        # An unresolved rule below an already selected rule cannot shadow it.
        if position is not None and item.get('position') is not None and item['position'] > position: continue
        unresolved.append(item['rule'])
    if unresolved:
        policy.update(state='unresolved_object', unresolvedRules=unresolved)
    state = policy['state']
    status = 'PASS' if state == 'allow' else 'BLOCK' if state in {'deny','no_matching_rule'} else 'WARNING'
    reason = ('일치하는 Allow Rule로 허용' if status == 'PASS' else
              '우선순위가 가장 높은 일치 Rule이 차단' if state == 'deny' else
              '일치하는 Allow Rule 없음 · 기본 Drop' if state == 'no_matching_rule' else
              'API에 Rule 순서가 없어 상충하는 일치 Rule의 우선순위를 결정할 수 없습니다')
    if state == 'unresolved_object':
        errors=[message for row in rows if row.get('Rule Name') in unresolved for message in row.get('_Object Resolution Errors',[])]
        status, reason = 'UNKNOWN', '; '.join(dict.fromkeys(errors)) if errors else 'API 결과에 필요한 Rule Object/Service가 없습니다: ' + ', '.join(unresolved)
    elif state == 'no_matching_rule' and any(item['sourceMatch']=='partial' or item['destinationMatch']=='partial' for item in policy.get('evaluations',[])):
        status, reason = 'WARNING', '입력 Network 중 일부 범위만 Rule에 일치합니다 · 허용/차단 범위가 상이합니다'
    return policy, status, reason


def interface_network(row):
    try:
        return ipaddress.ip_interface(row.get('CIDR') or f"{row['IP Address']}/{row['Netmask']}").network
    except (ValueError, KeyError, TypeError):
        return None


def service_slices(protocol, port, number, snapshots, aws_data):
    """Partition at every service boundary, never enumerate every TCP/UDP port."""
    if protocol in {'TCP','UDP'} and port is not None or protocol == 'IP' and number is not None or protocol not in {'ANY','TCP','UDP','IP'}:
        return [(protocol, port, port, number)]
    lines = [line for snapshot in snapshots for row in snapshot.get('rules',[])
             for line in row.get('Service Resolved / Protocol / Port','').splitlines()]
    lines += [line for snapshot in snapshots for value in snapshot.get('services',{}).values() for line in value.splitlines()]
    explicit_numbers={int(value) for line in lines for part in re.findall(r'Protocol Number:\s*([^|]+)',line,re.I) for value in re.findall(r'\d+',part) if int(value)<256}
    explicit_numbers.update(int(rule['IpProtocol']) for rule in aws_data.get('security_group_rules',[]) if str(rule.get('IpProtocol','')).isdigit() and int(rule['IpProtocol'])<256)
    def ip_groups(exclude=()):
        universe=set(range(256))-set(exclude)
        explicit=sorted(explicit_numbers & universe)
        groups=[(value,) for value in explicit]
        other=tuple(sorted(universe-set(explicit)))
        if other:groups.append(other)
        return [('IP',None,None,group) for group in groups]
    protocols = ['TCP','UDP','ICMP','ICMPV6'] if protocol == 'ANY' else [protocol]
    slices = []
    for current in protocols:
        if current not in {'TCP','UDP'}:
            if current == 'IP': slices += ip_groups()
            else: slices.append((current, None, None, None))
            continue
        bounds = {1,65536}
        for line in lines:
            match = re.search(r'Protocol:\s*([^|]+)', line, re.I)
            target = re.search(r'Destination:\s*([^|]+)', line, re.I)
            if not match or match.group(1).strip().upper() != current or not target: continue
            for start,end in re.findall(r'(\d{1,5})(?:\s*[:-]\s*(\d{1,5}))?',target.group(1)):
                a,b = int(start),int(end or start)
                if 1 <= a <= b <= 65535: bounds.update((a,b+1))
        for rule in aws_data.get('security_group_rules',[]):
            if str(rule.get('IpProtocol','')).upper() not in {current, '6' if current=='TCP' else '17'}: continue
            a,b = rule.get('FromPort'),rule.get('ToPort')
            if isinstance(a,int) and isinstance(b,int) and 1 <= a <= b <= 65535: bounds.update((a,b+1))
        points=sorted(bounds)
        slices += [(current,a,b-1,None) for a,b in zip(points,points[1:])]
    if protocol == 'ANY':
        slices += ip_groups({1,6,17,58})
    return slices


def progress(steps, source, destination):
    """A single backend-owned transition model shared by all UI views."""
    nodes=[{'id':'source','type':'source','title':'Source','label':'Source','status':'PASS','reason':source}]
    blocked=None
    for index, step in enumerate(steps):
        step['configurationStatus'] = step.get('configurationStatus',step['status'])
        if blocked:
            step.update(status='NOT_REACHED',reached=False,notReachedReason=f'Not reached · {blocked}에서 선행 차단')
        else:
            step['reached']=True
            if step['status']=='BLOCK': blocked=step.get('firewall') or step['label']
        nodes.append({'id':f'step-{index}','stepIndex':index,'type':step['type'],'title':step['label'],
                      'label':step['label'],'status':step['status'],'reason':step['reason']})
    nodes.append({'id':'destination','type':'destination','title':'Destination','label':'Destination',
                  'status':'NOT_REACHED' if blocked else 'UNKNOWN' if not steps or any(step['status']=='UNKNOWN' for step in steps) else 'WARNING' if any(step['status']=='WARNING' for step in steps) else 'PASS',
                  'reason':destination})
    links=[{'from':a['id'],'to':b['id'],'active':a['status']!='BLOCK' and b['status']!='NOT_REACHED',
            'status':'NOT_REACHED' if b['status']=='NOT_REACHED' else b['status']} for a,b in zip(nodes,nodes[1:])]
    return {'nodes':nodes,'links':links}
