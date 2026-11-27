"""Prepared service interval indexes. Construction happens with the configuration generation."""
import bisect
import re
from collections import defaultdict

from backend.services.firewall_rule_export import is_wildcard_value
from backend.services.firewall_path_decisions import normalized_service_lines


class ServiceIndex:
    def __init__(self, rows, names='Service', resolved='Service Resolved / Protocol / Port', wildcard='service_wildcard'):
        self.any=set();self.unknown=set();self.protocols=defaultdict(set);self.intervals={};self.bounds=defaultdict(dict)
        events={p:defaultdict(lambda:defaultdict(int)) for p in ('TCP','UDP')}
        for i,row in enumerate(rows):
            text=row.get(resolved,'');labels=row.get(names,'')
            if row.get(wildcard) or any(is_wildcard_value(v) for v in (labels+'\n'+text).splitlines()):
                self.any.add(i);continue
            if row.get('_Missing Services') or not text:self.unknown.add(i)
            recognized=False
            for protocol in ('TCP','UDP','ICMP','ICMPV6','IP','GRE','ESP','AH'):
                for line in normalized_service_lines(text,protocol):
                    actual=re.search(r'Protocol:\s*([^|]+)',line,re.I)
                    if not actual:continue
                    if actual.group(1).strip().upper()!=protocol:continue
                    recognized=True;self.protocols[protocol].add(i)
                    if protocol not in events:continue
                    value=re.search(r'Destination:\s*([^|]+)',line,re.I)
                    ranges=re.findall(r'(\d{1,5})(?:\s*[:-]\s*(\d{1,5}))?',value.group(1)) if value else []
                    if not ranges:self.unknown.add(i)
                    for start,end in ranges:
                        a,b=int(start),int(end or start)
                        if not 0<=a<=b<=65535:self.unknown.add(i);continue
                        events[protocol][a][i]+=1;events[protocol][b+1][i]-=1
                        self.bounds[protocol].setdefault(i,set()).update((max(1,a),b+1))
            if not recognized:self.unknown.add(i)
        for protocol,points in events.items():
            active=defaultdict(int);positions=[];values=[]
            for point,changes in sorted(points.items()):
                for identifier,change in changes.items():
                    active[identifier]+=change
                    if not active[identifier]:del active[identifier]
                positions.append(point);values.append(frozenset(active))
            self.intervals[protocol]=(positions,values)

    def find(self, protocol, port=None, number=None):
        result=self.any|self.unknown
        if protocol in {'ANY','IP'}:return result|set().union(*self.protocols.values())
        if protocol in self.intervals and port is not None:
            positions,values=self.intervals[protocol];at=bisect.bisect_right(positions,port)-1
            if at>=0:result.update(values[at])
        else:result.update(self.protocols.get(protocol,()))
        # IP-number rules are validated by the shared matcher, never discarded by this filter.
        result.update(self.protocols.get('IP',()))
        return result
