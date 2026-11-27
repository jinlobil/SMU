"""Immutable, cache-derived packet topology. No API or DNS calls during analysis."""
from __future__ import annotations

import ipaddress
import copy
import threading
from collections import OrderedDict
from dataclasses import dataclass

from backend.services.aws_assets import AwsAssetService
from backend.services.aws_security_group_path import _interface_addresses
from backend.services.firewall_path_decisions import interface_network


def network(value):
    try:
        return ipaddress.ip_network(value, strict=False)
    except (ValueError, TypeError):
        return None


def contains(scope, query):
    return scope is not None and query is not None and scope.version == query.version and query.subnet_of(scope)


def enabled(row):
    return str(row.get('status', row.get('Status', ''))).casefold() not in {'disable', 'disabled', 'off', 'false'}


@dataclass(frozen=True)
class Endpoint:
    kind: str
    address: object
    owner: dict | None = None
    aws: dict | None = None
    reason: str = ''

    def public(self):
        return {'type': self.kind, 'address': str(self.address), 'owner': self.owner, 'aws': self.aws, 'reason': self.reason}


class RouteResolver:
    def __init__(self, snapshots, indexes):
        self.snapshots, self.indexes = snapshots, indexes
        self._cache=OrderedDict();self._lock=threading.RLock()

    def interface(self, firewall, name):
        index=self.indexes.get(firewall)
        return index.interface_refs.get(name) if index and name else None

    def select(self,firewall,destination):
        key=(firewall,destination)
        with self._lock:
            if key in self._cache:return copy.copy(self._cache[key])
        value=self._select(firewall,destination)
        with self._lock:
            self._cache[key]=value
            if len(self._cache)>8192:self._cache.popitem(last=False)
        return copy.copy(value)

    def _select(self,firewall,destination):
        index=self.indexes.get(firewall)
        if index is None or destination is None:return None
        candidates=[index.connected_records[i] for i in index.connected_routes.find(destination)
            if contains(index.connected_records[i]['_cidr'],destination)]
        candidates += [index.route_records[i] for i in index.routes.find(destination) if i in index.route_records
            and enabled(index.route_records[i]) and contains(index.route_records[i]['_cidr'],destination)]
        if not candidates:candidates=[row for row in index.default_routes if row['_cidr'].version==destination.version]
        if not candidates:return None
        key=lambda row:(row['_cidr'].prefixlen,row['routeType']=='Connected',-row['_distance'])
        best=max(map(key,candidates));choices=[row for row in candidates if key(row)==best]
        clean=lambda row:{key:value for key,value in row.items() if not key.startswith('_')}
        result=clean(choices[0])
        if len({(r.get('interface'),r.get('gateway'),r.get('blackhole')) for r in choices})>1:
            result.update(ambiguous=True,alternatives=[clean(row) for row in choices])
        return result


class TopologyIndex:
    def __init__(self, snapshots, indexes, aws_data=None):
        self.snapshots, self.indexes = snapshots, indexes
        self.aws_data = copy.deepcopy(aws_data) if isinstance(aws_data, dict) else {}
        self.aws_errors = []
        for key in ('instances', 'network_interfaces', 'addresses', 'security_groups', 'security_group_rules'):
            values = self.aws_data.get(key, [])
            if not isinstance(values, list) or any(not isinstance(row, dict) for row in values):
                self.aws_errors.append(key)
                self.aws_data = {**self.aws_data, key: []}
        self.snapshot_ids = {name: row.get('metadata', {}).get('snapshot_id') for name, row in snapshots.items()}
        self.routes = RouteResolver(snapshots, indexes)
        self.addresses, self.public_addresses, self.aws_addresses = {}, {}, {}
        self.edges = []
        for name, snapshot in snapshots.items():
            for item in snapshot.get('interfaces', []) + snapshot.get('aliases', []):
                ip = network(item.get('IP Address'))
                if ip is None or ip.num_addresses != 1:
                    continue
                parent = item.get('Parent Interface') or item.get('Name')
                parent_row = self.routes.interface(name, parent) or {}
                owner = {**item, 'firewall': name, 'interface': item.get('Name'), 'parent_interface': parent,
                    'zone': parent_row.get('Zone') or item.get('Zone', ''), 'interface_type': 'alias' if item.get('Parent Interface') else 'physical'}
                self.addresses.setdefault(str(ip.network_address), []).append(owner)
                if item.get('Parent Interface'):
                    self.edges.append({'type': 'PARENT_OF', 'firewall': name, 'from': parent, 'to': item['Name']})
        self._aws()
        from backend.services.firewall_configuration import PrefixIndex
        self.connected=PrefixIndex();self.connected_rows={}
        for name,snapshot in snapshots.items():
            for i,row in enumerate(snapshot.get('interfaces',[])):
                cidr=interface_network(row)
                if enabled(row) and cidr is not None:
                    self.connected.add(str(cidr),(name,i));self.connected_rows[(name,i)]=(cidr,row)
        self.cache_lock=threading.RLock();self.partition_cache=OrderedDict();self.query_cache=OrderedDict()
        from collections import defaultdict
        self.sg_rules=defaultdict(list)
        for row in self.aws_data.get('security_group_rules',[]):
            if row.get('GroupId') and isinstance(row.get('IsEgress'),bool):self.sg_rules[(row['GroupId'],row['IsEgress'])].append(row)
        self.sg_groups={row['GroupId']:row for row in self.aws_data.get('security_groups',[]) if row.get('GroupId')}

    def _aws(self):
        instances=list(self.aws_data.get('instances',[]))
        instance_ids={item.get('InstanceId') for item in instances}
        embedded={row.get('NetworkInterfaceId') for item in instances for row in item.get('NetworkInterfaces',[]) if isinstance(row,dict)}
        instances.extend({'NetworkInterfaces':[eni]} for eni in self.aws_data.get('network_interfaces',[]) if eni.get('NetworkInterfaceId') not in embedded and (eni.get('Attachment') or {}).get('InstanceId') not in instance_ids)
        for instance in instances:
            for eni in AwsAssetService.attached_interfaces(instance, self.aws_data):
                refs = eni.get('Groups')
                valid = isinstance(refs, list) and all(isinstance(item, dict) and item.get('GroupId') for item in refs)
                base = {'state': 'IDENTIFIED', 'reason': 'Cached IP / ENI exact match', 'instanceId': instance.get('InstanceId'),
                    'eniId': eni.get('NetworkInterfaceId'), 'vpcId': eni.get('VpcId') or instance.get('VpcId'),
                    'subnetId': eni.get('SubnetId') or instance.get('SubnetId'),
                    'groupIds': [item['GroupId'] for item in refs] if valid else [], 'groupsValid': bool(valid and eni.get('NetworkInterfaceId')),
                    'name': AwsAssetService._tags(instance).get('Name', '-'), 'description': eni.get('Description', '')}
                pairs = [(eni.get('PrivateIpAddress'), (eni.get('Association') or {}).get('PublicIp'))]
                pairs += [(item.get('PrivateIpAddress'), (item.get('Association') or {}).get('PublicIp')) for item in eni.get('PrivateIpAddresses', [])]
                for eip in self.aws_data.get('addresses', []):
                    attached = eip.get('NetworkInterfaceId') == eni.get('NetworkInterfaceId') and bool(eni.get('NetworkInterfaceId'))
                    private = eip.get('PrivateIpAddress')
                    if not eip.get('NetworkInterfaceId'):
                        attached = eip.get('InstanceId') == instance.get('InstanceId') and any(private == ip for ip, _ in pairs)
                    if attached and private:
                        pairs.append((private, eip.get('PublicIp')))
                for private, public in pairs:
                    if network(private) is None:
                        continue
                    self._add_aws(private, {**base, 'ip': private, 'privateIp': private, 'addressKind': 'private'})
                    if network(public) is None:
                        continue
                    item = {**base, 'ip': public, 'public_ip': public, 'private_ip': private, 'privateIp': private, 'addressKind': 'public'}
                    self._add_aws(public, item)
                    self.public_addresses[public] = self.aws_addresses[public]
                    self.edges.append({'type': 'PUBLIC_MAPS_TO', 'from': public, 'to': private, 'eni': base['eniId']})
                for ip, kind in _interface_addresses(eni):
                    if kind == 'ipv6':
                        self._add_aws(str(ip), {**base, 'ip': str(ip), 'addressKind': 'ipv6'})

        # Join only after every ENI has been indexed; duplicated private addresses
        # in different VPCs must not bind unrelated public EIPs to the same Firewall.
        for public, item in self.public_addresses.items():
            private = item.get('private_ip')
            owners = self.addresses.get(private, [])
            private_entry = self.aws_addresses.get(private, {})
            if item.get('state') == 'UNKNOWN' or private_entry.get('state') == 'UNKNOWN' or len(owners) > 1:
                item.update(state='UNKNOWN', reason='Ambiguous AWS / Sophos private address ownership')
            elif len(owners) == 1:
                owner = owners[0]
                item.update(owner_type='firewall', firewall=owner['firewall'], interface=owner['interface'],
                    parent_interface=owner['parent_interface'], zone=owner['zone'], interface_type=owner['interface_type'])
            else:
                item['owner_type'] = 'instance'

    def _add_aws(self, ip, item):
        old = self.aws_addresses.get(ip)
        if old and old.get('state') == 'UNKNOWN':
            return
        if old and (old.get('eniId'), old.get('instanceId'), old.get('privateIp')) != (item.get('eniId'), item.get('instanceId'), item.get('privateIp')):
            self.aws_addresses[ip] = {'state': 'UNKNOWN', 'reason': 'Ambiguous cached IP ownership', 'ip': ip}
        else:
            self.aws_addresses[ip] = item

    def resolve(self, query):
        key = str(query.network_address) if query is not None and query.num_addresses == 1 else None
        aws = self.aws_addresses.get(key)
        if aws and aws.get('state') == 'UNKNOWN':
            return Endpoint('UNKNOWN_ENDPOINT', query, aws=aws, reason=aws['reason'])
        if aws and aws.get('owner_type') == 'firewall':
            owner = next((item for item in self.addresses.get(aws['private_ip'], []) if item['firewall'] == aws['firewall']), None)
            return Endpoint('FIREWALL_PUBLIC_IP', query, owner, aws)
        owners = self.addresses.get(key, [])
        if len(owners) == 1:
            return Endpoint('FIREWALL_ALIAS' if owners[0]['interface_type'] == 'alias' else 'FIREWALL_INTERFACE', query, owners[0], aws)
        if len(owners) > 1:
            return Endpoint('UNKNOWN_ENDPOINT', query, reason='Ambiguous firewall address ownership')
        if not aws and key:
            possible = [item for item in self.aws_data.get('instances', []) if key in {item.get('PrivateIpAddress'), item.get('PublicIpAddress')} ]
            if possible:
                return Endpoint('UNKNOWN_ENDPOINT', query, reason='EC2는 식별됐으나 IP에 연결된 ENI 확인 불가')
        if aws:
            return Endpoint('AWS_PUBLIC_IP' if aws['addressKind'] == 'public' else 'AWS_PRIVATE_IP', query, aws=aws)
        local = self.connected_owner(query)
        if local:
            return Endpoint('SITE_NETWORK', query, {'firewall': local[0], **local[1]})
        from backend.services.firewall_network_mapping import NETWORK_MAPPINGS, SITE_FIREWALLS
        seeds = [item for item in NETWORK_MAPPINGS if contains(item.network, query)]
        if seeds:
            seed = max(seeds, key=lambda item: item.network.prefixlen)
            return Endpoint('VPN_NETWORK' if 'VPN' in seed.site else 'MANAGED_HOST', query,
                {'firewall': SITE_FIREWALLS.get(seed.site), 'site': seed.site, 'seed': True})
        if query is not None and query.is_global:
            return Endpoint('EXTERNAL_INTERNET', query)
        return Endpoint('UNKNOWN_ENDPOINT', query, reason='Endpoint ownership unavailable')

    def connected_owner(self,query,exclude=None):
        matches=[(self.connected_rows[key][0].prefixlen,key[0],self.connected_rows[key][1]) for key in self.connected.find(query)
            if key[0]!=exclude and contains(self.connected_rows[key][0],query)]
        if not matches:return None
        best=max(item[0] for item in matches)
        selected={(name,row['Name']):row for prefix,name,row in matches if prefix==best}
        if len(selected)==1:
            (name,_),row=next(iter(selected.items()));return name,row
        return None

    def first_firewall(self, source, destination):
        owned = self.connected_owner(source.address)
        if owned:
            return owned[0], owned[1]
        seed = (source.owner or {}).get('firewall')
        if seed and seed in self.snapshots:
            return seed, None
        routes = []
        for name in self.snapshots:
            route = self.routes.select(name, source.address)
            if route and not route.get('ambiguous') and route.get('zone') not in {'WAN', 'VPN', ''} and network(route['network']).prefixlen > 0:
                routes.append((network(route['network']).prefixlen, name, route))
        if routes:
            best = max(item[0] for item in routes)
            candidates = [(name, route) for prefix, name, route in routes if prefix == best]
            if len(candidates) == 1:
                name, route = candidates[0]
                return name, self.routes.interface(name, route.get('interface'))
        if destination.owner and destination.kind.startswith('FIREWALL_'):
            return destination.owner['firewall'], self.routes.interface(destination.owner['firewall'], destination.owner['parent_interface'])
        # Published private addresses may be selected through a specific DNAT reference.
        return None, None

    def next_firewall(self, current, context, route):
        gateway = network(route.get('gateway'))
        owners = self.addresses.get(str(gateway.network_address), []) if gateway else []
        peers = {item['firewall'] for item in owners if item['firewall'] != current}
        if len(peers) == 1:
            return peers.pop(), 'gateway_owner'
        local = self.connected_owner(context.destination, exclude=current)
        if route.get('zone') == 'VPN':
            candidates = []
            for name in self.snapshots:
                if name == current:
                    continue
                forward = self.routes.select(name, context.destination)
                reverse = self.routes.select(name, context.source)
                if forward and reverse and reverse.get('zone') == 'VPN' and forward.get('zone') not in {'WAN', 'VPN', ''}:
                    candidates.append((network(forward['network']).prefixlen, name))
            if candidates:
                best = max(prefix for prefix, _ in candidates)
                selected = {name for prefix, name in candidates if prefix == best}
                if len(selected) == 1:
                    return selected.pop(), 'reciprocal_vpn_routes'
            return None, 'vpn_peer_unresolved'
        if local and route.get('routeType') != 'Connected':
            return local[0], 'connected_network_owner'
        return None, None
