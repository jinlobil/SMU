"""Persistent, generation-consistent firewall configuration and prebuilt search indexes."""
from __future__ import annotations
import copy
import ipaddress
import json
import re
import socket
import ssl
import urllib.error
import logging
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from backend.services.firewall_rule_export import _nodes, _values, _first, _object_maps, _fqdn_object_patterns, is_wildcard_value
from backend.services.firewall_path_check import _networks

log=logging.getLogger('smu.firewall.configuration')
TABLES=('rules','natRules','routes','interfaces','aliases','zones','gateways')
SCHEMA_VERSION=1


SAFE_REASONS=frozenset({
    'incomplete_snapshot','invalid_snapshot_tables','invalid_snapshot_objects','invalid_rule_name','duplicate_rule_name',
    'invalid_snapshot_metadata','invalid_snapshot_field','invalid_object_values','invalid_fqdn_values','index_version_mismatch',
    'configuration_missing','empty_snapshot','unconfirmed_empty_rules','partial_response','partial_response_count','invalid_response_root','authentication_failed',
})


def failure_diagnostic(exc,firewall,entity,stage,response=None):
    """Allowlisted metadata only: never return/log URL, body, credential or exception message."""
    from backend.services.firewall import parse_status
    http_status=int(exc.code) if isinstance(exc,urllib.error.HTTPError) else None
    api_code=None
    if response:
        code=parse_status(response).get('code','')
        if re.fullmatch(r'[0-9]{3,8}',code):api_code=code
    underlying=exc.reason if isinstance(exc,urllib.error.URLError) else exc
    if http_status:reason='http_authentication_or_access_denied' if http_status in {401,403} else 'http_request_failed'
    elif api_code and api_code!='200':reason='unsupported_entity' if api_code=='529' else 'firewall_api_error'
    elif isinstance(underlying,(TimeoutError,socket.timeout)):reason='timeout'
    elif isinstance(underlying,ssl.SSLCertVerificationError):reason='tls_certificate_verification_failed'
    elif isinstance(underlying,ssl.SSLError):reason='tls_error'
    elif isinstance(exc,urllib.error.URLError):reason='connection_failed'
    elif isinstance(exc,PermissionError):reason='permission_denied'
    elif isinstance(exc,OSError) and exc.errno==28:reason='disk_full'
    elif type(exc) is ValueError and str(exc) in SAFE_REASONS:reason=str(exc)
    else:
        import xml.etree.ElementTree as ET
        reason='invalid_xml' if isinstance(exc,ET.ParseError) else 'operation_failed'
    return {'firewall':firewall,'entity':entity,'stage':stage,'exception_type':type(exc).__name__,
            'http_status':http_status,'api_code':api_code,'reason':reason}


def log_failure(diagnostic):
    log.warning('Firewall refresh failed firewall=%s entity=%s stage=%s exception_type=%s http_status=%s api_code=%s reason=%s',
        *(diagnostic.get(key) for key in ('firewall','entity','stage','exception_type','http_status','api_code','reason')))


def validate_response(raw,entity):
    import xml.etree.ElementTree as ET
    root=ET.fromstring(raw)
    if root.tag.rsplit('}',1)[-1].casefold()!='response':raise ValueError('invalid_response_root')
    for login in root.iter('Login'):
        if any((node.text or '').strip().casefold() in {'authentication failure','authentication failed','login failed'} for node in login.iter()):raise ValueError('authentication_failed')
    nodes=_nodes(raw,entity)
    if entity in {'Interface','Alias','Zone'}:
        from backend.services.firewall_network_export import _entity_records
        nodes=_entity_records(raw,entity)
    scopes=[root]+[node for node in root if node.tag.rsplit('}',1)[-1].casefold() in {'pagination','page','result'}]
    for scope in scopes:
        fields={key.casefold():str(value) for key,value in scope.attrib.items()}
        fields.update({node.tag.rsplit('}',1)[-1].casefold():(node.text or '').strip() for node in scope if not list(node)})
        if any(fields.get(key,'').casefold() in {'true','1','yes'} for key in ('hasmore','more','hasnext')):raise ValueError('partial_response')
        if any(fields.get(key) for key in ('nexttoken','nextpage','continuationtoken')):raise ValueError('partial_response')
        for key in ('totalrecords','totalcount','total'):
            if fields.get(key,'').isdigit() and int(fields[key])!=len(nodes):raise ValueError('partial_response_count')
    return raw


def literal_address(value):
    try:ipaddress.ip_network(value,strict=False);return True
    except (ValueError,TypeError):return False


def normalize_objects(payloads, snapshot):
    """Reuse export field parsers; expand group membership once at refresh time."""
    objects,services=_object_maps(payloads)
    fqdns=_fqdn_object_patterns(payloads)
    object_groups={}
    for entity in ('IPHostGroup','FQDNHostGroup'):
        for node in _nodes(payloads.get(entity,'<Response/>'),entity):
            name=_first(node,'Name')
            object_groups[name]=[value for value in _values(node,{'IPHost','FQDNHost','Host','Member','HostName','IPHostGroup','FQDNHostGroup','Group'}) ]
    service_groups={_first(node,'Name'):[value for value in _values(node,{'Service','Services','Member','ServiceName','ServiceGroup'})]
                    for node in _nodes(payloads.get('ServiceGroup','<Response/>'),'ServiceGroup')}
    cycles=[]
    def expand(leaves,groups):
        memo={}
        def visit(name,trail=()):
            if name in memo:return memo[name]
            if name in trail:
                cycles.append('group_cycle');return []
            if name not in groups:return [name]
            values=[]
            for child in groups[name]:values.extend(visit(child,trail+(name,)))
            memo[name]=list(dict.fromkeys(values));return memo[name]
        resolved=dict(leaves)
        memberships={}
        for name in groups:
            members=visit(name);memberships[name]=members
            resolved[name]='\n'.join(leaves[member] if member in leaves else member for member in members if member in leaves or literal_address(member) or is_wildcard_value(member))
        return resolved,memberships
    objects,expanded=expand(objects,object_groups)
    services,expanded_services=expand(services,service_groups)
    for name,members in expanded.items():fqdns[name]=list(dict.fromkeys(pattern for member in members for pattern in fqdns.get(member,[])))
    for row in snapshot['rules']:
        for side in ('Source','Destination'):
            names=row.get(side+' Object','').splitlines()
            row[side+' Resolved']='\n'.join(objects[name] if name in objects else name for name in names if name in objects or literal_address(name) or is_wildcard_value(name))
            missing=[name for name in names if name not in objects and not literal_address(name) and not is_wildcard_value(name)]
            missing += [member for name in names for member in expanded.get(name,[]) if member not in objects and not literal_address(member) and not is_wildcard_value(member)]
            if missing:row['_'+side+' Missing Objects']=list(dict.fromkeys(missing))
            if names and all(name in object_groups and not object_groups[name] for name in names):row['_'+side+' EmptyGroup']=True
            row['_'+side+' FQDNs']=list(dict.fromkeys(pattern for name in names for pattern in fqdns.get(name,[])))
        names=row.get('Service','').splitlines()
        row['Service Resolved / Protocol / Port']='\n'.join(services[name] if name in services else name for name in names if name in services or is_wildcard_value(name))
        missing=[name for name in names if not is_wildcard_value(name) and (name not in services or 'Protocol:' not in services[name] and not is_wildcard_value(services[name]))]
        missing += [member for name in names for member in expanded_services.get(name,[]) if member not in services and not is_wildcard_value(member)]
        if missing:row['_Missing Services']=list(dict.fromkeys(missing))
    from backend.services.fqdn import resolve_fqdn
    dns={}
    for row in snapshot['rules']:
        for side in ('Source','Destination'):
            addresses=[]
            for pattern in row.get('_'+side+' FQDNs',[]):
                if '*' in pattern:continue
                if pattern not in dns:dns[pattern]=resolve_fqdn(pattern)
                addresses+=dns[pattern]
            if addresses:row[side+' Resolved']+='\n'+'\n'.join(addresses)
            elif row.get('_'+side+' FQDNs'):row.setdefault('_Object Resolution Errors',[]).append(side+' FQDN DNS Resolve 실패 또는 wildcard FQDN의 구체적 주소 데이터 없음')
    snapshot['resolvedFqdnAddresses']=dns
    snapshot.update(objects=objects,services=services,fqdnObjects=fqdns,objectGroups=object_groups,
                    expandedObjectGroups=expanded,serviceGroups=service_groups,expandedServiceGroups=expanded_services,
                    normalizationWarnings=list(dict.fromkeys(cycles)))
    return snapshot


class PrefixIndex:
    def __init__(self):
        self.prefixes=defaultdict(lambda:defaultdict(set));self.any=set()
    def add(self,text,identifier,wildcard=False):
        if wildcard or any(is_wildcard_value(value) for value in text.splitlines()):self.any.add(identifier)
        for network in _networks(text):self.prefixes[(network.version,network.prefixlen)][int(network.network_address)].add(identifier)
    def find(self,network):
        result=set(self.any)
        if network is None:return result
        bits=network.max_prefixlen
        for (version,prefix),values in self.prefixes.items():
            if version!=network.version:continue
            if prefix<=network.prefixlen:
                mask=((1<<bits)-1)^((1<<(bits-prefix))-1) if prefix else 0
                result.update(values.get(int(network.network_address)&mask,()))
            else:
                low,high=int(network.network_address),int(network.broadcast_address)
                for address,ids in values.items():
                    if low<=address<=high:result.update(ids)
        return result


class ConfigurationIndex:
    def __init__(self,snapshot):
        self.snapshot_id=snapshot.get('metadata',{}).get('snapshot_id')
        from backend.services.firewall_rule_export import _restore_rule_order
        self.ordered_rules=copy.deepcopy(snapshot.get('rules',[]));_restore_rule_order(self.ordered_rules)
        self.unresolved={side:set() for side in ('Source','Destination')}
        self.cuts=[]
        self.sides={side:PrefixIndex() for side in ('Source','Destination')}
        self.fqdns={side:defaultdict(set) for side in self.sides}
        self.objects=defaultdict(set);self.services=defaultdict(set);self.nat={field:PrefixIndex() for field in ('Original Source','Original Destination','Translated Source','Translated Destination')}
        self.hostObjects=PrefixIndex()
        for name,text in snapshot.get('objects',{}).items():self.hostObjects.add(text,name)
        self.objectParents=defaultdict(set)
        for parent,members in {**snapshot.get('objectGroups',{}),**snapshot.get('expandedObjectGroups',{})}.items():
            for member in members:self.objectParents[member].add(parent)
        self.serviceParents=defaultdict(set)
        for parent,members in snapshot.get('expandedServiceGroups',{}).items():
            for member in members:self.serviceParents[member].add(parent)
        self.natUnresolved={field:set() for field in self.nat}
        self.routes=PrefixIndex();self.interfaces={row['Name']:row for row in snapshot.get('interfaces',[]) if row.get('Name')}
        self.aliases={row['Name']:row for row in snapshot.get('aliases',[]) if row.get('Name')}
        self.gateways={row['Name']:row for row in snapshot.get('gateways',[]) if row.get('Name')}
        for i,row in enumerate(snapshot.get('rules',[])):
            for side in self.sides:
                self.sides[side].add(row.get(side+' Object','')+'\n'+row.get(side+' Resolved',''),i,row.get(side.lower()+'_wildcard',False))
                text=row.get(side+' Resolved','')
                if row.get('_'+side+' Missing Objects') or row.get(side+' Object') and not _networks(text) and i not in self.sides[side].any and not row.get('_'+side+' EmptyGroup'):self.unresolved[side].add(i)
                self.cuts+=_networks(text)
                for name in row.get(side+' Object','').splitlines():self.objects[name].add((side,i))
                for fqdn in row.get('_'+side+' FQDNs',[]):self.fqdns[side][fqdn].add(i)
            for name in row.get('Service','').splitlines():self.services[name].add(i)
        def nat_address(value):
            reference=self.aliases.get(value.lstrip('#'),self.interfaces.get(value.lstrip('#'),{}))
            if value.startswith('#') and reference.get('IP Address'):return reference['IP Address']
            return snapshot.get('objects',{}).get(value) or reference.get('IP Address') or value
        for i,row in enumerate(snapshot.get('natRules',[])):
            for field,index in self.nat.items():
                values=row.get(field,'').splitlines()
                text='\n'.join(nat_address(value) for value in values)
                index.add(text,i)
                if text and (not _networks(text) or any(value not in snapshot.get('objects',{}) and not literal_address(value) and not is_wildcard_value(value) and value.casefold() not in {'original','masq'} for value in values)) and i not in index.any and text.casefold() not in {'original','masq'}:self.natUnresolved[field].add(i)
        for row in snapshot.get('interfaces',[])+snapshot.get('aliases',[]):
            try:self.cuts.append(ipaddress.ip_interface(row.get('CIDR') or row['IP Address']+'/'+row['Netmask']).network)
            except (ValueError,KeyError,TypeError):pass
        for row in snapshot.get('natRules',[]):
            for field in ('Original Source','Original Destination'):
                self.cuts += [net for value in row.get(field,'').splitlines() for net in _networks(snapshot.get('objects',{}).get(value,value))]
        self.cuts=list(set(self.cuts))
        for i,row in enumerate(snapshot.get('routes',[])):
            text=row.get('destination','')
            if '/' not in text:text+='/'+(row.get('netmask') or '32')
            self.routes.add(text,i)
            self.cuts+=_networks(text)
    def rules(self,side,network=None,fqdn=None):
        from backend.services.fqdn import fqdn_matches
        result=self.sides[side].find(network) | self.unresolved[side]
        if fqdn:
            for pattern,ids in self.fqdns[side].items():
                if fqdn_matches(fqdn,pattern):result.update(ids)
        return result


def validate(snapshot, *, build_index=True):
    if not isinstance(snapshot,dict) or snapshot.get('configurationErrors'):raise ValueError('incomplete_snapshot')
    if not any(snapshot.get(table) for table in TABLES):raise ValueError('empty_snapshot')
    if any(not isinstance(snapshot.get(table),list) or any(not isinstance(row,dict) for row in snapshot[table]) for table in TABLES):raise ValueError('invalid_snapshot_tables')
    if any(not isinstance(snapshot.get(key),dict) for key in ('objects','services','fqdnObjects')):raise ValueError('invalid_snapshot_objects')
    if any(not row.get('Rule Name') for row in snapshot['rules']+snapshot['natRules']):raise ValueError('invalid_rule_name')
    for key in ('rules','natRules'):
        names=[row['Rule Name'] for row in snapshot[key]]
        if len(names)!=len(set(names)):raise ValueError('duplicate_rule_name')
    for table,fields in {
        'rules':('Rule Name','Status','Action','Source Object','Source Resolved','Destination Object','Destination Resolved','Service','Service Resolved / Protocol / Port'),
        'natRules':('Rule Name','Status','Original Source','Original Destination','Original Service','Translated Source','Translated Destination','Translated Service','Inbound Interface','Outbound Interface'),
        'routes':('destination','netmask','interface','gateway'),
        'interfaces':('Name','Zone','IP Address','CIDR'), 'aliases':('Name','Parent Interface','IP Address','CIDR'),
        'zones':('Name',),'gateways':('Name','Gateway IP')}.items():
        if any(not isinstance(row.get(field,''),str) for row in snapshot[table] for field in fields):raise ValueError('invalid_snapshot_field')
    if any(not isinstance(value,str) for field in ('objects','services') for value in snapshot[field].values()):raise ValueError('invalid_object_values')
    if any(not isinstance(value,list) or any(not isinstance(item,str) for item in value) for value in snapshot['fqdnObjects'].values()):raise ValueError('invalid_fqdn_values')
    metadata=snapshot.get('metadata',{})
    if not isinstance(metadata,dict):raise ValueError('invalid_snapshot_metadata')
    if metadata.get('schema_version')!=SCHEMA_VERSION or not metadata.get('snapshot_id') or not metadata.get('refreshed_at'):raise ValueError('invalid_snapshot_metadata')
    if not build_index:return None
    index=ConfigurationIndex(snapshot)
    if index.snapshot_id!=metadata['snapshot_id']:raise ValueError('index_version_mismatch')
    return index


class FirewallConfigurationStore:
    def __init__(self,root,firewalls,collector):
        self.root=Path(root);self.directory=self.root/'cache/firewall_config'
        self.firewalls,self.collector=firewalls,collector
        self.lock=threading.RLock();self.refresh_lock=threading.Lock()
        self.snapshots={};self.indexes={};self.topology=None;self.aws_data={};self.status={'running':False,'firewalls':{}}
        self.load()
        self.load_topology()
    def path(self,name):return self.directory/(name.casefold()+'.json')
    def load(self):
        try:
            status=json.loads((self.directory/'status.json').read_text(encoding='utf-8'))
            if isinstance(status,dict) and isinstance(status.get('firewalls'),dict):self.status={'running':False,'firewalls':{name:value for name,value in status['firewalls'].items() if isinstance(name,str) and isinstance(value,dict)}}
        except (OSError,ValueError,TypeError):pass
        for config in self.firewalls.configurations():
            name=config['name']
            try:
                payload=json.loads(self.path(name).read_text(encoding='utf-8'));index=validate(payload)
                if payload['metadata']['firewall']!=name:continue
                self.snapshots[name]=payload;self.indexes[name]=index
                previous=self.status['firewalls'].get(name,{})
                self.status['firewalls'][name]={**previous,'refresh_status':previous.get('refresh_status','loaded'),'last_successful_refresh':payload['metadata']['refreshed_at']}
            except (OSError,ValueError,KeyError,TypeError):continue
    def load_topology(self):
        from backend.services.firewall_topology import TopologyIndex
        try:
            manifest=json.loads((self.directory/'topology.json').read_text(encoding='utf-8'))
            versions={name:row.get('metadata',{}).get('snapshot_id') for name,row in self.snapshots.items()}
            if manifest.get('snapshot_ids') != versions:raise ValueError('topology_version_mismatch')
            self.aws_data=manifest['aws']
        except FileNotFoundError:
            # One-time migration from the pre-topology cache, not a per-query reload.
            try:self.aws_data=json.loads((self.root/'cache/aws.json').read_text(encoding='utf-8'))
            except (OSError,ValueError):self.aws_data={}
        except (OSError,ValueError,KeyError,TypeError):
            self.aws_data={}
            log.warning('Firewall topology generation unavailable reason=topology_version_mismatch')
        if not isinstance(self.aws_data,dict):self.aws_data={}
        self.topology=TopologyIndex(self.snapshots,self.indexes,self.aws_data)

    def collect_aws_topology(self):
        # Explicit refresh only. Never invokes SSM or unrelated inventory collectors.
        from backend.services.aws_assets import AwsCollector, load_aws_credentials, AwsConfigurationError
        try:load_aws_credentials(self.root/'env/aws_env.txt')
        except AwsConfigurationError:
            try:
                data=json.loads((self.root/'cache/aws.json').read_text(encoding='utf-8'))
                return data if isinstance(data,dict) else self.aws_data
            except (OSError,ValueError):return self.aws_data
        return AwsCollector(self.root).collect_network()

    def get(self,name):
        with self.lock:return self.snapshots.get(name)
    def index(self,name):
        with self.lock:return self.indexes.get(name)
    def info(self):
        with self.lock:return copy.deepcopy(self.status)
    def refresh(self,_leased=False):
        if not _leased and not self.refresh_lock.acquire(blocking=False):return self.info()
        with self.lock:self.status['running']=True
        pending_snapshots={};pending_indexes={}
        previous_snapshots=dict(self.snapshots)
        previous_status=copy.deepcopy(self.status['firewalls'])
        batch_stage='aws_topology_collection'
        try:
            aws_error=None
            try:aws_data=self.collect_aws_topology()
            except Exception as exc:aws_data=self.aws_data;aws_error=exc
            batch_stage='configuration_load'
            for config in self.firewalls.configurations():
                name=config['name'];attempt=datetime.now(timezone.utc).isoformat();started=time.perf_counter()
                snapshot=None;previous=self.get(name);saved=False;stage='api_collection'
                try:
                    if not config.get('configured'):
                        diagnostic=failure_diagnostic(ValueError('configuration_missing'),name,'Configuration','configuration')
                        diagnostic['missing_fields']=[field for field in ('host','port','username','password') if not config.get(field)]
                        log_failure(diagnostic)
                        with self.lock:
                            self.status['firewalls'][name]={**self.status['firewalls'].get(name,{}),
                                'last_refresh_attempt':attempt,'refresh_status':'failed','error':'ValueError',
                                'error_code':'configuration_missing','error_entities':['Configuration'],'diagnostics':[diagnostic]}
                        continue
                    # This is the online Collector, not _snapshot()/analysis_snapshots().
                    snapshot=copy.deepcopy(self.collector(config,True))
                    collected_at=datetime.now(timezone.utc).isoformat()
                    snapshot['metadata']={'schema_version':SCHEMA_VERSION,'snapshot_id':uuid.uuid4().hex,'firewall':name,'refreshed_at':collected_at,'source':'sophos_configuration_api'}
                    snapshot['checkedAt']=collected_at
                    stage='snapshot_validation';validate(snapshot,build_index=False)
                    if previous and previous['rules'] and not snapshot['rules'] and not snapshot.get('confirmedEmptyRules',False):raise ValueError('unconfirmed_empty_rules')
                    from backend.services.refresh import RefreshService
                    stage='snapshot_save';RefreshService(self.root).save_json_atomic(self.path(name),snapshot);saved=True
                    stage='index_build';index=ConfigurationIndex(snapshot)
                    if index.snapshot_id!=snapshot['metadata']['snapshot_id']:raise ValueError('index_version_mismatch')
                    with self.lock:
                        pending_snapshots[name]=snapshot;pending_indexes[name]=index
                        self.status['firewalls'][name]={'last_refresh_attempt':attempt,'last_successful_refresh':collected_at,
                            'refresh_status':'success','error':None,'error_code':None,'error_entities':[],'diagnostics':[]}
                    log.info('Firewall refresh collected firewall=%s stage=prepared snapshot_id=%s elapsed_ms=%.2f',name,index.snapshot_id,(time.perf_counter()-started)*1000)
                except Exception as exc:
                    details=list(snapshot.get('collectionDiagnostics',[])) if isinstance(snapshot,dict) else []
                    diagnostic=failure_diagnostic(exc,name,'Snapshot',stage)
                    if not details:details.append(diagnostic);log_failure(diagnostic)
                    if saved:
                        try:
                            from backend.services.refresh import RefreshService
                            if previous is not None:RefreshService(self.root).save_json_atomic(self.path(name),previous)
                            else:self.path(name).unlink(missing_ok=True)
                        except Exception as rollback_exc:
                            rollback=failure_diagnostic(rollback_exc,name,'Snapshot','snapshot_rollback')
                            details.append(rollback);log_failure(rollback)
                    with self.lock:
                        old=self.status['firewalls'].get(name,{})
                        self.status['firewalls'][name]={**old,'last_refresh_attempt':attempt,'refresh_status':'failed',
                            'error':type(exc).__name__,'error_code':diagnostic['reason'],
                            'error_entities':sorted({item['entity'] for item in details}),'diagnostics':details}
                log.debug('Firewall configuration refresh firewall=%s elapsed_ms=%.2f',name,(time.perf_counter()-started)*1000)
            if aws_error is not None:
                batch_stage='aws_topology_collection'
                raise aws_error
            from backend.services.firewall_topology import TopologyIndex
            batch_stage='topology_build'
            generation={**self.snapshots,**pending_snapshots};indexes={**self.indexes,**pending_indexes}
            topology=TopologyIndex(generation,indexes,aws_data)
            from backend.services.refresh import RefreshService
            batch_stage='topology_save'
            RefreshService(self.root).save_json_atomic(self.directory/'topology.json',{'snapshot_ids':topology.snapshot_ids,'aws':aws_data})
            with self.lock:
                self.snapshots=generation;self.indexes=indexes;self.aws_data=aws_data;self.topology=topology
        except Exception as exc:
            from backend.services.refresh import RefreshService
            for name in pending_snapshots:
                try:
                    if name in previous_snapshots:RefreshService(self.root).save_json_atomic(self.path(name),previous_snapshots[name])
                    else:self.path(name).unlink(missing_ok=True)
                except Exception as rollback_exc:log_failure(failure_diagnostic(rollback_exc,name,'Snapshot','snapshot_rollback'))
            pending_snapshots={};pending_indexes={}
            from backend.services.firewall import FIREWALL_DEFINITIONS
            for name in set(FIREWALL_DEFINITIONS)|set(self.status['firewalls']):
                diagnostic=failure_diagnostic(exc,name,'Configuration',batch_stage)
                log_failure(diagnostic)
                with self.lock:
                    self.status['firewalls'][name]={**previous_status.get(name,{}),
                        'last_refresh_attempt':datetime.now(timezone.utc).isoformat(),'refresh_status':'failed',
                        'error':type(exc).__name__,'error_code':diagnostic['reason'],'error_entities':['Configuration'],'diagnostics':[diagnostic]}
        finally:
            with self.lock:
                self.status['running']=False
            try:
                from backend.services.refresh import RefreshService
                RefreshService(self.root).save_json_atomic(self.directory/'status.json',self.info())
            except Exception as exc:log_failure(failure_diagnostic(exc,'Local','Status','status_save'))
            finally:self.refresh_lock.release()
        return self.info()
    def start_refresh(self):
        # Mark running before launching, so duplicate clicks share one refresh.
        with self.lock:
            if self.status['running'] or not self.refresh_lock.acquire(blocking=False):return self.info()
            self.status['running']=True
            threading.Thread(target=lambda:self.refresh(_leased=True),daemon=True,name='smu-firewall-config-refresh').start()
        return self.info()
