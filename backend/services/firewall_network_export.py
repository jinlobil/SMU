"""Interface/Alias, Zone and Gateway mappings from the supplied SFOS XML fields."""
import ipaddress

from backend.services.firewall_rule_export import _nodes, _direct_child, _direct_text, _tag

INTERFACE_COLUMNS = ['Name', 'Type', 'Parent Interface', 'Hardware', 'Zone', 'IP Family', 'IPv4 Assignment',
                     'IP Address', 'Netmask', 'CIDR', 'Gateway Name', 'Gateway IP', 'Interface Status', 'Status',
                     'Interface Speed', 'Auto Negotiation', 'MTU', 'MAC Address']
ZONE_COLUMNS = ['Name', 'Type', 'Members', 'Device Access', 'Description']
GATEWAY_COLUMNS = ['Name', 'IP Family', 'Gateway IP', 'Type', 'Weight', 'Failover Protocol',
                   'Failover Target', 'Failover Port', 'Failover Condition']


def interface_cidr(address, netmask):
    try:
        return str(ipaddress.ip_interface(f'{address}/{netmask}')) if address and netmask else ''
    except (ValueError, TypeError): return ''


def _family(address):
    try: return f'IPv{ipaddress.ip_address(address).version}'
    except (ValueError, TypeError): return ''


def _entity_records(xml_text, entity):
    nodes = _nodes(xml_text, entity)
    # A same-named reference inside a record (e.g. BreakoutMembers/Interface)
    # is not a separately returned entity, even when it has nested fields.
    nested = {id(child) for node in nodes for child in node.iter() if child is not node and _tag(child) == entity}
    return [node for node in nodes if id(node) not in nested and list(node)]


def parse_interfaces(xml_text):
    rows = []
    for node in _entity_records(xml_text, 'Interface'):
        row = dict.fromkeys(INTERFACE_COLUMNS, '')
        for column, field in [('Name', 'Name'), ('Hardware', 'Hardware'), ('Zone', 'NetworkZone'),
            ('IPv4 Assignment', 'IPv4Assignment'), ('IP Address', 'IPAddress'), ('Netmask', 'Netmask'),
            ('Gateway Name', 'GatewayName'), ('Gateway IP', 'GatewayIP'), ('Interface Status', 'InterfaceStatus'),
            ('Status', 'Status'), ('Interface Speed', 'InterfaceSpeed'), ('Auto Negotiation', 'AutoNegotiation'),
            ('MTU', 'MTU'), ('MAC Address', 'MACAddress')]:
            row[column] = _direct_text(node, field)
        row['Type'] = 'Physical'
        row['IP Family'] = _family(row['IP Address'])
        row['CIDR'] = interface_cidr(row['IP Address'], row['Netmask'])
        rows.append(row)
    return rows


def parse_aliases(xml_text, interfaces=()):
    parents = {key: row for row in interfaces for key in (row.get('Name'), row.get('Hardware')) if key}
    rows = []
    for node in _entity_records(xml_text, 'Alias'):
        row = dict.fromkeys(INTERFACE_COLUMNS, '')
        for column, field in [('Name', 'Name'), ('Parent Interface', 'Interface'), ('IP Family', 'IPFamily'),
                              ('IP Address', 'IPAddress'), ('Netmask', 'Netmask')]:
            row[column] = _direct_text(node, field)
        row['Type'] = 'Alias'
        row['Zone'] = parents.get(row['Parent Interface'], {}).get('Zone', '')
        row['CIDR'] = interface_cidr(row['IP Address'], row['Netmask'])
        rows.append(row)
    return rows


_ACCESS = {
    'AdminServices': [('HTTPS', 'HTTPS'), ('SSH', 'SSH')],
    'AuthenticationServices': [('ClientAuthentication', 'Client Authentication'), ('CaptivePortal', 'Captive Portal'),
                               ('RadiusSSO', 'Radius SSO'), ('ChromebookSSO', 'Chromebook SSO')],
    'NetworkServices': [('DNS', 'DNS'), ('Ping', 'Ping')],
    'OtherServices': [('WebProxy', 'Web Proxy'), ('UserPortal', 'User Portal'), ('WirelessProtection', 'Wireless Protection'),
                      ('SMTPRelay', 'SMTP Relay'), ('SNMP', 'SNMP')],
    'VPNServices': [('VPNPortal', 'VPN Portal'), ('SSLVPN', 'SSL VPN')],
}


def parse_zones(xml_text, interfaces=()):
    members = {}
    for row in interfaces:
        if row.get('Type') == 'Physical' and row.get('Zone') and row.get('Name'):
            members.setdefault(row['Zone'], []).append(row['Name'])
    rows = []
    for node in _entity_records(xml_text, 'Zone'):
        name = _direct_text(node, 'Name')
        access = _direct_child(node, {'ApplianceAccess'})
        enabled = []
        if access is not None:
            for group, services in _ACCESS.items():
                category = _direct_child(access, {group})
                if category is not None:
                    enabled.extend(label for field, label in services if _direct_text(category, field).casefold() == 'enable')
        rows.append({'Name': name, 'Type': _direct_text(node, 'Type'),
                     'Members': '\n'.join(dict.fromkeys(members.get(name, []))),
                     'Device Access': '\n'.join(enabled), 'Description': _direct_text(node, 'Description')})
    return rows


def parse_gateways(xml_text):
    rows, timeouts = [], []
    for configuration in _nodes(xml_text, 'GatewayConfiguration'):
        timeout = _direct_text(configuration, 'GatewayFailoverTimeout')
        if timeout and timeout not in timeouts: timeouts.append(timeout)
        for node in list(configuration):
            if _tag(node) != 'Gateway': continue
            rules = _direct_child(node, {'FailOverRules'})
            rules = [rule for rule in list(rules) if _tag(rule) == 'Rule'] if rules is not None else []
            row = {'Name': _direct_text(node, 'Name'), 'IP Family': _direct_text(node, 'IPFamily'),
                   'Gateway IP': _direct_text(node, 'IPAddress'), 'Type': _direct_text(node, 'Type'),
                   'Weight': _direct_text(node, 'Weight')}
            for column, field in [('Failover Protocol', 'Protocol'), ('Failover Target', 'IPAddress'),
                                  ('Failover Port', 'Port'), ('Failover Condition', 'Condition')]:
                # Preserve empty slots: line N refers to the same rule in all four columns.
                row[column] = '\n'.join(_direct_text(rule, field) for rule in rules)
            rows.append(row)
    return rows, timeouts


def collect_network_sheets(configs, clients, errors, progress):
    """Collect four read entities once/device and preserve partial Interface data."""
    from backend.services.firewall import FirewallClient
    from backend.services.firewall_rule_export import _safe_export_error, classify_export_error, log
    sections = {'Interface': [], 'Zone': [], 'Gateway': []}
    counts = {'Interface': {}, 'Alias': {}, 'Zone': {}, 'Gateway': {}}
    for config in configs:
        name, parsed, failed = config['name'], {}, {}
        for entity in ('Interface', 'Alias', 'Zone', 'GatewayConfiguration'):
            progress(f'{name} {entity} 조회 중')
            try:
                client = clients.get(name)
                if client is None:
                    client = FirewallClient(config); clients[name] = client
                raw = client.get(entity)
                if entity == 'Interface': parsed[entity] = parse_interfaces(raw)
                elif entity == 'Alias': parsed[entity] = parse_aliases(raw, parsed.get('Interface', []))
                elif entity == 'Zone': parsed[entity] = parse_zones(raw, parsed.get('Interface', []))
                else: parsed[entity] = parse_gateways(raw)
            except Exception as exc:
                message = _safe_export_error(exc, entity)
                failed[entity] = f'조회 실패 · {entity}: {message}'
                errors.append({'Firewall': name, 'Error Type': f'{entity}: {classify_export_error(exc)}', 'Message': message})
                log.warning('Firewall network export unavailable firewall=%s entity=%s error=%s', name, entity, message)
        combined = parsed.get('Interface', []) + parsed.get('Alias', [])
        interface = {'title': f'{name} Interfaces', 'tableName': f'tbl_interface_{name.lower()}', 'rows': combined}
        interface_errors = [failed[entity] for entity in ('Interface', 'Alias') if entity in failed]
        if interface_errors:
            if combined: interface['notes'] = interface_errors
            else: interface['message'] = '\n'.join(interface_errors)
        if 'Interface' in parsed or 'Alias' in parsed: counts['Interface'][name] = len(combined)
        if 'Alias' in parsed: counts['Alias'][name] = len(parsed['Alias'])
        sections['Interface'].append(interface)
        zone = {'title': f'{name} Zones', 'tableName': f'tbl_zone_{name.lower()}', 'rows': parsed.get('Zone', [])}
        if 'Zone' in failed: zone['message'] = failed['Zone']
        else:
            counts['Zone'][name] = len(zone['rows'])
            if 'Interface' in failed: zone['notes'] = [failed['Interface'] + ' · Members 확인 불가']
        sections['Zone'].append(zone)
        gateways, timeouts = parsed.get('GatewayConfiguration', ([], []))
        gateway = {'title': f'{name} Gateways', 'tableName': f'tbl_gateway_{name.lower()}', 'rows': gateways}
        if 'GatewayConfiguration' in failed: gateway['message'] = failed['GatewayConfiguration']
        else:
            counts['Gateway'][name] = len(gateways)
            gateway['notes'] = [f'Gateway Failover Timeout : {value} sec' for value in timeouts]
        sections['Gateway'].append(gateway)
    return [{'name': kind, 'columns': columns, 'sections': sections[kind]}
            for kind, columns in [('Interface', INTERFACE_COLUMNS), ('Zone', ZONE_COLUMNS), ('Gateway', GATEWAY_COLUMNS)]], counts
