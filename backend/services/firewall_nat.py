"""NATRule mapping from the supplied, observed SFOS XML contract."""
from backend.services.firewall_rule_export import _nodes, _direct_child, _direct_text, _tag

NAT_COLUMNS = ['Rule Name', 'Status', 'IP Family', 'Position', 'After Rule',
               'Original Source', 'Original Destination', 'Original Service',
               'Translated Source', 'Translated Destination', 'Translated Service',
               'Inbound Interface', 'Outbound Interface', 'Linked Firewall Rule',
               'NAT Method', 'Health Check', 'Override Interface NAT', 'Description']


def _members(node, container_name, member_name):
    container = _direct_child(node, {container_name})
    if container is None: return ''
    return '\n'.join(dict.fromkeys((child.text or '').strip() for child in container.iter()
                                  if _tag(child) == member_name and (child.text or '').strip()))


def parse_nat_rules(xml_text, firewall_rules=()):
    reverse = {}
    for rule in firewall_rules:
        for name in str(rule.get('Linked NAT') or '').splitlines():
            if name.strip() and rule.get('Rule Name'):
                reverse.setdefault(name.strip(), []).append(rule['Rule Name'])
    rows = []
    for node in _nodes(xml_text, 'NATRule'):
        name = _direct_text(node, 'Name')
        after = _direct_child(node, {'After'})
        linked = _direct_text(node, 'LinkedFirewallrule')
        if not linked or linked.casefold() == 'none':
            linked = '\n'.join(dict.fromkeys(reverse.get(name, [])))
        rows.append({'Rule Name': name, 'Status': _direct_text(node, 'Status'),
            'IP Family': _direct_text(node, 'IPFamily'), 'Position': _direct_text(node, 'Position'),
            'After Rule': _direct_text(after, 'Name') if after is not None else '',
            'Original Source': _members(node, 'OriginalSourceNetworks', 'Network'),
            'Original Destination': _members(node, 'OriginalDestinationNetworks', 'Network'),
            'Original Service': _members(node, 'OriginalServices', 'Service'),
            'Translated Source': _direct_text(node, 'TranslatedSource'),
            'Translated Destination': _direct_text(node, 'TranslatedDestination'),
            'Translated Service': _direct_text(node, 'TranslatedService'),
            'Inbound Interface': _members(node, 'InboundInterfaces', 'Interface'),
            'Outbound Interface': _members(node, 'OutboundInterfaces', 'Interface'),
            'Linked Firewall Rule': linked, 'NAT Method': _direct_text(node, 'NATMethod'),
            'Health Check': _direct_text(node, 'HealthCheck'),
            'Override Interface NAT': _direct_text(node, 'OverrideInterfaceNATPolicy'),
            'Description': _direct_text(node, 'Description')})
    return rows
