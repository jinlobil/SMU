"""Compatibility parsing for Sophos AD department display names."""
import re

_NAMED = re.compile(r'(?P<name>.+?)\s*\(\s*(?P<code>[0-9]+)\s*\)(?:\s*\(LOCKNLOCK\))?', re.IGNORECASE)


def parse_department_display_name(value, department_names=None):
    """Return the unchanged department schema, or None for a non-department group."""
    if not isinstance(value, (str, int)) or isinstance(value, bool): return None
    text = str(value).strip()
    if re.fullmatch(r'[0-9]+', text):
        return {'deptCode': text, 'deptName': (department_names or {}).get(text) or text}
    match = _NAMED.fullmatch(text)
    if match and match['name'].strip():
        return {'deptCode': match['code'], 'deptName': match['name'].strip()}
    return None


def department_names_with_directory(department_names, users):
    """Overlay explicit new AD names in memory; never rewrite the legacy map/cache."""
    names = dict(department_names)
    for user in users:
        source = user.get('source') if isinstance(user.get('source'), dict) else {}
        if source.get('type') not in (None, '', 'activeDirectory'): continue
        groups = user.get('groups') if isinstance(user.get('groups'), dict) else {}
        items = groups.get('items', [])
        for group in items if isinstance(items, list) else []:
            if not isinstance(group, dict): continue
            value = group.get('displayName')
            parsed = parse_department_display_name(value)
            if parsed and str(value).strip() != parsed['deptCode']:
                names[parsed['deptCode']] = parsed['deptName']
    return names
