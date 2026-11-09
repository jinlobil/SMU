"""Local-file EOS lookup. No network, inferred dates, or Inventory mutation."""
from datetime import date
from pathlib import Path
import re


def _key(product, version):
    return f'{product.strip()}|{" ".join(version.split())}'.casefold()


def os_eos_keys(value):
    if not isinstance(value, str): return []
    value = ' '.join(value.strip().split())
    patterns = [
        (r'^(?:Microsoft\s+)?(?:Windows(?:\s+Server)?|Win)\s+(20\d{2})\b', 'Windows Server'),
        (r'^Amazon\s+Linux\s+(\d+)\b', 'Amazon Linux'),
        (r'^CentOS(?:\s+Linux)?\s+(\d+)\b', 'CentOS Linux'),
        (r'^(?:Synology\s+)?DSM\s+(\d+\.\d+)\b', 'Synology DSM'),
        (r'^Ubuntu\s+(\d+\.\d+)\b', 'Ubuntu'),
        (r'^(?:RHEL|redhat|Red\s+Hat(?:\s+Enterprise\s+Linux)?)(?:\s+Server)?[\s-]+(?:release\s+)?(\d+)\b', 'RHEL'),
    ]
    suse = re.match(r'^(?:SLES|SUSE(?:\s+Linux\s+Enterprise\s+Server)?)(?:\s+for\s+SAP(?:\s+Applications)?)?\s*(\d+)\b(?:\s+(?:SP|Service\s+Pack)\s*(\d+)\b)?', value, re.I)
    if suse:
        major, sp = suse.groups()
        return ([f'SLES|{major} SP{sp}'] if sp else []) + [f'SLES|{major}']
    for pattern, product in patterns:
        match = re.match(pattern, value, re.I)
        if match: return [f'{product}|{match.group(1)}']
    return []


def db_eos_keys(product, version):
    if not isinstance(product, str) or not isinstance(version, str): return []
    aliases = {'sybase': 'SAP ASE', 'sybase ase': 'SAP ASE', 'ase': 'SAP ASE', 'sap ase': 'SAP ASE',
               'hana': 'SAP HANA', 'sap hana': 'SAP HANA', 'sql server': 'MSSQL',
               'microsoft sql server': 'MSSQL', 'mssql': 'MSSQL', 'mysql': 'MySQL',
               'mariadb': 'MariaDB', 'oracle': 'Oracle', 'postgresql': 'PostgreSQL', 'postgres': 'PostgreSQL'}
    name = aliases.get(' '.join(product.casefold().split()))
    version = version.strip()
    if name == 'SAP HANA':
        match = re.match(r'^(\d+)\.(\d+)\s+SP\s*(\d+)\b', version, re.I)
        if match:
            major, minor, sp = map(int, match.groups())
            return [f'{name}|{major}.{minor} SP{sp}', f'{name}|{major}.{minor}']
        return []
    match = re.match(r'^(\d+)(?:\.(\d+))?(?:\.|\b)', version)
    if not name or not match: return []
    major, minor = match.groups()
    if name == 'MSSQL' or (name == 'PostgreSQL' and int(major) >= 10):
        return [f'{name}|{major}']
    return [f'{name}|{major}.{minor}'] if minor is not None else []


class EosCatalog:
    def __init__(self, env: Path):
        # Reload once per export so operator file changes take effect without restart.
        self.os_dates = self._load(env / 'os_eos')
        self.db_dates = self._load(env / 'db_eos')

    @staticmethod
    def _load(path):
        result = {}
        try: lines = path.read_text(encoding='utf-8-sig').splitlines()
        except (OSError, UnicodeError): return result
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'): continue
            key, sep, value = line.partition('=')
            if not sep or key.count('|') != 1 or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', value.strip()): continue
            product, version = key.split('|')
            if not product.strip() or not version.strip(): continue
            try: date.fromisoformat(value.strip())
            except ValueError: continue
            result[_key(product, version)] = value.strip()
        return result

    @staticmethod
    def _lookup(table, candidates):
        for candidate in candidates:
            product, version = candidate.split('|', 1)
            if _key(product, version) in table: return table[_key(product, version)]
        return '-'

    def os(self, value):
        return self._lookup(self.os_dates, os_eos_keys(value))

    def db(self, product, version):
        return self._lookup(self.db_dates, db_eos_keys(product, version))
