from pathlib import Path

import pytest

from backend.services.eos import EosCatalog, os_eos_keys, db_eos_keys


@pytest.fixture
def eos(tmp_path):
    (tmp_path / 'os_eos').write_text('''Amazon Linux|2023=2029-06-30
CentOS Linux|7=2024-06-30
Synology DSM|6.2=2024-10-01
Windows Server|2016=2027-01-12
Windows Server|2019=2029-01-09
Windows Server|2022=2031-10-14
Windows Server|2025=2034-11-14
SLES|12 SP2=2018-03-31
SLES|12 SP3=2019-06-30
SLES|12 SP4=2020-06-30
SLES|12=2024-10-31
Ubuntu|22.04=2027-05-31
Ubuntu|24.04=2029-05-31
RHEL|4=2012-02-29
''')
    (tmp_path / 'db_eos').write_text('''SAP ASE|16.0=2025-12-31
SAP HANA|2.0 SP30=2020-06-30
SAP HANA|2.0 SP48=2021-06-30
SAP HANA|2.0 SP59=2025-06-30
MSSQL|11=2022-07-12
MSSQL|13=2026-07-14
MSSQL|14=2027-10-12
MSSQL|15=2030-01-08
MariaDB|10.0=2019-03-31
MariaDB|10.2=2022-05-23
MariaDB|10.11=2028-02-16
MySQL|5.1=2013-12-31
MySQL|5.7=2023-10-31
MySQL|8.0=2026-04-30
Oracle|10.2=2013-07-31
Oracle|12.1=2022-07-31
Oracle|12.2=2022-03-31
PostgreSQL|9.6=2021-11-11
PostgreSQL|13=2025-11-13
''')
    return EosCatalog(tmp_path)


@pytest.mark.parametrize('value,key', [
    ('Amazon Linux 2023.7.20250512', 'Amazon Linux|2023'),
    ('Amazon Linux 2023.9.20251110', 'Amazon Linux|2023'),
    ('CentOS Linux 7 (Core)', 'CentOS Linux|7'), ('DSM 6.2', 'Synology DSM|6.2'),
    ('Microsoft Windows Server 2016 Datacenter', 'Windows Server|2016'),
    ('Microsoft Windows Server 2019 Datacenter', 'Windows Server|2019'),
    ('Microsoft Windows Server 2022 Datacenter', 'Windows Server|2022'),
    ('Microsoft Windows Server 2025 Datacenter', 'Windows Server|2025'),
    ('Win 2016 D.E', 'Windows Server|2016'), ('Windows 2016 D.E', 'Windows Server|2016'),
    ('SLES for SAP12 SP2', 'SLES|12 SP2'), ('SLES for SAP12 SP3', 'SLES|12 SP3'),
    ('SLES for SAP12 SP4', 'SLES|12 SP4'), ('SUSE Linux Enterprise Server 12 SP3', 'SLES|12 SP3'),
    ('SUSE Linux Enterprise Server 12 SP4', 'SLES|12 SP4'),
    ('SUSE Linux Enterprise Server for SAP Applications 12 SP2', 'SLES|12 SP2'),
    ('SUSE 12', 'SLES|12'), ('Ubuntu 22.04.5 LTS', 'Ubuntu|22.04'),
    ('Ubuntu 24.04.1 LTS', 'Ubuntu|24.04'), ('Ubuntu 24.04.4 LTS', 'Ubuntu|24.04'),
    ('Ubuntu 24.04.5 LTS', 'Ubuntu|24.04'), ('redhat-4', 'RHEL|4'),
])
def test_os_aliases_match_local_canonical_keys(eos, value, key):
    assert os_eos_keys(value)[0] == key
    assert eos.os(value) == eos.os_dates[key.casefold()]


@pytest.mark.parametrize('product,version,key,expected', [
    ('MySQL', '5.7.16', 'MySQL|5.7', '2023-10-31'),
    ('MySQL', '8.0.46', 'MySQL|8.0', '2026-04-30'),
    ('Oracle', '12.2.0.1.0', 'Oracle|12.2', '2022-03-31'),
    ('Oracle', '12.1.0', 'Oracle|12.1', '2022-07-31'),
    ('MariaDB', '10.2.19', 'MariaDB|10.2', '2022-05-23'),
    ('MSSQL', '13.0.1601.5', 'MSSQL|13', '2026-07-14'),
    ('Microsoft SQL Server', '15.0.1234', 'MSSQL|15', '2030-01-08'),
    ('PostgreSQL', '9.6.24', 'PostgreSQL|9.6', '2021-11-11'),
    ('PostgreSQL', '13.8', 'PostgreSQL|13', '2025-11-13'),
    ('Sybase', '16.0.03.03', 'SAP ASE|16.0', '2025-12-31'),
    ('SAP HANA', '2.0 SP30 (2.00.030.00.1522209842)', 'SAP HANA|2.0 SP30', '2020-06-30'),
    ('SAP HANA', '2.0 SP48 (2.00.048.02.1601540280)', 'SAP HANA|2.0 SP48', '2021-06-30'),
    ('SAP HANA', '2.0 SP59 (2.00.059.00.fixture)', 'SAP HANA|2.0 SP59', '2025-06-30'),
])
def test_db_product_version_canonicalization(eos, product, version, key, expected):
    assert db_eos_keys(product, version)[0] == key
    assert eos.db(product, version) == expected


def test_specific_sles_key_precedes_major_fallback(eos):
    assert eos.os('SLES for SAP12 SP3') == '2019-06-30'
    assert eos.os('SLES for SAP12 SP9') == '2024-10-31'


@pytest.mark.parametrize('value', [None, '', 'unknown', 'Example OS 2023', 'Ubuntu 20.04 LTS'])
def test_unknown_os_has_no_inferred_date(eos, value):
    assert eos.os(value) == '-'


@pytest.mark.parametrize('product,version', [('MySQL', None), ('Oracle', 'unknown'),
    ('Example DB', '1.2.3'), ('SAP HANA', '2.0 SP49 (2.00.049.00)'), ('PostgreSQL', '15.2')])
def test_missing_db_keys_preserve_unknown(eos, product, version):
    assert eos.db(product, version) == '-'


def test_missing_invalid_and_bom_catalog_entries_are_safe(tmp_path):
    assert EosCatalog(tmp_path).os('Ubuntu 24.04') == '-'
    (tmp_path / 'os_eos').write_text('\ufeff# local operator data\nUbuntu|24.04=2029-05-31\nUbuntu|22.04=2027-02-30\ninvalid\n', encoding='utf-8')
    catalog = EosCatalog(tmp_path)
    assert catalog.os('Ubuntu 24.04.4 LTS') == '2029-05-31'
    assert catalog.os('Ubuntu 22.04 LTS') == '-'
