"""Execute shipped scripts; PowerShell uses fixture CIM/registry data, never remote hosts."""
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from backend.services.ssm_inventory import validate_inventory

SCRIPTS = Path(__file__).parents[1] / 'backend/services/ssm_scripts'


def test_linux_process_detection_and_json_escaping(tmp_path):
    proc = tmp_path / 'proc'; proc.mkdir()
    applications = tmp_path / 'apps'; applications.mkdir()
    tomcat = applications / 'tomcat'
    tomcat.mkdir(); (tomcat / 'RELEASE-NOTES').write_text('Apache Tomcat Version 9.0.46\n')
    products = [('nginx', 'Tengine version: Tengine/2.3.3 (nginx/1.18.0)', ''),
                ('mysqld', 'mysqld Ver 8.0.46 for Linux', ''),
                ('postgres', 'postgres (PostgreSQL) 16.3', ''),
                ('java', '', f'java -Dcatalina.base={tomcat} org.apache.catalina.startup.Bootstrap')]
    for number, (name, version, command) in enumerate(products, 1):
        exe = applications / name
        exe.write_text('#!/bin/sh\nprintf \'%s\\n\' ' + "'" + version + "'\n")
        exe.chmod(0o700)
        entry = proc / str(number); entry.mkdir()
        (entry / 'comm').write_text(name)
        (entry / 'exe').symlink_to(exe)
        (entry / 'cmdline').write_bytes(command.encode().replace(b' ', b'\0'))
    # Use the shipped logic against fixture /proc; do not alter operational script interfaces.
    script = (SCRIPTS / 'linux.sh').read_text().replace('/proc/[0-9]*', str(proc / '[0-9]*'))
    # Exercise quotes, backslashes and control characters in JSON encoding.
    script = script.replace('host=$(hostname 2>/dev/null)', "host=$(printf 'fixture\\\"\\\\\\\\host\\tname')")
    result = subprocess.run(['sh'], input=script, capture_output=True, text=True, timeout=20, check=True)
    row = validate_inventory(json.loads(result.stdout))
    assert '\t' in row['hostname'] and '"' in row['hostname'] and '\\' in row['hostname']
    assert row['web'][0]['product'] == 'Tengine' and row['web'][0]['version'] == '2.3.3'
    assert row['was'][0]['product'] == 'Tomcat' and row['was'][0]['version'] == '9.0.46'
    assert [(item['product'], item['version']) for item in row['db']] == [('MySQL', '8.0.46'), ('PostgreSQL', '16.3')]


PWSH = os.environ.get('SMU_TEST_PWSH') or shutil.which('pwsh')


@pytest.mark.skipif(not PWSH, reason='Optional PowerShell script execution requires pwsh')
@pytest.mark.parametrize('products', [False, True])
def test_windows_script_single_json_with_mock_cim(tmp_path, products):
    wrapper = tmp_path / 'inventory-fixture.ps1'
    wrapper.write_text(r'''
function Get-CimInstance {
    [CmdletBinding()]param([string]$ClassName)
    switch ($ClassName) {
        'Win32_OperatingSystem' { [pscustomobject]@{ Caption='Example Windows Server'; Version='10.0.fixture'; InstallDate=[datetime]'2025-01-02T03:04:05' } }
        'Win32_Process' {
            if ($env:SMU_FIXTURE_PRODUCTS -eq 'yes') {
                [pscustomobject]@{ Name='mysqld.exe'; ExecutablePath='C:\fixture\mysqld.exe'; CommandLine='' }
                [pscustomobject]@{ Name='tomcat9.exe'; ExecutablePath='C:\fixture\tomcat\bin\tomcat9.exe'; CommandLine='java -Dcatalina.base="C:\fixture\tomcat"' }
            }
        }
        'Win32_Service' { [pscustomobject]@{ Name='W3SVC'; State='Running' } }
    }
}
function Get-ItemProperty {
    [CmdletBinding()]param([string]$Path)
    if ($env:SMU_FIXTURE_PRODUCTS -eq 'yes') { [pscustomobject]@{ MajorVersion=10; MinorVersion=0 } }
}
$env:windir = 'C:\Windows'
& $args[0]
''')
    env = {**os.environ, 'SMU_FIXTURE_PRODUCTS': 'yes' if products else 'no',
           'XDG_CACHE_HOME': str(tmp_path / 'cache'), 'XDG_CONFIG_HOME': str(tmp_path / 'config'),
           'XDG_DATA_HOME': str(tmp_path / 'data')}
    result = subprocess.run([PWSH, '-NoProfile', '-NonInteractive', '-File', str(wrapper), str(SCRIPTS / 'windows.ps1')],
                            env=env, capture_output=True, text=True, check=True, timeout=20)
    assert not result.stdout.startswith('\ufeff')
    data = json.loads(result.stdout)
    row = validate_inventory(data)
    assert row['kernel'] == '10.0.fixture' and row['os_install_date'] == '2025-01-02 03:04:05'
    if products:
        assert row['web'][0]['product'] == 'IIS' and row['web'][0]['version'] == '10.0'
        assert row['db'][0]['product'] == 'MySQL'
        assert row['was'][0]['product'] == 'Tomcat'
    else: assert row['web'] == row['was'] == row['db'] == []
