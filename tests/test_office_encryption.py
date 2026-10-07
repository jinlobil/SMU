from io import BytesIO
import json
import logging
from pathlib import Path
from zipfile import ZipFile, is_zipfile
from xml.etree import ElementTree as ET

import msoffcrypto
import pytest

from backend.services.office_encryption import encrypted_xlsx_export, ExportEncryptionError
from backend.services.spreadsheet import write_xlsx
from system_monitor.laborer import LaborerAgent
from test_aws_export_inventory import prepare
from test_firewall_rule_export import XML, env
from test_timeline_export import _database

PASSWORD = 'Fixture-only-암호 42'


def run_job(agent, monkeypatch, job_type, payload):
    agent.stop.clear()
    job = agent.submit(job_type, payload)
    update = agent._update
    def finish(job_id, **fields):
        update(job_id, **fields)
        if fields.get('status') in {'completed', 'failed'}: agent.stop.set()
    monkeypatch.setattr(agent, '_update', finish)
    agent.worker_loop()
    return agent.get(job['id'])


def workbook_entries(data):
    with ZipFile(BytesIO(data)) as archive:
        assert archive.testzip() is None
        entries = {name: archive.read(name) for name in archive.namelist()}
        for name, content in entries.items():
            if name.endswith(('.xml', '.rels')): ET.fromstring(content)
        return entries


def decrypt(path, password=PASSWORD):
    with Path(path).open('rb') as file:
        office = msoffcrypto.OfficeFile(file)
        assert office.is_encrypted() and office.type == 'agile'
        xml = ET.fromstring(office.file.openstream('EncryptionInfo').read()[8:])
        key = xml.find('{http://schemas.microsoft.com/office/2006/encryption}keyData')
        assert key.attrib['cipherAlgorithm'] == 'AES' and key.attrib['keyBits'] == '256'
        assert key.attrib['hashAlgorithm'] == 'SHA512'
        office.load_key(password=password, verify_password=True)
        output = BytesIO(); office.decrypt(output, verify_integrity=True)
        return output.getvalue()


KINDS = [('export', {'kind': kind, 'start': '2026-01-01', 'end': '2026-01-02'}) for kind in ['detections', 'xdr', 'firewall', 'inbound', 'outbound', 'dlp']]
KINDS += [('endpoint_export', {}), ('aws_export', {'kind': 'aws_ec2'}), ('aws_export', {'kind': 'aws_sg'}),
          ('firewall_rules_export', {'firewalls': ['Cloud']}), ('timeline_export', {'user': 'fixture', 'keyword': '', 'sources': ['Detection']})]


@pytest.mark.parametrize('job_type,payload', KINDS)
def test_every_export_encrypted_roundtrip_preserves_all_workbook_entries(tmp_path, monkeypatch, caplog, job_type, payload):
    from backend.services.firewall import FirewallClient
    import system_monitor.laborer as laborer
    prepare(tmp_path); env(tmp_path, ['Cloud']); _database(tmp_path, [])
    monkeypatch.setattr(FirewallClient, 'get', lambda _self, entity: XML[entity])
    for cls, methods in [(laborer.DetectionService, ['_events']), (laborer.EmailSecurityService, ['_collect_xdr', '_collect_inbound']),
                         (laborer.FirewallDetectionService, ['_collect']), (laborer.TransferService, ['_collect_outbound', '_collect_dlp'])]:
        for method in methods: monkeypatch.setattr(cls, method, lambda *_: ([('fixture', {}, {'time': 'fixture', 'action': 'Allow'})], {}))
    agent = LaborerAgent(tmp_path)
    plain = agent._xlsx_job(job_type, payload, lambda _: None)
    plain_path = Path(plain['path']); baseline = workbook_entries(plain_path.read_bytes()); plain_path.unlink()
    with caplog.at_level(logging.DEBUG):
        job = run_job(agent, monkeypatch, job_type, {**payload, 'encrypt': True, 'password': PASSWORD})
    assert job['status'] == 'completed', job['error']
    final = Path(job['result']['path'])
    assert final.suffix == '.xlsx' and not is_zipfile(final)
    assert final.read_bytes()[:8] == bytes.fromhex('d0cf11e0a1b11ae1')
    assert workbook_entries(decrypt(final)) == baseline
    with pytest.raises(msoffcrypto.exceptions.InvalidKeyError): decrypt(final, 'incorrect')
    assert list((tmp_path / 'exports').iterdir()) == [final]
    assert not list((tmp_path / 'runtime/laborer/xlsx-temp').iterdir())
    assert agent._export_passwords == {}
    assert PASSWORD not in caplog.text and PASSWORD not in json.dumps(job, ensure_ascii=False)
    assert PASSWORD.encode() not in agent.database.read_bytes()
    with agent._connect() as db:
        assert 'password' not in db.execute('SELECT payload FROM jobs').fetchone()[0].casefold()


@pytest.mark.parametrize('failure,code', [('build', 'EXPORT_GENERATION_FAILED'), ('encrypt', 'OFFICE_ENCRYPTION_FAILED'),
    ('missing_library', 'ENCRYPTION_LIBRARY_MISSING'), ('cleanup', 'EXPORT_TEMP_FAILED')])
def test_failures_never_publish_plaintext_or_persist_password(tmp_path, monkeypatch, caplog, failure, code):
    import backend.services.office_encryption as helper
    agent = LaborerAgent(tmp_path)
    def build(*_):
        path = tmp_path / 'exports/test.xlsx'; write_xlsx(path, [{'a': 'private fixture'}])
        assert not path.exists()
        if failure == 'build': raise RuntimeError(PASSWORD)
        return {'path': str(path), 'filename': path.name}
    monkeypatch.setattr(agent, '_xlsx_job', build)
    if failure == 'encrypt':
        from msoffcrypto.format.ooxml import OOXMLFile
        monkeypatch.setattr(OOXMLFile, 'encrypt', lambda *_: (_ for _ in ()).throw(RuntimeError(PASSWORD)))
    elif failure == 'missing_library':
        import builtins
        actual = builtins.__import__
        def missing(name, *args, **kwargs):
            if name == 'msoffcrypto': raise ImportError(PASSWORD)
            return actual(name, *args, **kwargs)
        monkeypatch.setattr(builtins, '__import__', missing)
    elif failure == 'cleanup':
        actual = helper.tempfile.TemporaryDirectory.__exit__
        def cleanup(*args):
            actual(*args)
            raise OSError(PASSWORD)
        monkeypatch.setattr(helper.tempfile.TemporaryDirectory, '__exit__', cleanup)
    with caplog.at_level(logging.DEBUG):
        job = run_job(agent, monkeypatch, 'endpoint_export', {'encrypt': True, 'password': PASSWORD})
    assert job['status'] == 'failed' and job['result'] is None
    assert job['error']['code'] == code and 'traceback' not in job['error']
    assert not list((tmp_path / 'exports').glob('*'))
    assert not list((tmp_path / 'runtime/laborer/xlsx-temp').glob('xlsx-*'))
    assert agent._export_passwords == {}
    assert PASSWORD not in caplog.text and PASSWORD not in json.dumps(job, ensure_ascii=False)
    assert PASSWORD.encode() not in agent.database.read_bytes()


def test_restart_fails_secret_jobs_recovers_plain_jobs_and_cleans_staging(tmp_path):
    agent = LaborerAgent(tmp_path)
    encrypted = agent.submit('endpoint_export', {'encrypt': True, 'password': PASSWORD})
    plain = agent.submit('endpoint_export', {})
    agent._update(encrypted['id'], status='running'); agent._update(plain['id'], status='running')
    leftover = tmp_path / 'runtime/laborer/xlsx-temp/xlsx-interrupted'; leftover.mkdir(parents=True)
    (leftover / '0.xlsx').write_bytes(b'private fixture')
    restarted = LaborerAgent(tmp_path)
    assert restarted.get(encrypted['id'])['status'] == 'failed'
    assert restarted.get(plain['id'])['status'] == 'queued'
    assert not leftover.exists() and restarted._export_passwords == {}


@pytest.mark.parametrize('password', [None, '', '   ', 123])
def test_empty_password_is_rejected_before_db_insert(tmp_path, password):
    agent = LaborerAgent(tmp_path)
    with pytest.raises(ValueError): agent.submit('endpoint_export', {'encrypt': True, 'password': password})
    with agent._connect() as db: assert db.execute('SELECT count(*) FROM jobs').fetchone()[0] == 0


def test_off_ignores_password_and_keeps_zip_output(tmp_path, monkeypatch):
    agent = LaborerAgent(tmp_path)
    job = run_job(agent, monkeypatch, 'endpoint_export', {'encrypt': False, 'password': PASSWORD})
    assert job['status'] == 'completed'
    assert is_zipfile(job['result']['path'])
    assert not job['result'].get('encrypted')
    assert agent._export_passwords == {} and PASSWORD.encode() not in agent.database.read_bytes()


def test_library_returning_plain_zip_is_rejected(tmp_path, monkeypatch):
    from msoffcrypto.format.ooxml import OOXMLFile
    agent = LaborerAgent(tmp_path)
    monkeypatch.setattr(OOXMLFile, 'encrypt', lambda self, _password, outfile: (self.file.seek(0), outfile.write(self.file.read())))
    job = run_job(agent, monkeypatch, 'endpoint_export', {'encrypt': True, 'password': PASSWORD})
    assert job['status'] == 'failed' and job['error']['code'] == 'OFFICE_ENCRYPTION_FAILED'
    assert not list((tmp_path / 'exports').iterdir())
    assert not list((tmp_path / 'runtime/laborer/xlsx-temp').iterdir())
