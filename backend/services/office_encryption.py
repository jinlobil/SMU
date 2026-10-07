"""Office Agile file encryption at the shared Laborer XLSX finalization boundary."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from io import BytesIO
from pathlib import Path
import os
import shutil
import tempfile
import uuid
from zipfile import ZipFile


XLSX_JOB_TYPES = frozenset({'export', 'firewall_rules_export', 'timeline_export', 'aws_export', 'endpoint_export'})
_STAGING = ContextVar('xlsx_output_staging', default=None)


class ExportEncryptionError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def encryption_options(payload: dict) -> dict:
    enabled = payload.get('encrypt', False)
    if not isinstance(enabled, bool):
        raise ValueError('파일 암호화 옵션은 true/false여야 합니다.')
    if not enabled:
        return {}
    password = payload.get('password')
    if not isinstance(password, str) or not password.strip():
        raise ValueError('파일 암호화 비밀번호를 입력하세요.')
    return {'encrypt': True, 'password': password}


def staged_output_path(path: Path) -> Path:
    staging = _STAGING.get()
    if staging is None:
        return path
    directory, outputs = staging
    key = path.resolve()
    if key not in outputs:
        outputs[key] = directory / f'{len(outputs)}.xlsx'
    return outputs[key]


def require_office_library():
    try:
        import msoffcrypto
        return msoffcrypto
    except ImportError:
        raise ExportEncryptionError('ENCRYPTION_LIBRARY_MISSING', 'Office 암호화 라이브러리가 없습니다. setup_local.bat 또는 backend/requirements.txt로 의존성을 설치하세요.') from None


def cleanup_stale_exports(root: Path):
    directory = root / 'runtime/laborer/xlsx-temp'
    if directory.exists():
        for path in directory.glob('xlsx-*'):
            if path.is_dir():
                shutil.rmtree(path)


def encrypted_xlsx_export(root: Path, password: str, build, progress) -> dict:
    library = require_office_library()
    directory = root / 'runtime/laborer/xlsx-temp'
    final_path = None
    try:
        directory.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix='xlsx-', dir=directory)
    except OSError:
        raise ExportEncryptionError('EXPORT_TEMP_FAILED', '암호화 임시파일 준비에 실패했습니다.') from None
    try:
        with temporary as temp:
            outputs = {}
            token = _STAGING.set((Path(temp), outputs))
            try:
                try:
                    result = build()
                except OSError:
                    raise ExportEncryptionError('EXPORT_GENERATION_FAILED', 'XLSX 생성에 실패했습니다. 파일 저장 경로와 권한을 확인하세요.') from None
                except Exception:
                    raise ExportEncryptionError('EXPORT_GENERATION_FAILED', 'XLSX 생성에 실패했습니다.') from None
            finally:
                _STAGING.reset(token)
            original = Path(result['path']).resolve()
            plain = outputs.get(original)
            if not plain or original.parent != (root / 'exports').resolve() or original.suffix.lower() != '.xlsx' or not plain.is_file():
                raise ExportEncryptionError('EXPORT_GENERATION_FAILED', '공통 XLSX Writer에서 생성한 파일을 확인할 수 없습니다.')
            # msoffcrypto 6.0 pads small EncryptedPackage OLE streams to 4096
            # bytes without including that padding in its HMAC. A legal ZIP
            # comment grows tiny OOXML packages past the cutoff without changing
            # any workbook entry; keep integrity verification enabled.
            size = plain.stat().st_size
            if size < 4096:
                with ZipFile(plain, 'a') as archive:
                    archive.comment += b' ' * (4096 - size)
            encrypted = Path(temp) / 'encrypted.xlsx'
            progress('Office 파일 암호화 및 검증 중')
            try:
                with plain.open('rb') as source, encrypted.open('wb') as target:
                    library.OfficeFile(source).encrypt(password, target)
                # Verify Agile password verifier + package integrity and exact bytes.
                with encrypted.open('rb') as source:
                    office = library.OfficeFile(source)
                    if not office.is_encrypted(): raise ValueError()
                    office.load_key(password=password, verify_password=True)
                    decoded = BytesIO()
                    office.decrypt(decoded, verify_integrity=True)
                if decoded.getvalue() != plain.read_bytes(): raise ValueError()
                decoded.close()
            except Exception:
                raise ExportEncryptionError('OFFICE_ENCRYPTION_FAILED', 'Office 파일 암호화 또는 암호화 검증에 실패했습니다.') from None
            plain.unlink()
            final_path = original.with_name(f'{original.stem}_{uuid.uuid4().hex[:12]}.xlsx')
            os.replace(encrypted, final_path)
            return {**result, 'path': str(final_path), 'filename': final_path.name, 'encrypted': True}
    except ExportEncryptionError:
        if final_path: final_path.unlink(missing_ok=True)
        raise
    except OSError:
        if final_path: final_path.unlink(missing_ok=True)
        raise ExportEncryptionError('EXPORT_TEMP_FAILED', '암호화 임시파일 정리 또는 최종파일 저장에 실패했습니다.') from None
