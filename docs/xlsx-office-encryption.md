# 선택적 XLSX Office 파일 암호화

## 구조와 적용 위치

기존 흐름을 유지한다:

Export Management/Timeline → FastAPI Export Job → Watchdog → Laborer → XLSX Service
→ 공통 XLSX Writer → exports → 기존 Download API.

암호화 OFF는 기존 Job/Writer/파일명/ZIP XLSX 동작을 사용한다.
암호화 ON은 Laborer의 공통 `encrypted_xlsx_export()`에서 파일 레벨로 적용한다.
Export Service마다 암호화 코드를 추가하지 않는다. ContextVar로 공통 Writer의
출력을 해당 작업의 private staging으로 지정한다. Writer 반환값과 Workbook
Sheet/Column 데이터 모델은 유지한다.

적용 대상 11종: Detection, Email/XDR, Firewall Detection, Inbound Mail,
Outbound Mail, DLP, Timeline, Firewall Rule, Endpoint, AWS EC2, AWS SG.
기존 동기식 GET Export는 일반 XLSX 호환성을 유지한다. 선택적 암호화 요청은
기존 `/api/jobs/export*` Job API를 사용한다. 새 XLSX Job도 `XLSX_JOB_TYPES` 등록과
기존 dispatcher에서 공통 Writer를 사용하면 동일 암호화 경계를 재사용할 수 있다.

## Office 표준과 라이브러리

`msoffcrypto-tool` 6.0.0에서 실제 encryption/decryption을 검증했다.
Dependency는 `backend/requirements.txt`의 `msoffcrypto-tool>=6.0,<7.0`이다.
`setup_local.bat`의 기존 requirements 설치를 재사용하고 `start_local.bat`의
모듈 검사에 msoffcrypto를 추가했다.

형식은 MS-OFFCRYPTO / ECMA-376 Agile, AES-256-CBC, SHA-512, password verifier와
package HMAC이다. 파일은 `.xlsx` 확장자를 유지하는 OLE Compound File이며,
`EncryptionInfo`와 `EncryptedPackage` stream을 포함한다. 일반 ZIP parser로
Workbook을 직접 읽을 수 없다. ZIP 암호·Sheet Protection·Workbook 편집 보호가 아니다.

검증 중 msoffcrypto 6.0.0이 4096 byte보다 작은 EncryptedPackage OLE stream을
padding하면서 HMAC에 padding을 포함하지 않는 문제를 발견했다. 작은 원본 ZIP에는
유효한 ZIP comment를 추가해 크기를 최소 4096 byte로 맞춘다. 모든 Workbook entry는
그대로 보존하며 무결성 검증을 끄지 않는다. 빈 Endpoint 같은 작은 Export도 검증했다.

## UI와 비밀번호 전달

Export Management의 XLSX 공통 옵션과 Timeline Export에 동일 UI/hook을 적용한다.
기본은 OFF이며 ON이면 password/confirmation 두 입력이 표시된다. 빈 값·공백만 있는
값·불일치는 Job 요청 전에 거부한다. 복잡도 정책은 추가하지 않는다.
OFF에는 비밀번호를 전송하지 않고 confirmation은 서버로 전송하지 않는다.
PDF에는 이 옵션을 적용하지 않는다. 요청 수락 또는 실패 후 입력값을 지우며,
localStorage에는 기존 Job ID/type만 보관한다.

ON 요청의 `encrypt: true`, `password`는 JSON POST body로 FastAPI → Watchdog
→ Laborer에 전달한다. URL query에는 넣지 않는다. OFF는 기존 query transport를
유지한다. Backend/Laborer도 빈 비밀번호를 검증한다.

Laborer는 비밀번호를 Job ID별 메모리 dictionary에만 저장한다. DB payload에서는
password/confirmation 필드를 제거하고 public Job/결과/오류/history에는 포함하지 않는다.
worker 시작 시 메모리 값을 가져오고 완료/실패 finally에서 제거한다. 로그는 Job ID와
고정 오류 code만 기록하며 encrypted Job에는 원문 exception/traceback을 노출하지 않는다.
재시작 시 queued/running encrypted Job은 비밀번호를 복구하지 않고 FAIL 처리한다.
암호화 OFF Job의 기존 복구 동작은 유지한다.

## 임시 파일과 최종 배치

1. `runtime/laborer/xlsx-temp/xlsx-*` private TemporaryDirectory에 평문 XLSX 생성.
2. 같은 private directory에 Office encrypted 파일 생성.
3. password verifier + HMAC 검증 후 복호화하고 평문 package와 byte equality 확인.
4. 평문 삭제.
5. 암호화된 파일을 유일한 이름의 `.xlsx`로 `exports`에 atomic rename.
6. TemporaryDirectory 정리 완료 후 Job 완료와 최종 filename 반환.

예외/실패는 finally/context cleanup으로 임시 파일을 삭제한다. 강제 프로세스 종료로
남은 staging directory는 다음 Laborer 시작 시 정리한다. cleanup 실패는 Job FAIL로
처리하고 최종 결과물을 반환하지 않는다. 삭제 권한/파일 잠금으로 정리가 불가능해도
평문은 다운로드 경로 밖에 있으며 운영자가 파일 권한/잠금을 해결해야 한다.
암호화 실패를 일반 XLSX로 대체하지 않는다. Writer staging ContextVar는 반드시 reset한다.

## 오류 구분

- API: `INVALID_EXPORT_ENCRYPTION` (필수 비밀번호 또는 옵션 오류).
- UI: 필수 입력/비밀번호 불일치 (Job 미생성).
- `EXPORT_GENERATION_FAILED`: XLSX 생성 오류.
- `OFFICE_ENCRYPTION_FAILED`: Office 암호화/검증 오류.
- `ENCRYPTION_LIBRARY_MISSING`: 의존성 누락, 설치 안내 포함.
- `EXPORT_TEMP_FAILED`: 임시파일/최종 저장/정리 오류.
- `EXPORT_PASSWORD_LOST`: 재시작으로 메모리 비밀번호 소실, 다시 요청 필요.

## 검증 결과

- 11종의 실제 Laborer Export 암호화, 올바른/잘못된 비밀번호 검증.
- 복호화 후 ZIP CRC, workbook/worksheet/relationships XML 파싱.
- 암호화 전후 모든 ZIP entry bytes 비교: Sheet 수/이름, Navy Header, Border,
  Freeze, Autofilter, Cell 색상, Timeline 7 Sheet, AWS SG Mapping merge 모두 보존.
- 잘못된 암호/일반 ZIP을 반환하는 가짜 encryption 결과 거부.
- 생성/암호화/의존성/cleanup 오류: FAIL, 평문 미노출, 임시파일 정리.
- DB bytes/payload, public Job/history, 로그에 비밀번호 없음.
- 실제 HTTP JSON 전달: WatchdogManager → Watchdog → Laborer.
- 기존 Download API에서 encrypted bytes 반환, private staging 파일 404.
- 재시작 시 encrypted Job 실패/일반 Job 복구 및 잔여 staging 정리.
- Chromium UI 검증 **4 passed**: ON/OFF, 필수·불일치, PDF 제외,
  password-only 전송, localStorage 미저장, 입력값 정리, Timeline 공통 옵션.
- 전체 Python 검사(브라우저 제외) **604 passed**, 기존 실패 2개:
  `ScheduledIndex.mode` 누락 및 Timeline search_all 150개 기대 대비 100개 반환.
- 프런트엔드 typecheck/build 통과.

Microsoft Excel GUI는 이 Linux 환경에서 실행하지 못했다. 실제 Excel의 암호 입력창은
미검증이며, Office Agile descriptor/암호 verifier/HMAC 및 decrypt round-trip을 검증했다.
Windows에서 파일을 열어 ‘파일을 열기 위한 암호’ 창과 정상 Workbook 표시를 확인하는
수동 GUI 검증이 남아 있다. Library API 존재만으로 호환성 검증을 대신하지 않았다.

## 변경 파일

- `backend/services/office_encryption.py`: 공통 staging/encryption/validation/cleanup.
- `backend/services/spreadsheet.py`: 공통 Writer staging 연결.
- `backend/app.py`: 모든 XLSX Job API 옵션 검증/전달.
- `backend/services/watchdog_client.py`, `system_monitor/watchdog.py`: JSON body 전달.
- `system_monitor/laborer.py`: 메모리 전용 비밀번호, 공통 dispatcher, 재시작/실패 처리.
- `frontend/src/components/ExportEncryptionOptions.tsx`: 공통 옵션/검증 hook.
- `frontend/src/pages/ExportManagementPage.tsx`, `frontend/src/pages/TimelinePage.tsx`:
  옵션 연결, 요청/입력값 정리.
- `frontend/src/styles.css`: 기존 Theme 변수로 옵션 입력 스타일 적용.
- `backend/requirements.txt`, `start_local.bat`: 의존성 추가/검사.
- `tests/test_office_encryption.py`, `tests/test_export_encryption_transport.py`,
  `tests/test_export_encryption_browser.py`: 암호화/보안/실제 전달/UI 검증.
- 기존 구조 기대값 갱신: `tests/test_aws_frontend.py`, `tests/test_endpoint_ip_export.py`,
  `tests/test_firewall_rule_export_frontend.py`, `tests/test_timeline_export.py`.
- `docs/xlsx-office-encryption.md`: 완료 보고 및 제약.
