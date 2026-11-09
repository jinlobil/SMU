# 로컬 EOS 매핑 및 HANA parser 진단

기준 main: e3b9a3d (PR #336 merge). 운영 AWS 접근/Document 변경 없이 작업했다.

## HANA 원인 확인 범위

운영에서 제공된 세 Cache 레코드는 status=failed/error=invalid_product_record였다.
따라서 SSM 명령 Success/ResponseCode=0과 SMU parser 성공은 달랐고,
last_success_at 및 success/stale 조건을 만족하지 못해 Excel의 SSM 필드가 '-'로 남았다.

현재 invalid_product_record를 내는 조건은 정확히 두 가지다:
- 의미 있는 제품 줄의 pipe 분리 필드가 4개가 아닌 경우
- 4개여도 product가 정규화 후 비어 있는 경우

제공된 REC_WAS/REC_DB의 제품 줄은 모두 4개 필드다. Tomcat 버전 끝 공백은 기존
normalized.strip()이 제거하며 SAP HANA 버전의 괄호/공백은 허용된다.
SP30의 DB 2개와 SP48의 두 순서 변형을 재현했지만 invalid_product_record는 발생하지 않았다.
운영의 최종 WAS=/WEB=/DB= 원문 줄은 보존돼 있지 않아 어느 실제 줄이 잘못됐는지는 확정할 수 없다.
따라서 Parser 규칙을 완화하거나 RAW에서 제품을 추측 복원하는 fallback을 만들지 않았다.
초기에 검토한 output_truncated 경로도 운영의 error와 다르므로 원인으로 적용하지 않았다.
SSM YAML/탐지 로직은 변경하지 않았다. 실제 운영 3대의 문제 해결을 확인했다고 주장하지 않는다.

## 다음 강제 갱신의 TXT 진단

기존 runtime/ssm_raw/ TXT에 아래 안전한 metadata를 추가한다.
- Parse Status: Success / Failed / Not Attempted
- Parse Error: 기존 고정 reason (전체 exception message 아님)
- Keys Present: 기존 7개 key의 존재 여부
- Record Counts: WAS/WEB/DB의 None 아닌 stdout 레코드 수
- Output Length
- invalid_product_record 시 Invalid Record Key/Line/Field Count/Fields Present

예:

```text
Status: Success
Response Code: 0
Parse Status: Failed
Parse Error: invalid_product_record
Invalid Record Key: WAS
Invalid Record Line: 5
Invalid Record Field Count: 3
Invalid Record Fields Present: product=true, version=true, status=false
```

필드 존재 여부는 고정 product/version/status 슬롯의 비어 있지 않음만 표시한다.
특히 4개가 아닌 레코드는 슬롯 의미를 확정할 수 없으므로 count와 함께 확인한다.
실패한 제품 문자열/경로/전체 stdout/stderr/credential은 추가 저장하거나 로깅하지 않는다.
기존 SSM_RAW 및 Command ID의 TXT-only 정책은 유지한다.
이 진단 필드는 aws.json/API/Excel에 포함하지 않는다.

## EOS source 및 canonicalization

제공된 기준 데이터를 env/os_eos 및 env/db_eos에 추가했다. 날짜는 이 두 로컬 파일만 읽는다.
외부 인터넷/API나 하드코딩된 날짜 fallback은 없다. Export마다 두 파일을 읽어 변경 사항을 반영한다.
UTF-8 BOM/빈 줄/# 주석을 지원하고 잘못된 형식/날짜는 무시한다.
파일 없음/읽기 불가/미매칭은 '-'다.

OS:
- Amazon Linux 2023.* → Amazon Linux|2023
- CentOS Linux 7.* → CentOS Linux|7
- Microsoft Windows Server / Windows / Win + 연도 → Windows Server|연도
- SLES for SAP / SUSE Linux Enterprise Server (for SAP Applications) / SUSE
  → SLES|major SPn 우선, 없으면 SLES|major
- Ubuntu point release → Ubuntu|major.minor LTS key
- redhat/RHEL/Red Hat Enterprise Linux → RHEL|major
- DSM/Synology DSM → Synology DSM|major.minor

DB는 표시용 db_platform을 재파싱하지 않고 record.db의 product/version을 사용한다.
- MySQL/MariaDB/Oracle → major.minor
- MSSQL/SQL Server → major
- PostgreSQL 9.x 이하 → major.minor, 10 이상 → major
- Sybase/ASE/SAP ASE → SAP ASE|major.minor
- SAP HANA의 명시적 2.0 SP30/48/59 → SAP HANA|2.0 SPn
- 알 수 없는 제품/버전이나 없는 key에는 다른 제품/인접 버전의 날짜를 추정하지 않는다.

DB EOS는 기존 DB 제품 출력에 사용되는 유효 레코드와 같은 순서다.
중간 미매칭도 '-'를 남긴다. 예: Oracle; UnknownDB; MariaDB → date; -; date.
DB Platform 문자열은 기존 규칙을 그대로 사용하며 EOS 조회와 독립적이다.
SSM last_success_at 및 success/stale guard도 유지한다. 실패한 첫 수집으로 EOS를 만들지 않는다.

## 변경 파일

- env/os_eos, env/db_eos: 사용자가 제공한 초기 로컬 기준 날짜
- backend/services/eos.py: 로컬 loader/canonicalization/lookup
- backend/services/aws_export.py: 기존 OS EOS/DB EOS 컬럼에 lookup 결과 반영
- backend/services/ssm_inventory.py: parser 검증 의미를 유지하며 안전한 오류 위치/형태와 TXT 결과 추가
- tests/test_eos_lookup.py: 제공된 OS alias와 DB 버전/미매칭/우선순위/파일 처리
- tests/test_hana_inventory_eos.py: HANA 제공 형태 3건, Cache→실제 XLSX, 실패 모양/안전한 TXT
- tests/test_ssm_excel.py: 복수 DB EOS 순서/미매칭 위치, Cache-only 실제 XLSX, 로컬 파일 변경 반영
- docs/eos-hana-diagnostics.md

기존 테스트 삭제/skip/검증 약화는 없다. 기존 복수 DB 미매칭 기대값 한 곳만
EOS 위치 보존 요구에 맞춰 '-'에서 '-; -'로 구체화했다.
EC2 컬럼 순서/스타일, SG/ENI Sheet, Frontend/API/Launcher/재시작 정책은 변경하지 않았다.
SSM API/retry/daily collection/RAW 추출 함수는 AST 비교로 동일함을 확인했다.

## 검증 결과

- 관련 EOS/SSM/RAW/Excel/Refresh: 193 passed (1.44s).
- 전체 pytest (Chromium 포함, skip 없음): 848 passed, 2 failed (39.10s).
- 기존 실패: ScheduledIndex.mode 테스트 대역 누락, Timeline 기대 150/실제 100 불일치.
- 실제 XLSX의 OS EOS(P)/DB EOS(W), 순서/기존 헤더/색상/필터를 확인했다.
- Export에서 boto3/requests를 실패시키는 mock으로 API 미호출을 검증했다.
- 제공된 3가지 HANA 레코드 형태의 fake SSM → 성공 Cache → XLSX 전달은 통과했다.
  실제 운영 실패 레코드는 미확인으로, 다음 강제 갱신 TXT metadata로 추가 확인해야 한다.
- git diff --check 통과. 운영 AWS 호출 및 SSM Document 변경 없음.
