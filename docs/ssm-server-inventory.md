# EC2 SSM Server Inventory / Sophos Version 감사·완료 보고

## 1. 기존 흐름 감사

- Scheduler는 사용자 Interval과 AWS Source 선택을 유지한다. 지금 실행도 기존 Source Job을 즉시 실행한다.
- Scheduler → Watchdog/Fetcher → `RefreshService.refresh_aws()` → `AwsCollector.collect()` 순서다.
- AwsCollector의 기존 9개 Describe 수집, credentials/region 처리, JSON serialization은 수정하지 않았다.
- RefreshService는 `cache/aws.json.tmp` 작성 후 `os.replace`로 기존 atomic save를 사용한다.
- EC2/SG Export는 AwsExportService → 공통 XLSX Writer → 기존 Laborer/다운로드/선택적 Office 암호화 경로다.
- SophosClient.fetch_endpoints는 paged_items의 원본 item을 그대로 반환하므로 modules/assignedProducts를 별도로 제거하지 않고 기존 Endpoint Cache에 보존한다. 추가 Sophos 조회를 넣지 않았다.
- 기존 SophosMatcher는 Endpoint cache를 읽고 IP/ENI/hostname fallback을 사용한다. EC2 hostname의 이 fallback과 SG Mapping 동작은 유지한다.
- EC2 Anti Virus 판정만 Primary Private IP exact match로 한정했다. 기존의 ENI/hostname fallback으로 백신 설치를 추측하지 않는다.

## 2. Scheduler와 SSM 조건 분리

Scheduler/Fetcher 소스 코드는 변경하지 않았다. Interval 30/60/120분을 설정한 실제
Scheduler dispatch 경로에서 AWS 최신화와 같은 날짜 SSM 미재실행을 검증한다.

SSM은 명시적 Asia/Seoul(UTC+09:00)의 달력 날짜를 사용한다. 24시간 TTL이 아니다.
인스턴스별 `last_attempt_at`의 서울 날짜가 오늘이면 성공/실패와 관계없이 일반 자동 수집을 재실행하지 않는다.
현재 EC2 모두 오늘 시도했으면 SSM client/Describe API도 호출하지 않고 기존 상태를 유지한다.
새 날짜에는 다시 시도하고, 당일 신규 EC2는 시도 이력이 없어 1회 수집한다.
force refresh는 당일 Gate를 무시한다. Scheduler Interval은 변경하거나 SSM에 전달하지 않는다.

실행 실패는 send_command / get_command_invocation / terminal_status / parse 단계로 구분한다.
로그에는 Instance ID, PlatformType, 단계, 고정 실패 사유, Exception type, AWS Error Code,
Status와 ResponseCode만 남긴다. 원문 stdout/stderr, CommandId, URL, 예외 메시지는 기록하지 않는다.
Cache에는 고정 실패 사유만 저장하며 기존 정상 Inventory는 stale로 보존한다.
`StandardOutputUrl`은 S3 stdout 위치이므로 존재만으로 실패 처리하지 않는다.
inline stdout은 AWS 제한인 24,000자에 도달하면 잘림 가능성으로 거부하며 S3 추가 호출은 하지 않는다.
Parser는 UTF BOM, CRLF, 앞뒤 공백을 처리한다.

## 3. 대상·Plugin·부하 제어

현재 EC2 Instance ID와 매칭되는 i- 대상 중 조회가 필요한 ID만
DescribeInstanceInformation Filters에 최대 50개씩 넣고 pagination한다.
외부 ManagedInstance/mi-는 대상에서 제외한다.

PingStatus=Online이고 PlatformType이 Linux/Windows일 때만 SendCommand한다.
AssociationStatus는 Run Command 실행 가능 여부의 판정에 쓰지 않는다.
DocumentName은 `LNL-ServerInventory`로 고정하며 Parameters/임의 명령은 전송하지 않는다.

- Linux: GetCommandInvocation의 PluginName=`linuxInventory`.
- Windows: PluginName=`windowsInventory`.
- 다른 Platform Plugin을 읽거나 Success 상태만 보고 정상 Inventory로 간주하지 않는다.
- Skip/빈 출력/비정상 응답은 Inventory 성공으로 처리하지 않는다.
- 동시 서버 최대 5대. GetCommandInvocation은 최대 45초 polling window/46회 cap이다.
- InvocationDoesNotExist/Pending/InProgress/Delayed 등을 bounded retry한다.
- SDK 연결 5초/읽기 10초 및 제한된 재시도를 사용한다. 진행 중인 SDK 요청의 종료 시간은
  polling window에 추가될 수 있다. 무한 polling은 없다.

IAM에는 기존 EC2 조회 권한 외에 ssm:DescribeInstanceInformation, ssm:SendCommand,
ssm:GetCommandInvocation이 필요하다. SendCommand는 해당 Custom Document/EC2 대상으로
제한할 수 있다. 이 작업에서 IAM이나 운영 AWS 리소스를 실제 변경하지 않았다.

## 4. Parser와 Cache

KEY=VALUE를 첫 '='에서만 나눈다. HOSTNAME/KERNEL/OS/OS_INSTALL_DATE는 scalar,
WAS/WEB/DB는 반복 KEY를 모두 배열에 보존한다. 제품은 Product|Version|Path|Status의
4개 필드로 읽는다. None 제품은 빈 배열이며 unknown/N/A/null/빈 값/'-'는 null이다.
추정값을 만들지 않는다. HOSTNAME/OS가 없는 Skip 등은 파싱 실패다.
전체 Command Output, stderr, Command ID, 원문 예외는 Cache에 저장하지 않는다.

예시 schema(모두 fixture):

```json
{
  "ssm_inventory": {
    "snapshot_date": "2026-10-15",
    "collected_at": "2026-10-15T09:00:00+09:00",
    "last_attempt_at": "2026-10-15T09:00:00+09:00",
    "status": "success",
    "instances": {
      "i-fixture-001": {
        "status": "success",
        "last_success_at": "2026-10-15T09:00:00+09:00",
        "last_attempt_at": "2026-10-15T09:00:00+09:00",
        "platform_type": "Linux",
        "hostname": "fixture-server",
        "kernel": "6.1-fixture",
        "os": "Example Linux",
        "os_install_date": null,
        "was": [{"product": "ExampleApp", "version": "1.0", "path": "/srv/app", "status": "running"}],
        "web": [],
        "db": [{"product": "ExampleDB", "version": null, "path": "/srv/db", "status": "running"}]
      }
    }
  }
}
```

snapshot_date는 조회 가능한 Online 대상의 당일 수집이 성공하면 갱신한다.
Offline/미관리 EC2가 있거나 일부 서버가 실패하면 전역 상태는 partial/failed 등으로
구분한다. collected_at은 실제 성공한 Inventory 수집 시간이며 Cache 재사용 시 유지한다.
처음부터 실패한 서버에는 없는 Inventory 필드를 만들어 넣지 않는다.

기존 성공 서버가 실패하면 status=stale, last_attempt_at/error만 갱신하며 정상 값과
last_success_at은 보존한다. SSM discovery/command/기타 수집 오류를 AWS Describe 성공과
분리하므로 EC2 Cache는 정상 갱신된다. 깨진 과거 JSON도 일반 AWS 최신화로 복구 가능하다.

## 5. 전용 강제 갱신과 동시 실행

- GET `/api/aws/ssm-inventory`: 기준일/수집 시간/시도 시간/상태/실행 여부. Cache만 읽는다.
- POST `/api/jobs/aws/ssm-inventory`: 기존 JobManager로 force 수집. 기존 `/api/jobs/{id}`로 조회한다.
- AWS Asset의 기존 panel/panel-head/status-pill 및 RefreshButton을 재사용한다.
- 같은 날짜라도 현재 EC2 Cache와 매칭되는 Online 대상 전체를 다시 수집한다.
- 일반 Scheduler/지금 실행에는 force를 전달하지 않는다.
- 기존 cross-process OS singleton helper로 SSM 중복 실행을 차단하며 중복 POST는 409다.
- SSM 실행 잠금과 짧은 Cache 쓰기 잠금은 분리한다. 수동 SSM 중에도 일반 EC2 Describe/Cache
  갱신을 허용하며 중복 SSM만 생략한다. 일반 AWS 저장은 최신 SSM Cache를 합치고,
  수동 SSM 저장은 최신 EC2 Cache를 다시 읽어 SSM key만 갱신한다. 서로 덮어쓰지 않는다.

## 6. Excel 데이터 출처

| 컬럼 | 최종 출처 |
|---|---|
| Instance/ID/Status/IP | 기존 EC2 DescribeInstances Cache |
| MEM | 기존 DescribeInstanceTypes Cache |
| EBS | 기존 DescribeVolumes Cache |
| EIP | 기존 DescribeAddresses Cache |
| Hostname | Instance ID로 join한 SSM 정상/보존 값 우선, 없으면 기존 Sophos hostname fallback |
| OS | SSM DescribeInstanceInformation의 PlatformType, SSM 미수집 시 기존 Tag fallback 유지 |
| Platform | SSM OS, SSM 미수집 시 기존 Tag fallback 유지 |
| Kernel | SSM KERNEL |
| WAS/WEB | Product + 알려진 Version, 여러 항목은 '; ' |
| DB | Product Name, 여러 항목은 '; ' |
| DB Platform | Product + 알려진 Version, 모르는 Version은 '-', 여러 항목은 '; ' |
| 설치일 | SSM OS_INSTALL_DATE, N/A는 '-' |
| Anti Virus | EC2 Primary Private IP ↔ Endpoint ipv4Addresses exact match이면 Sophos, 아니면 미설치 |
| Anti Virus Version | modules[name=coreAgent].version 우선, 없으면 installed assignedProducts[code=coreAgent].version, 없으면 '-' |
| OS EOS / DB EOS | 기존 컬럼/기본값 유지. Catalog/Lookup/계산 없음 |

SSM stale의 마지막 정상 값도 출력한다. 버전을 추정하거나 문자열 일부를 버리지 않는다.
`anti virus`를 `Anti Virus`로 바꾸고 바로 오른쪽 `Anti Virus Version`을 추가했다.
공통 Writer를 사용하므로 Autofilter/폭은 새 AB 컬럼까지 확장되며 Sophos/Running/Stop/
미설치 스타일을 유지한다. Network Interfaces와 SG 4개 Sheet/merge는 변경하지 않았다.
Excel 생성 시 boto3.client/외부 request를 실패시키는 테스트로 API 미호출을 검증한다.

## 7. 파일과 테스트

구현 파일:

- backend/services/ssm_inventory.py
- backend/services/refresh.py
- backend/services/aws_export.py
- backend/app.py
- frontend/src/pages/AwsAssetPage.tsx
- frontend/src/components/RefreshButton.tsx

검증 파일:

- tests/test_ssm_inventory.py: parser/plugin/date/new EC2/offline/pagination/concurrency/실패.
- tests/test_ssm_refresh.py: atomic save/실패 격리/수동 force/중복/동시 cache merge/Scheduler.
- tests/test_ssm_excel.py: Instance ID join/Version/정확한 IP/Header/Style/API 미호출.
- tests/test_ssm_browser.py: 실제 Chromium 상태/기존 RefreshButton/중복 비활성화/완료 갱신.
- tests/test_aws_assets.py: 기존 수집 테스트의 SSM client를 fixture로 주입.
- tests/test_aws_export_inventory.py: 의도한 두 Header 기대값 갱신.

Python Dependency 추가 없음. 기존 boto3/botocore와 표준 라이브러리만 사용한다.
운영 서버명/IP/Instance ID를 코드나 테스트에 추가하지 않았다.
실제 운영 AWS/SSM/Sophos API 실행 없이 fixture로 검증했다.

## 8. 최종 검증 및 커밋 상태

- 브라우저 포함 전체 `pytest -q`: **654 passed, 2 failed**.
- AWS/SSM/Excel/기존 브라우저 단독 회귀 묶음: **73 passed**.
- 신규 SSM Chromium UI: **1 passed**. 프런트엔드 typecheck/build 통과.
- 전체 검사 중 기존 Path 브라우저 테스트에서 한 차례 timeout이 있었으나,
  단독 재실행과 마지막 전체 재실행에서는 모두 통과했다. 해당 제품/테스트 코드는 수정하지 않았다.
- 최종 남은 실패 2개는 수정하지 않은 main(`3bfd71f`)을 별도 임시 디렉터리에 추출해 그대로 재현했다.
  - `test_scheduler_runs_every_target_then_index`: 테스트 대역 ScheduledIndex.mode 누락.
  - `test_search_all_is_not_limited_by_timeline_group_item_cap`: 150개 기대 대비 100개 반환.
- 기존 Scheduler/Timeline 소스나 실패 테스트를 이번 변경에서 수정·skip하지 않았다.
- OS EOS/DB EOS/Lifecycle Catalog와 새 Inventory DB는 추가하지 않았다.

변경 브랜치: `codex/ssm-server-inventory`. PR 검증 결과에 기존 main에서 재현된 실패 2개를 명시한다.

## Collector 진단 수정

기존 `command_failed`는 AWS 실행 실패를 의미하는 확정 진단이 아니었다.
전송/조회/terminal status/파싱 예외를 모두 같은 사유로 바꿨기 때문이다.
AWS SDK GetCommandInvocation 응답 정의를 확인한 결과 StandardOutputUrl은 S3 전체 stdout URL이며
실패 조건이 아니다. 기존 조건은 Success/ResponseCode=0 응답도 거부할 수 있었다.
또 첫 KEY에 UTF BOM이 붙으면 HOSTNAME 누락으로 파싱 실패했다. 두 경로 모두 회귀 테스트로 검증한다.
운영 aws.json 및 기존 실행 로그는 이 작업 환경에 없어 26대의 실제 실패 분포는 확정할 수 없다.
수정 후 당일 재검증에는 SSM 전용 강제 갱신을 사용해야 한다. 일반 Scheduler는 오늘 시도 이력을 존중한다.
진단 로그에서 terminal_failed/terminal_timed_out, parse_failed,
invocation_not_found_timeout/invocation_poll_timeout 등을 구분하여 확인한다.

수정 후 전체 pytest: 669 passed, 2 failed (56.69s). 남은 실패는 위에 기록한 기존
Scheduler 테스트 대역 mode 누락과 Timeline 150/100 불일치로 동일하다.
관련 AWS/SSM/Excel 선택 검사 85개 통과 후 추가 Windows/서울 날짜 회귀 검사까지 전체 실행에 포함했다.
