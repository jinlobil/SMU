# SSM Server Inventory: OS별 단일 Document + JSON

## 감사 결과와 재구현 범위

기존 흐름은 Custom Document 내 OS별 step을 전제로 고정 plugin 이름 조회,
실제 plugin 탐색, skip 판별과 모호성 처리로 확대됐다. 이와 별개로 KEY=VALUE,
pipe 구분 제품 레코드를 해석하면서 출력 형식 문제까지 실행 오류와 섞였다.
이번 구현은 SSM 수집 경로를 교체하고 기존 Cache 소비 계약을 유지한다.

기존에 저장한 필드는 hostname/kernel/os/os_install_date, web/was/db 배열과
배열 항목 product/version/path/status, platform_type, 실행 상태/시각이다.
새 구현은 이 필드를 유지하고 os_version을 선택적 필드로 추가한다.
Custom Document 본문은 저장소에 없으므로 기존 외부 스크립트의 전체 탐지 규칙과
동등하다고 주장할 수는 없다. 확인된 출력의 Tomcat/Tengine/MySQL/IIS와 아래 탐지 범위를 구현한다.

전체 참조를 확인한 뒤 제거한 코드:

- _resolve_plugin, plugin 후보 탐색/모호성 판별/multi-step 결과 선택
- 고정 PluginName, fallback 및 ListCommandInvocations 호출
- KEY=VALUE parse_inventory, 반복 KEY/pipe 레코드 parser
- StandardOutputUrl 및 기존 출력 잘림/BOM 호환 분기

normalized는 aws_export의 Sophos 버전/Excel 표시에도 사용하므로 유지한다.
SSM stdout은 JSON 한 건만 받으며 기존 텍스트 출력으로 fallback하지 않는다.

## 실행 흐름

DescribeInstanceInformation에서 현재 EC2의 PlatformType/PingStatus 확인
→ Online Linux/Windows만 선택
→ OS별 SendCommand
→ 같은 CommandId/InstanceId로 GetCommandInvocation polling (PluginName 없음)
→ Status=Success와 정수 ResponseCode=0 확인
→ json.loads(StandardOutputContent)
→ schema 검증 및 null 정규화
→ 기존 aws.json의 ssm_inventory 갱신.

Windows Document: AWS-RunPowerShellScript.
실제 고정 명령: backend/services/ssm_scripts/windows.ps1 전체를 Parameters.commands[0]로 전송.
Linux Document: AWS-RunShellScript.
실제 고정 명령: backend/services/ssm_scripts/linux.sh 전체를 Parameters.commands[0]로 전송.
사용자 입력으로 명령을 만들지 않는다. executionTimeout=60, SendCommand.TimeoutSeconds=60이다.

## 수집 스크립트

### Windows

PowerShell/Get-CimInstance로 OS Caption/Version/InstallDate, 실행 프로세스와 서비스를 읽는다.
IIS는 InetStp Registry MajorVersion/MinorVersion 및 W3SVC 상태를 사용한다.
nginx/Tengine/Apache, Tomcat/WebLogic/JBoss/Jetty,
MySQL/MariaDB/PostgreSQL/Oracle/SQL Server/MongoDB/Redis의 실행 프로세스를 탐지한다.
제품 버전은 해당 실행 파일 ProductVersion을 사용하며 Java 버전을 WAS 버전으로 사용하지 않는다.
Tomcat 버전은 RELEASE-NOTES에서 확인한다. 확인하지 못한 값은 null이다.
제품/설치 경로로 중복을 제거하며 IIS 외 제품은 실행 중인 프로세스 기준이다.
최종 출력은 ConvertTo-Json -Depth 6 -Compress 한 건이다. UTF-8 BOM 없이 출력한다.
OS 조회 실패는 명령 실패로 드러내며 선택적 제품 조회 실패가 최종 exit code가 되지 않도록 한다.

### Linux

POSIX shell, /etc/os-release, hostname, uname, /proc를 사용한다. 원격 Python/jq가 필요 없다.
OS 설치일은 추정하지 않고 null이다.
nginx/Tengine/Apache, Tomcat/WebLogic/JBoss/Jetty,
MySQL/MariaDB/PostgreSQL/Oracle/SQL Server/MongoDB/Redis 실행 프로세스를 탐지한다.
실제 실행 경로/설치 경로를 저장하고 다중 worker를 중복 제거한다.
Tomcat RELEASE-NOTES 및 인식한 제품의 version 옵션에서 버전을 읽는다.
version 실행은 timeout 유틸리티가 있을 때만 최대 2초로 제한하며, 없으면 버전은 null이다.
Tengine의 호환 nginx 버전을 Tengine 버전으로 저장하지 않는다.
Oracle 등 확인되지 않는 버전을 추정하지 않는다. 제품 미탐지는 빈 배열이다.
JSON escaping을 거쳐 stdout에 JSON object 하나만 출력한다. 선택적 탐지 실패는 무시하고
JSON 출력 후 명시적으로 exit 0을 반환한다.

## JSON stdout / Cache schema

기존 Cache와 같은 flat 필드로 출력하여 변환 단계를 최소화한다.

```json
{
  "hostname": "fixture-host",
  "kernel": "fixture-kernel",
  "os": "Example Linux",
  "os_version": "1",
  "os_install_date": null,
  "web": [],
  "was": [
    {"product": "Tomcat", "version": "9.0.46", "path": "/srv/app", "status": "running"}
  ],
  "db": []
}
```

hostname/os는 의미 있는 문자열이어야 한다. kernel/os_version/os_install_date는 string/null이다.
web/was/db는 필수 배열이며 제품 항목은 product 필수 문자열,
version/path/status 선택적 string/null이다. unknown/N/A/빈 문자열 등은 null로 정규화한다.
JSON 이외 stdout이나 schema 위반은 성공으로 취급하지 않는다.
제품이 여러 개면 배열로 저장한다. 원문 출력과 명령 ID는 저장하지 않는다.

Cache 외부 구조는 유지한다:
ssm_inventory.snapshot_date/collected_at/last_attempt_at/status/instances[InstanceId].
성공 레코드에 기존 platform_type/status/last_success_at/last_attempt_at을 붙인다.
신규 DB를 만들지 않고 기존 atomic save 및 run/cache-write lock을 그대로 사용한다.

## 실행 조건과 실패 보존

Asia/Seoul의 인스턴스별 last_attempt_at 날짜를 사용한다. 24시간 TTL이 아니다.
오늘 시도한 서버는 성공/실패와 관계없이 일반 AWS Refresh에서 재실행하지 않는다.
다음 날짜, 시도 이력이 없는 신규 EC2는 다시 대상이 된다.
force=True는 날짜 Gate를 무시하고 현재 Online EC2를 모두 실행한다.
Offline/ConnectionLost/미관리/미지원 OS는 명령을 보내지 않는다.
현재 EC2 ID와 매칭되지 않는 mi- 등은 제외한다.
AssociationStatus=Failed만으로 Online 서버를 제외하지 않는다.

실패 시 기존 성공 Inventory/last_success_at을 보존하고 status=stale,
last_attempt_at/error만 갱신한다. 처음 실패한 서버는 status=failed이다.
SSM 실패는 기존 EC2 Describe 수집을 실패시키지 않는다.
Scheduler Interval 및 일반 지금 실행 의미는 그대로이며 SSM 전용 갱신만 force이다.

## 시간 제한 / throttling / 로그

동시 서버 3대, 개별 서버 90초, 전체 수집 300초 deadline이다.
GetCommandInvocation은 최대 120회로도 제한한다.
SDK 자체 retry는 끄고 connect 3초/read 5초로 제한한다.
진행 중인 SDK 요청은 해당 네트워크 timeout까지 종료를 기다릴 수 있지만 deadline 이후
추가 호출/재시도를 시작하지 않는다.

Describe/Send/Get의 명시적 throttling만 최대 5회 시도한다.
대기: min(4초, 0.25 * 2^retry) * (0.5 + 0.5 * random jitter).
deadline 내 대기가 불가능하거나 retry 한도에 도달하면 throttled로 기록한다.
SendCommand의 다른 오류는 중복 실행 방지를 위해 자동 재전송하지 않는다.
InvocationDoesNotExist는 초기 준비 지연으로 polling하고 종료까지 지속되면 invocation_not_ready,
다른 진행 상태가 deadline/cap에 도달하면 polling_timeout이다.

주요 reason: send_command_failed/get_command_invocation_failed/discovery_failed,
invocation_not_ready/polling_timeout/terminal_failed/nonzero_response_code,
empty_output/json_parse_failed/schema_validation_failed/throttled.

로그: Instance ID, PlatformType, stage/reason, exception type, AWS error code,
Status, ResponseCode, output length만 기록한다.
stdout/stderr/CommandId/credential/전체 exception message는 기록하지 않는다.

## 운영 갱신과 권한

기존 GET /api/aws/ssm-inventory와 POST /api/jobs/aws/ssm-inventory 및 job polling을 유지한다.
UI의 Server Inventory (SSM) 지금 갱신 버튼으로 당일 실패 서버도 새 경로에서 재검증한다.
중복 실행 방지와 기존 AWS Asset UI는 변경하지 않았다.

IAM: ssm:DescribeInstanceInformation, ssm:SendCommand, ssm:GetCommandInvocation.
SendCommand 정책이 LNL-ServerInventory ARN에만 한정돼 있으면 AWS 소유
AWS-RunShellScript/AWS-RunPowerShellScript Document ARN 및 대상 EC2에 맞게 조정해야 한다.
ListCommandInvocations 권한은 이 수집 경로에서 더 이상 필요하지 않다.

특정 운영 Instance ID를 코드/테스트에 넣거나 별도 분기하지 않는다.
이전 Linux exit code 1 기록을 새 실행의 실패 근거로 재사용하지 않는다.
새 명령이 실제로 Status=Failed/ResponseCode=1을 반환할 때만 이번 실행의
terminal_failed로 분류한다. 운영 API 호출 없이 fixture로 검증했으므로 실제 서버 성공은 미확인이다.

## 기존 기능 영향과 검증

화면/API 응답/Scheduler/Refresh atomic save/Cache-only Excel은 수정하지 않는다.
Excel의 Instance ID join, Sophos exact IP/버전, EOS 빈 컬럼, 기존 Sheet/Style을 유지한다.
새 os_version 필드는 추가 저장만 하며 기존 os/kernel/Excel 표시를 바꾸지 않는다.
서버나 로컬 Python dependency 추가는 없다. Linux는 기본 shell 도구를 사용한다.

변경 파일:
- backend/services/ssm_inventory.py: 수집/JSON 검증/제한적 retry
- backend/services/ssm_scripts/linux.sh: Linux 읽기 전용 명령
- backend/services/ssm_scripts/windows.ps1: Windows 읽기 전용 명령
- tests/test_ssm_inventory.py: 새 boto3 요청/응답 기반 테스트
- tests/test_ssm_scripts.py: 실제 script 실행 및 fixture 기반 제품 탐지
- tests/test_ssm_excel.py: 기존 Cache-only Excel 테스트 fixture를 JSON으로 교체
- docs/ssm-server-inventory.md: 설계/운영/검증 문서

PowerShell 테스트는 pwsh가 있으면 실행하며, 없으면 선택적 skip이다.
이번 검증은 Microsoft 배포 portable PowerShell을 /tmp에 추출해 Windows CIM/Registry fixture를
대체하여 실행했다. 운영 Windows/실제 AWS API를 호출하지 않았고 프로젝트 의존성은 추가하지 않았다.

검증 결과:
- 관련 AWS/SSM/Excel/스크립트: 99 passed (3.91s).
- 전체 pytest (PowerShell fixture 실행 포함): 681 passed, 2 failed (56.73s).
- 기존 실패 2개: test_scheduler_runs_every_target_then_index의 ScheduledIndex.mode 누락,
  test_search_all_is_not_limited_by_timeline_group_item_cap의 기대 150/실제 100 불일치.
- 기존 브라우저 테스트 포함 신규 회귀 실패 없음. 기존 실패 테스트를 수정/skip하지 않았다.
- git diff --check 통과.
