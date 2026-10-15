# LNL-ServerInventory 수집 계약과 Collector

## 실제 Document 확인 결과

출처는 관리자가 이번 작업에서 제공한 현재 운영 LNL-ServerInventory 전체 YAML이다.
저장소/Git 이력에는 실제 Document 정의가 없었으며, 이전 코드만으로는 step 이름을 검증할 수 없었다.
이번에는 제공받은 정의의 mainSteps/action/precondition/inputs 및 출력 명령과 직접 대조했다.
AWS API로 Document를 조회하거나 실행하지 않았고 운영 Document도 변경하지 않았다.

아래 표는 정의에서 확인한 구조 요약이다. 배포용 Document 또는 새 스크립트가 아니다.

| 항목 | Linux | Windows |
|---|---|---|
| schemaVersion | 2.2 | 2.2 |
| DocumentName | LNL-ServerInventory | LNL-ServerInventory |
| mainSteps[].name | linuxInventory | windowsInventory |
| mainSteps[].action | aws:runShellScript | aws:runPowerShellScript |
| precondition.StringEquals | [platformType, Linux] | [platformType, Windows] |
| inputs.timeoutSeconds | "300" | "300" |
| inputs.runCommand | 정의 내 Linux shell 본문 | 정의 내 PowerShell 본문 |

최상위 parameters 항목은 없다. Collector가 명령/스크립트/timeout 값을 Parameters로 전송할 필요가 없다.
Document action과 AWS-RunShellScript/AWS-RunPowerShellScript라는 별도 Document는 다른 개념이다.
운영 권한에 맞춰 SendCommand는 LNL-ServerInventory만 사용한다.

## 기존 문제와 제거한 코드

이전 변경은 운영 Custom Document 권한과 맞지 않는 AWS 기본 Document를 전송하여
SendCommand에서 AccessDeniedException을 유발했다. 또 운영 출력은 KEY=VALUE인데
JSON stdout을 요구하여 정상 Success/ResponseCode=0도 파싱 실패할 수 있었다.
이전 단계의 plugin 후보 탐색/모호성 판별은 이제 필요 없다.

- AWS 기본 Document 실행과 Parameters.commands/executionTimeout 제거
- 자체 생성 linux.sh/windows.ps1 및 그 명령 실행용 테스트 제거 (다른 참조 없음 확인)
- JSON stdout/schema validator 제거
- ListCommandInvocations, 후보 탐색, ambiguous 판별, action 기반 추정, PluginName fallback 없음
- StandardOutputUrl 존재를 실패 조건으로 사용하지 않음

normalized는 Sophos/Excel에서도 참조하므로 유지한다.

## 호출 경로

1. DescribeInstanceInformation을 현재 EC2 Instance ID로 필터링한다.
2. Online + 지원 PlatformType만 명령 대상으로 선택한다. AssociationStatus는 offline 판정에 사용하지 않는다.
3. SendCommand(InstanceIds=[id], DocumentName='LNL-ServerInventory', TimeoutSeconds=60).
   Parameters는 전달하지 않는다. TimeoutSeconds는 delivery 설정이며 Document의 300초 실행 시간을 덮어쓰지 않는다.
4. PlatformType=Linux면 PluginName='linuxInventory', Windows면 'windowsInventory'.
5. GetCommandInvocation(CommandId=returned_id, InstanceId=id, PluginName=selected_step)를 polling한다.
6. Status='Success' 및 정수 ResponseCode=0인 경우에만 stdout을 파싱한다.
7. 구조화된 값만 기존 aws.json의 ssm_inventory에 저장한다.

step 선택은 위 제공된 정의와 일치하는 고정 매핑이다. 다른 step이나 action 이름으로 재시도하지 않는다.
InvalidPluginName이 반환되면 조회 오류 invalid_plugin_name으로 끝낸다. 운영에서 같은 문제가
지속된다면 호출 계정/리전의 실제 기본 Document 버전이 제공된 정의와 일치하는지 확인해야 한다.
CommandId/stdout/stderr를 로그나 Cache에 저장하여 진단하지 않는다.

## 출력과 parser

Document의 KV/kv 함수는 KEY=VALUE를 출력하며 제품은 Product|Version|Path|Status다.

```text
HOSTNAME=fixture-windows
KERNEL=10.0.14393
OS=Microsoft Windows Server 2016 Datacenter
OS_INSTALL_DATE=2025-01-14 19:48:22
WEB=IIS|10.0|C:\Windows\System32\inetsrv|running
WAS=None
DB=None
```

제공된 정의와 실제 보고된 출력 형식을 기준으로 parse_inventory를 구현했다.

- BOM/CRLF/앞뒤 공백을 처리하고 첫 '='만 구분자로 사용한다.
- hostname/kernel/os/os_install_date와 was/web/db를 기존 Cache 필드로 저장한다.
- 반복 WAS/WEB/DB는 순서대로 배열에 추가한다. installed/stopped/running 등 상태를 그대로 보존한다.
- 제품 항목의 product/version/path/status 네 필드를 유지한다.
- None 제품은 빈 배열이다. unknown/N/A/빈 값/null 문자열 등은 null로 정규화한다.
- package: 경로와 MSSQL instance=... 경로의 '='도 보존한다.
- Document는 각 제품 카테고리가 없으면 None을 반드시 출력하므로 WAS/WEB/DB key도 확인한다.
- 알 수 없는 부가 라인은 Inventory로 저장하지 않는다. JSON/다른 stdout 형식으로 추정 전환하지 않는다.
- 24,000자 이상은 AWS inline stdout 한계에서 잘렸을 가능성이 있어 output_truncated로 거부한다.
  길이만으로 정확히 한계 길이인 정상 출력과 잘린 출력을 확정 구분할 수 없으므로 보수적으로 처리한다.
- StandardOutputUrl은 판단에 사용하지 않으며 S3 등 추가 API를 호출하지 않는다.

os_version은 이전 Cache 확장에서 생긴 필드다. 운영 Document에는 별도 OS_VERSION 출력이 없어
새 값은 null로 남긴다. KERNEL에서 OS Version을 추정해 채우지 않는다.
실패한 기존 성공 레코드의 os_version을 포함한 정상 필드들은 다른 필드와 함께 보존한다.

### 실제 제품 탐지 범위 (Document는 수정하지 않음)

Linux: 실행 중 Tomcat/WebLogic, Apache/Nginx/Tengine, MySQL/MariaDB/PostgreSQL/Oracle.
Oracle은 /etc/oratab도 확인한다. RPM/dpkg에서는 설치만 된 서버 제품도 확인한다.
Windows: Java/서비스 실행 파일에서 Tomcat/WebLogic, Apache/Nginx/Tengine,
MySQL/MariaDB/PostgreSQL/Oracle; IIS 서비스/Registry와 MSSQL Registry도 확인한다.
제품/version/path/status를 그대로 받으므로 실행 상태와 설치 전용 항목을 모두 유지한다.
Linux OS_INSTALL_DATE=N/A는 null, Windows 설치일은 제공 문자열을 보존한다.
Collector가 별도 탐지 명령을 생성하거나 DB에 접속하지 않는다.

## 진단과 실패 보존

파싱 reason: empty_output/missing_hostname/missing_os/invalid_product_record/output_truncated/parse_failed.
parse_failed는 필수 제품 카테고리 누락 등 완전한 출력 계약을 만족하지 못하는 경우다.

실행/조회 reason: send_command_failed/get_command_invocation_failed/invalid_plugin_name,
invocation_not_ready/polling_timeout/terminal_failed/nonzero_response_code/throttled.
실제 Failed/ResponseCode=1은 terminal_failed이며 PluginName 조회 오류와 구분된다.
이전 실행의 특정 운영 서버 실패를 새 실행 실패로 간주하거나 ID로 별도 분기하지 않는다.

로그는 Instance ID, PlatformType, selected_step, stage/reason, exception type,
AWS error code, Status, ResponseCode, output length, has_hostname/has_os/has_was/has_web/has_db만 남긴다.
key 존재 여부는 파싱 단계에서만 평가하며 그 외에는 None이다.
원문 stdout/stderr/CommandId/credential/전체 exception message는 로그/Cache에 저장하지 않는다.
Cache에는 고정 error reason과 기존 메타데이터만 저장한다.

실패 시 이전 성공 Inventory와 last_success_at을 유지하고 status=stale,
last_attempt_at/error만 갱신한다. 처음 실패하면 status=failed이다.
SSM 실패는 기존 AWS Describe 수집 실패로 전파하지 않는다.

## 일자 Gate / 부하 제한

Asia/Seoul 기준 인스턴스별 last_attempt_at 날짜를 사용한다. 오늘 시도했으면 성공/실패와
관계없이 일반 Scheduler에서는 다시 실행하지 않는다. 다음 날짜 또는 당일 신규 EC2는 시도한다.
force=True는 날짜 Gate를 무시하고 현재 Online EC2를 대상으로 한다.
Scheduler Interval과 일반 지금 실행의 의미는 변경하지 않았다.

동시 서버 3대, 개별 polling deadline 330초, 전체 수집 deadline 1800초다.
Document의 timeoutSeconds=300을 기존 90초 제한으로 먼저 실패시키지 않도록 조정했다.
polling은 최대 360회로도 제한한다. 초기 InvocationDoesNotExist는 준비 지연으로 재시도한다.
SDK connect 3초/read 5초, SDK 자동 retry 없음. 진행 중인 요청은 네트워크 timeout까지
마무리를 기다릴 수 있지만 deadline 이후 새 호출/재시도를 시작하지 않는다.
Describe/Send/Get의 명시적 throttling만 최대 5회, bounded exponential backoff+jitter로 재시도한다.
SendCommand의 다른 오류는 중복 실행 방지를 위해 재전송하지 않는다.

## 기존 기능과 검증

화면/API 응답/Scheduler 인터페이스/중복 실행 lock/atomic save/Cache-only Excel을 유지한다.
기존 GET /api/aws/ssm-inventory, POST /api/jobs/aws/ssm-inventory 및 job polling을 그대로 사용한다.
새 Inventory DB/의존성을 추가하지 않는다. Document 조회 API나 ListCommandInvocations도 필요 없다.
IAM은 기존 Custom Document 기준 DescribeInstanceInformation/SendCommand/GetCommandInvocation을 사용한다.
기존 Sophos exact IP/버전, Excel Sheet/Style/Instance ID Join, EOS 컬럼은 그대로다.

변경 파일:
- backend/services/ssm_inventory.py
- backend/services/ssm_scripts/linux.sh 삭제
- backend/services/ssm_scripts/windows.ps1 삭제
- tests/test_ssm_inventory.py
- tests/test_ssm_excel.py
- tests/test_ssm_scripts.py 삭제
- docs/ssm-server-inventory.md

운영 확인 항목:
- 실제 계정/리전에서 기본 LNL-ServerInventory 버전의 step 이름/출력이 제공된 정의와 같은지
- SSM 전용 지금 갱신 후 send/조회/parse 단계 결과와 선택 step, key 존재 여부
- 이전 실패 서버들이 이번 실행에서 success/stale 중 어떤 상태가 되는지
- 실제 Failed/ResponseCode=1만 서버 측 실행 실패로 구분되는지
- 다음 Scheduler 실행이 당일 실패 서버를 재실행하지 않는지

로컬에서는 boto3 Stubber/가짜 클라이언트만 사용하며 운영 AWS는 호출하지 않는다.
운영 Document 및 원격 스크립트도 변경/실행하지 않았다.

검증 결과:
- 관련 AWS/SSM/Excel: 110 passed (1.90s).
- 전체 pytest (기존 브라우저 포함): 692 passed, 2 failed (58.90s).
- 기존 실패: test_scheduler_runs_every_target_then_index의 ScheduledIndex.mode 누락;
  test_search_all_is_not_limited_by_timeline_group_item_cap의 기대 150/실제 100 불일치.
- 공식 boto3 Stubber의 기대값은 구현 상수에서 가져오지 않고 제공된 Document/step 이름을
  직접 지정하여 대조했으며 Windows/Linux 2개 재검사도 통과했다.
- git diff --check 통과. 기존 실패 테스트 수정/skip 없음. 운영 AWS 호출 없음.
