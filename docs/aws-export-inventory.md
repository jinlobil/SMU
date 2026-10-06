# AWS XLSX 관리대장 개편 결과

## 기준 코드와 유지한 구조

작업 시작 HEAD는 `b3c314dd64d9914f7d537b1bdf7ffa40a791d139`이다. 지정된
`b1c3f650229d416c2fde65ad3268f2bda05ffb50`은 로컬에 없고 원격 조회도
`not our ref`로 실패했다. 선후 관계를 단정하거나 해당 커밋으로 checkout하지 않았다.
현재 HEAD의 AWS 수집 및 Export 구현을 확장했다.

Export Management → FastAPI Job → Watchdog → Laborer → AwsExportService →
`exports` → 기존 Download API 흐름을 유지한다. UI, Job transport, Download API는
수정하지 않았다. Export는 `cache/aws.json`과 `cache/endpoints.json`만 읽으며
AWS/Sophos API를 호출하지 않는다.

## 추가 수집과 캐시

기존 조회 API 6개와 `env/aws_env.txt`의 Credential/Region을 유지한다.

| 추가 IAM 조회 권한 | 수집 방식 | 기존 Raw JSON에 추가한 배열 |
| --- | --- | --- |
| `ec2:DescribeInstanceTypes` | boto3 paginator의 모든 페이지 | `instance_types` |
| `ec2:DescribeVolumes` | boto3 paginator의 모든 페이지 | `volumes` |
| `ec2:DescribeAddresses` | pagination을 지원하지 않으므로 단일 호출 | `addresses` |

기존 `metadata.counts`에도 새 배열의 건수가 포함된다. Credential을 캐시에 쓰지
않으며 새 AWS DB/SQLite/설정 파일은 만들지 않는다. 기존 원자적 캐시 저장과
수집 실패 시 이전 캐시 보존 동작을 사용한다. 추가 API 권한이 없으면 기존의
안전한 권한 오류로 수집이 실패하고 이전 캐시를 보존한다.

## EC2 List의 컬럼과 Source

| 순서 | 컬럼 | Source / 표시 방식 |
| --- | --- | --- |
| 1 | NO | EC2 행 순번 |
| 2 | Type | `EC2` |
| 3 | 티어 | `Environment` Tag, `PRD` → `PROD`, `DEV` 유지, 나머지 원본 |
| 4 | 종류 | `Project` Tag |
| 5 | Hostname | 공통 Sophos 캐시 매칭 결과의 `hostname` |
| 6 | Name | `Name` Tag |
| 7 | 용도 | `Purpose` Tag → `Description` Tag → `-` |
| 8 | Instance ID | `InstanceId` |
| 9 | Instance | `InstanceType` |
| 10 | vCPU(core) | 해당 Instance Type의 `DefaultVCpus(DefaultCores)` |
| 11 | MEM | `MemoryInfo.SizeInMiB / 1024`, GiB, 불필요한 소수점 제거 |
| 12 | EBS | 해당 InstanceId의 연결 Volume Size 합계, GB |
| 13 | OS | `OS` Tag |
| 14 | Platform | `OS_type` Tag |
| 15 | Kernel | `-` |
| 16 | OS EOS | `-` |
| 17 | WAS | `-` |
| 18 | WEB | `-` |
| 19 | DB | `-` |
| 20 | DB Platform | `-` |
| 21 | DB EOS | `-` |
| 22 | EIP | DescribeAddresses의 InstanceId 또는 연결 ENI ID가 일치하는 실제 PublicIp 목록 |
| 23 | EIP 필수 여부 | `-` |
| 24 | IP | Primary `PrivateIpAddress` |
| 25 | 설치일 | `-`, LaunchTime을 사용하지 않음 |
| 26 | Status | `running` → `Running`, `stopped` → `Stop`, 기타 상태 의미 유지 |
| 27 | anti virus | 공통 Sophos 매칭 성공 → `Sophos`, 실패 → `미설치` |

Root 외 데이터 EBS도 합산하고 동일 Volume ID의 중복 attachment를 중복 계산하지
않는다. detached attachment는 제외한다. 복수 EIP는 모두 줄바꿈으로 보존한다.
일반 EC2 Public IP를 EIP로 추정하지 않는다. 새 배열이 없는 구형 캐시는
CPU/MEM/EBS를 `-`로 표시한다. 수집된 volumes가 있으나 연결 볼륨이 없으면
`0 GB`이다. EIP가 없거나 addresses 배열이 없으면 `-`이다.

`Network Interfaces`의 기존 컬럼, 데이터 변환과 기본 스타일은 유지했다.

## 공통 Sophos 매칭

`SophosMatcher`를 EC2 List와 EC2 Mapping 양쪽에서 재사용한다.
Primary Private IPv4를 먼저 확인하고 ENI의 private IPv4도 정확히 비교한다.
IP 매칭이 없을 때만 실제 AWS `PrivateDnsName`/`Hostname`과 Sophos hostname을
공백 제거·소문자·마지막 점 제거 후 전체 문자열로 정확히 비교한다.
부분 문자열, 유사도, 도메인 생략 매칭은 사용하지 않는다. `Name` Tag는
매칭 입력에 사용하지 않는다. 동일 IP가 캐시의 복수 Endpoint에 있으면
hostname/id 정렬에 따른 첫 Endpoint를 사용한다. 매칭 결과로 Hostname과
anti virus를 함께 결정한다.

## EC2 Mapping 정책 구조

21개 컬럼은 요청 순서인 NO, EC2 Name, Hostname, Instance ID, State, Private IP,
Public IP, SG Name, SG ID, Direction, Protocol, From Port, To Port, Source Type,
Source, Destination Type, Destination, Rule Description, ENI ID, VPC ID, Subnet ID이다.

Instance → NetworkInterfaces → Groups.GroupId → 해당 GroupId의 Rule 관계만
사용한다. SG 참조 Rule을 실제 부착으로 해석하지 않는다. 한 행은 하나의
ENI에 적용된 SG Rule이다. 복수 ENI에 같은 SG가 붙으면 각 적용 관계를
별도 행으로 보존해 ENI/Subnet/VPC 대응이 손실되지 않게 한다. 다른 SG의 같은
포트나 개별 Rule을 합치지 않는다.

Direction은 `IsEgress`만 사용한다. Inbound는 Source만, Outbound는 Destination만
채우고 반대쪽은 `-`이다. IPv4/IPv6 CIDR, Prefix List, 참조 Security Group ID를
보존한다. 기존 `_rule` 변환을 재사용하며 Mapping의 ALL은 Protocol/From/To 모두
`ALL`, ICMP/ICMPv6는 `Type n` / `Code n`으로 표시한다. 기존 Inbound/Outbound
시트의 데이터와 컬럼은 유지했다.

EC2 Name → Instance ID → Inbound/Outbound → SG Name → Protocol → From/To 순서로
정렬한다. 숫자 포트와 ICMP Type/Code는 숫자로 정렬한다. 적용 Rule이 없는 EC2도
한 행으로 보존하며 SG/Rule 정보는 `-`로 표시한다. 구형 캐시에 instance-level
SecurityGroups만 있고 ENI가 없으면 실제 ENI 부착을 추측하지 않는다.

## 스타일과 Vertical Merge

기존 dependency-free XLSX writer에 선택적 `ledger` 스타일을 추가했다.
기존 스타일 번호와 다른 Export의 기본 동작을 유지한다.

- EC2 List와 SG 4개 시트: Navy 헤더, White Bold 글자, 가운데 정렬, Thin Border,
  Autofilter, Header Freeze. 일반 셀은 White Fill, Black Font, Thin Border, Vertical Center.
- Running은 Green/White Bold, Stop과 미설치는 Red/White Bold, Sophos는 Blue/White Bold.
- Inbound Rules의 Rule ID와 Mapping Direction은 Light Blue/Dark Font,
  Outbound는 Light Orange/Dark Font. SG별 색상이나 미사용 SG 판정은 추가하지 않았다.
- Mapping은 연속 서버 그룹의 첫 7개 공통 컬럼(A:G)만 세로 병합한다.
  SG/Rule 및 ENI/VPC/Subnet 컬럼은 병합하지 않는다.
- 서버 그룹 첫 행은 Medium Top Border, 나머지는 Thin Border이다.
  병합 셀은 가로·세로 가운데 정렬하고 anchor 아래 셀의 값을 비운다.
- 행과 셀은 오름차순으로 출력한 뒤 mergeCells를 기록한다. 중복 병합 컬럼을
  제거하고 병합 대상 값이 다르거나 그룹 ID가 없으면 오류로 중단해 데이터 손실을 막는다.

## 검증과 생성물

최종 전체 pytest: **430 passed, 2 failed**. 실패 2개는 작업 전에도 확인한 기존
문제로 `test_settings_service.py::test_scheduler_runs_every_target_then_index`의
누락된 `ScheduledIndex.mode`, `test_timeline_export.py::test_search_all_is_not_limited_by_timeline_group_item_cap`의
기존 Timeline 검색 100건 제한이다. 해당 코드는 변경하지 않았다.

신규 테스트는 데이터 매핑, exact matching, 복수 EBS/EIP, 구형·빈 캐시, 복수
ENI와 SG 참조, Protocol/Direction/Source 종류, 정렬, 스타일, 기존 시트 회귀,
Laborer Job 생성과 완료를 검증한다. ZIP CRC와 모든 XML/relationship part 파싱,
행·셀 번호 순서, merge anchor, 범위, 중복·겹침, 하위 셀 비움도 검사한다.
기본 fixture에서 정책 서버 4행은 A2:A5부터 G2:G5까지 정확히 7개 범위로 병합된다.

실제 생성하고 XML 검증한 합성 fixture 파일:

- `runtime/aws-export-validation/exports/aws_ec2_20261006_024108_667089.xlsx`
- `runtime/aws-export-validation/exports/aws_sg_20261006_024108_679876.xlsx`
- 전체 테스트 결과: `runtime/aws-export-pytest.xml`, `runtime/aws-export-pytest.log`

현재 개발 서버의 Laborer를 재시작한 뒤 기존 FastAPI
`POST /api/jobs/export/aws` → Job 완료 → 기존 Download API 흐름도
두 Export 모두 실제 HTTP로 검증했다. 실행 환경의 AWS 캐시가 비어 있으므로
이 확인에서는 빈 데이터와 정상 헤더/스타일을 검증했다. 다운로드한 파일도
전체 XML을 파싱했다. 해당 smoke 파일은 `runtime/aws-export-validation/exports/api-*.xlsx`에 보존한다.

실제 AWS 계정·Sophos API 호출과 Microsoft Excel GUI 열기는 검증하지 않았다.
기존 캐시를 새로 수집해야 CPU/MEM/EBS/EIP가 채워지며 AWS IAM에 추가 조회 권한
3개가 필요하다. SSM, Kernel/WAS/WEB/DB/EOS 자동 수집, 설치일 추정, SG 변경 기능은
추가하지 않았다.

## 변경 파일

- `backend/services/aws_assets.py`: 추가 조회 API와 pagination 차이 처리
- `backend/services/aws_export.py`: 관리대장, 공통 매칭, 리소스 계산과 정책 매핑
- `backend/services/spreadsheet.py`: 선택적 관리대장 스타일과 안전한 Vertical Merge
- `tests/test_aws_assets.py`: 새 수집 배열과 API 회귀 테스트 확장
- `tests/test_aws_export_inventory.py`: 관리대장·스타일·XML·Laborer 테스트
- `docs/aws-export-inventory.md`: Source와 구현·검증 결과

이 변경은 `Revise AWS Excel exports as server and SG policy inventories` 메시지로
커밋한다. 실제 Commit Hash는 완료 보고와 `git log -1`에서 확인할 수 있다.
