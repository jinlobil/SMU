# Firewall Path Check의 AWS Security Group 연동

## 기준 코드와 재사용한 구조

원격 main을 조회하고 기존 AWS Excel PR #321이 병합된
`4778ad0b27c77b9773f62406e7a765585dc46ad7`으로 fast-forward한 뒤 작업했다.
기존 `POST /api/firewall/path-check`, `FirewallPathCheckService.check`, Sophos
snapshot/TTL/refresh, Rule 순서·Address/Zone·Protocol/Port 판정과 Static Route
판정을 유지한다. `firewalls`, `path`, `partialPath`의 기존 결과를 그대로 반환하고
`awsSecurityGroups`, 순서가 있는 `steps`, `policySummary`를 추가했다.

기존 AWS 서비스에서 ENI 탐색을 `AwsAssetService.attached_interfaces` 공통 helper로
추출해 Asset/SG의 기존 관계 처리와 이번 IP별 검사에서 함께 사용한다.
기존 Asset/SG 호출의 동작은 유지하며 새 검사는 선택적으로 raw ENI 캐시를 보완한다.

## Endpoint와 부착 관계

`cache/aws.json`을 요청당 한 번 읽는다. AWS API를 호출하거나 DB/Index/새 수집 API를
추가하지 않는다. 이름이나 Name Tag로 AWS Endpoint를 추정하지 않는다.

- PrivateIpAddress와 ENI의 PrivateIpAddresses, Ipv6Addresses를 `ipaddress`로 파싱해
  exact match한다. Public IP도 실제 ENI Association이 있을 때 해당 ENI와 연결한다.
- DescribeAddresses 캐시의 EIP는 NetworkInterfaceId 또는 InstanceId + PrivateIpAddress
  관계가 입력 IP를 특정 ENI에 연결할 때만 사용한다.
- DescribeNetworkInterfaces raw 캐시는 Attachment.InstanceId가 해당 InstanceId와
  일치할 때만 embedded ENI를 보완한다.
- CIDR이 EC2 주소를 포함하더라도 /32 또는 /128 단일 주소가 아니면 임의 EC2를
  선택하지 않는다. 동일 IP가 복수 EC2/ENI에 존재하거나 EC2만 식별되고 ENI를
  확인할 수 없으면 UNKNOWN이다.
- SG는 식별된 ENI의 Groups.GroupId만 사용한다. 다른 ENI의 SG나 instance-level
  SecurityGroups를 대신 합치지 않는다. Rule은 SecurityGroupRule.GroupId로 연결한다.

## 방향, Rule 매칭과 상태

새 연결의 forward 방향만 검사한다. Source EC2에는 Outbound (`IsEgress=true`),
Destination EC2에는 Inbound (`IsEgress=false`)를 적용한다. Stateful SG의 응답을 위해
Destination Outbound/Source Inbound를 별도로 요구하지 않는다.

연결된 여러 SG의 Allow Rule을 합집합으로 검사하며 하나라도 Exact Allow이면 해당
SG 단계는 PASS이다. 여러 Match와 Candidate를 모두 반환하며 첫 Rule만 선택하지 않는다.

| 조건 | 처리 |
| --- | --- |
| IPv4/IPv6 CIDR | 상대 IP/CIDR이 Rule 범위에 포함되면 일치, 일부 겹침은 Candidate, 다른 address family는 불일치 |
| TCP/UDP | 실제 FromPort ≤ Destination Port ≤ ToPort, protocol의 `6`/`17` 표기도 처리 |
| `IpProtocol=-1` | ALL, 포트 제한 없음 |
| ICMP/ICMPv6 (`1`/`58` 포함) | Type/Code로 표시, `-1/-1` 전체 허용만 Exact 가능, 제한된 Type/Code는 입력이 없어 Candidate |
| 기존 IP Protocol Number 입력 | Protocol Number로 검사, 포트로 해석하지 않음 |
| Protocol ANY / Port 미지정 | 주소에 적용되는 TCP/UDP 등 모든 후보 표시, UNKNOWN으로 조건 확인 필요 |
| ReferencedGroupInfo.GroupId | 상대 IP가 붙은 ENI의 실제 GroupId로 비교, 참조 SG를 새 부착으로 간주하지 않음 |
| PrefixListId | ID와 미수집 사유를 표시, 다른 서비스 조건도 적용 가능하면 Candidate; CIDR을 추정하지 않음 |

SG Reference의 Exact Allow는 기존 엔진이 완전한 직접 경로로 판단하고, 양쪽
private/IPv6 ENI가 동일 VPC이며 GroupId가 실제 일치할 때로 한정한다. Firewall 경유,
EIP/Public 주소, VPC 간 연결 정보 부족, 부분 경로이면 NAT/Middlebox/Reference 의미를
단정하지 않고 Candidate로 남긴다. Prefix List/Reference Candidate가 있더라도 독립된
Exact Allow Rule이 존재하면 SG Union에 따라 PASS일 수 있다.

| 상태 | 의미 |
| --- | --- |
| PASS | EC2·IP별 ENI·Attached SG가 확인되고 정확한 Allow Rule 존재 |
| FAIL | 부착 SG/Rule 데이터가 확인되고 구체적 Query에 일치 Allow 없음 |
| N/A | 정상 Instance 캐시에서 해당 IP의 AWS EC2를 찾지 못함 |
| UNKNOWN | 캐시 누락/오류, ENI 식별 모호, 필요한 SG/Rule 정보 누락, Broad/미확정 조건 |

구체적인 Query에서 수집된 Rule 배열이 비어 있으면 FAIL이다. Rule 배열 자체가
누락됐거나 IsEgress/Protocol/Port/SG 원본 등의 필요한 데이터가 불완전하면 UNKNOWN이다.
AWS 읽기/구조 오류는 기존 Firewall 결과를 폐기하지 않고 UNKNOWN으로 정상 반환한다.
최종 결과는 확정 FAIL 우선, 그 외 UNKNOWN/부분 경로면 `일부 정책 확인 불가`, 필요한
모든 단계가 PASS이면 `Firewall / AWS SG 정책 기준 허용`이다. 실제 연결 가능으로
표현하지 않는다. Static Route 확인 결과는 기존 방식으로 별도 표시한다.

## 경로별 결합

| 경로 | Step 순서 |
| --- | --- |
| OFFICE → AWS | 기존 사업장 FW → 기존 Cloud FW → Destination SG Inbound |
| AWS → OFFICE | Source SG Outbound → 기존 Cloud FW → 기존 사업장 FW |
| AWS → AWS | Source SG Outbound → 기존 엔진이 선택한 FW만 → Destination SG Inbound |
| WAN → AWS | 기존 엔진이 선택한 FW만 → Destination SG Inbound |

어느 경우에도 경로 이름을 기준으로 Cloud Firewall을 새로 삽입하지 않는다.
기존 엔진이 직접 경로를 반환하면 SG 두 단계만 남는다. 기존 IPv4 경로와 Zone 매핑은
유지했다. IPv6 Query와 CidrIpv6 검사를 위해 address family 비교를 보호하고 같은
family의 Source/Destination 입력을 허용했다. 기존 Sophos IPv4 매핑을 IPv6 경로로
추정하거나 새로운 IPv6 Firewall 주소 매핑을 만들지 않는다.

## UI

기존 Firewall Path Check 화면, 입력, 메뉴, API와 CSS를 사용한다. 기존 Path diagram과
결과 순서에 SG Step을 추가했다. 기존 Firewall CandidateTable/RouteTable은 유지한다.
SG 결과에는 Direction, EC2 Name, Instance ID, IP, ENI ID, Attached SG Name/ID,
Rule ID, Protocol, From/To Port 또는 Type/Code, Source/Destination, Description,
Match/Candidate와 이유를 표시한다. N/A는 요약에서 표시하고 불필요한 graph Step은
생략한다. 기존 result-pill의 success/fail/exists 색상만 사용한다.

## 변경 파일

- `backend/services/aws_assets.py`: 기존 관계 탐색을 공유하는 IP별 ENI attachment helper
- `backend/services/aws_security_group_path.py`: cache-only Endpoint/SG Rule 검사, 상태·요약
- `backend/services/firewall_path_check.py`: 기존 결과에 SG Step/정책 요약 추가, IP family 보호
- `backend/services/firewall_network_mapping.py`: 다른 address family 간 network 비교 보호
- `frontend/src/pages/FirewallPathCheckPage.tsx`: 기존 diagram/결과 UI에 SG 상세 표시
- `tests/test_aws_security_group_path.py`: 경로·Rule·캐시 오류·API 통합 검증
- `docs/firewall-path-aws-sg.md`: 이 완료 보고서

## 검증 결과

- 신규 AWS SG Path 테스트 **68 passed**: OFFICE/WAN/AWS 양방향, Direct/Cloud 경로,
  IPv4/IPv6, EIP/Secondary IP/복수 ENI, 여러 SG Union, CIDR/Port/Protocol, SG Reference,
  Prefix List, Broad/ICMP, N/A/UNKNOWN, Stateful, cache-only와 FastAPI 정상/오류 응답.
- 기존 Firewall Path/Frontend/Rule 분석 및 AWS Asset/Management 테스트
  **75 passed**, 신규와 함께 **143 passed**. 기존 Rule 순서, wildcard, Address/Zone,
  Route, protocol number, Broad Query의 회귀 검증을 포함한다.
- 전체 pytest **498 passed, 2 failed**. 기존 스케줄러 테스트의 `ScheduledIndex.mode`
  누락과 Timeline 검색의 100건 제한 실패이며 해당 기능은 수정하지 않았다.
- `npm run typecheck`, `npm run build` 통과. 기존 큰 bundle 경고는 비차단이다.
- Vite의 TSX 변환과 실제 React SSR로 SG 상세의 Match/Candidate, EC2/ENI와 Rule ID,
  Prefix List 표시 및 기존 Source/Destination/Protocol/Port 입력 렌더링을 검증했다.
- 테스트와 기능 검증은 합성 캐시/Mock Sophos snapshot을 사용했다. 검증 결과 JSON과
  React HTML은 `runtime/aws-sg-path-validation/`에 있으며 실제 원본 AWS 캐시는 변경하지 않았다.
- 전체 pytest 결과: `runtime/aws-sg-path-pytest.xml`, `runtime/aws-sg-path-pytest.log`.
- 실제 개발 서버와 Vite 프록시에서도 기존 Path Check API가 HTTP 200을 반환하고,
  AWS 캐시 없음은 UNKNOWN으로 표시하며 기존 Seoul/Cloud Firewall Step을 유지하는지
  확인했다. Vite가 수정된 TSX 페이지를 제공하는 것도 검증했다.

## 남은 제약과 커밋

Route Table/NACL/NAT/IGW/TGW/LB/Prefix List 수집, 실제 Ping/TCP 연결 및 SG 변경은
추가하지 않았다. 실 AWS/Sophos 장비 호출과 브라우저 GUI에서의 클릭은 검증하지
않았다. 결과는 현재 캐시·기존 경로 엔진·Firewall Config의 정책 범위에 한정된다.
UNKNOWN을 해소하려고 미수집 네트워크 정보를 추측하지 않는다.

커밋 메시지: `Integrate AWS Security Group checks into Firewall Path Check`.
실제 Commit Hash와 GitHub 브랜치 링크는 완료 보고에 제공한다.
