# 첨부 Excel + AWS 원본 교차 검증

이번 검증은 제공된 Firewall Export Workbook 전체 시트와 추가 `aws.json`을 사용했다. 운영 API/DNS는 호출하지 않았으며 제품 코드나 테스트에 운영 IP/ENI/SG 관계를 하드코딩하지 않았다.

## 앞선 결과의 정정

Seoul DNAT Object 3개는 자료에 없었던 것이 아니다. `Seoul`의 `250827_Forti(IN)`에 Object 목록과 동일 순서의 Resolved 주소 목록이 있었다. 기존 오프라인 XLSX loader가 다중 Object의 bare-address 목록을 추출하지 못했다. 이 결과를 “원본 누락”으로 보고한 판단을 정정한다.

| Object | 실제 Resolved 값 |
|---|---|
| `VIP_FSA1000F_116.122.51.131` | `116.122.51.131/32` |
| `VIP_FSA3000E_116.122.51.130` | `116.122.51.130/32` |
| `VIP_FML400F_116.122.51.132` | `116.122.51.132/32` |

Object 이름에 포함된 숫자는 사용하지 않았다. 동일 개수의 명확한 bare IP/CIDR 목록만 순서대로 연결한다. Group의 펼쳐진 `member (address)`는 별도로 처리하며, 서로 개수가 다른 목록이나 정의가 충돌하는 참조는 임의로 연결하지 않는다.

## 전체 자료 교차 확인

- Cloud/Seoul/Icheon/Anseong 원본 정책 514개와 LAN ↔ OFFICE / LAN ↔ WAN / ETC의 정책 증거를 함께 읽는다. 분석용 중복 시트의 Rule을 새 정책으로 중복 삽입하지 않는다.
- Rule의 Source/Destination Resolved를 NAT Object lookup에 사용한다. 다른 시트에 동일 참조의 유일하고 일관된 명시적 정의가 있으면 활용하고, 충돌하면 가져오지 않는다.
- 예를 들어 `UDP_6515`는 Cloud Rule `AIDR_SYSLOG`에 `Protocol: UDP | Destination: 6515`로 제공되어 있다. 이를 교차 Resolve하면 TCP Packet은 해당 NAT와 불일치함을 확정할 수 있다. Original Destination이 아직 미해석이어도 다른 AND 조건이 확정 불일치하면 해당 NAT는 적용 후보가 아니다.
- `#PortB:13`처럼 실제 Alias가 존재하는데 빈 Object placeholder가 있는 경우, 빈 값이 Interface lookup을 가리던 문제를 수정했다. NAT Index와 실제 matcher 모두 Interface/Alias 주소를 우선 사용한다.
- AWS 원본은 EC2 80개, ENI 153개, Security Group 339개, SG Rule 5,433개, EIP 17개를 포함한다. query IP → 실제 ENI → 해당 ENI의 Groups → GroupId가 같은 Rule만 연결했다.
- Sophos Cloud Firewall 소유로 자동 Join된 Public Address는 **15개**이며, Primary Interface 1개와 Alias 14개다.

## Scenario 1

입력: `101.1.3.50 → 100.1.2.131`, TCP / ANY.

| 항목 | 실제 데이터 결과 |
|---|---|
| Destination type | `AWS_PRIVATE_IP` |
| Instance | `i-0524d31d77c74a83e` |
| ENI | `eni-0b8e3baab3bbb69bb` |
| Attached SG | **10개**, 원본 ENI.Groups와 exact 일치. 10개 모두 SG 원본에 존재 |
| Seoul Policy | `ztna(LAN TO AWS1_1)_tag` 허용 |
| Seoul Route | `100.1.0.0/16 → xfrm3`, VPN |
| NAT | 기본 WAN SNAT 미적용. 이전 3개 VIP Object / UDP NAT / 실제 Alias 참조 때문에 발생했던 오프라인 가짜 UNKNOWN 제거 |
| 다음 실제 평가 | Cloud Firewall의 정책 |
| 최종 미확정 위치 | 선행 `KR OT SCM_RDS` Rule의 Destination predicate |

`SRV_KR_AWS_PRD_SCM_DB`의 실제 Resolved 값은 `sourcedb.cuu7vs7fuvij.ap-northeast-2.rds.amazonaws.com`이다. **Object/FQDN 정의는 존재한다.** 그러나 그 hostname의 실제 IP 목록/DNS Cache는 Excel/AWS JSON 어디에도 없었다. AWS JSON 전체 문자열도 확인했으며 이 hostname의 주소 매핑은 포함되어 있지 않다. EC2 이름이나 RDS hostname의 일부로 임의의 IP를 추정하지 않는다.

따라서 엔진은 ENI/SG 연결 실패가 아니라 이 선행 정책의 match 여부를 확정하지 못해 멈춘다. 나중의 `VPN <> LAN Drop Logging`을 확정된 적용 Rule로 채택하지 않으며, 실제 Forward SG Step도 생성하지 않는다.

별도 **독립 SG 조건 검사**에서는 대상 ENI의 10개 SG를 모두 평가했다. 일부 서비스는 SG Rule이 Prefix List를 참조한다. 제공 JSON에는 PrefixListId는 있지만 해당 CIDR entries가 없으므로 그 주소 조건만 미확정이다. 관련 ID:

- `pl-001eb3e6e6bef0fb4`
- `pl-003377dd519c3a5d2`
- `pl-08f09dc4b51ca9394`
- `pl-0c990d615b0114997`
- `pl-0e5ff57e4e4f891cd`

독립 검사 결과는 원래 Source를 peer로 한 SG 조건의 판정이며, 앞선 Firewall을 통과했다는 의미가 아니다. 예를 들어 TCP/3389는 이 peer 조건의 SG 단독 검사에서 FAIL이며, Prefix List에 의존하는 포트는 UNKNOWN이다. TCP/ANY를 임의의 포트 하나로 확정하지 않았다.

## Scenario 2

입력: `101.1.3.50 → 3.38.46.51:4430`, TCP.

| 관계 | 실제 데이터 결과 |
|---|---|
| Public IP | `3.38.46.51` |
| Instance | `i-07b65dfa02c34128a` |
| WAN ENI | `eni-0ddebd5da4a537a90` |
| ENI Private IP | `10.30.1.201` |
| Sophos owner | Cloud / `PortB` / Physical / WAN |
| Endpoint type | **`FIREWALL_PUBLIC_IP`**, 일반 Internet이나 일반 EC2 Destination으로 오분류하지 않음 |
| Attached SG | `sg-08f8f44b8d1d954be`, `sg-029e839b455af4b73` |
| Seoul Route | Interface Gateway 기반 `0.0.0.0/0 → Port2 / WAN / ISP_Gateway` |
| 최종 미확정 위치 | Seoul의 선행 `250827_위험국가 차단` 및 `noname-18` predicate |

`Block_Country`는 Object 이름만 Resolved 셀에 반복되며 실제 구성원/주소 범위는 어떤 시트에도 없다. `*.wetax.go.kr`도 패턴만 있고 구체적인 주소 목록은 제공되어 있지 않다. 뒤의 `250827_웹 사이트 허용`에는 TCP/4430 허용 Service가 명시되어 있으나, 선행 Drop 정책을 확인하지 않고 최종 Allow로 건너뛰지 않는다. 이 지점의 UNKNOWN은 Public/Private/Interface 연결 실패가 아니다.

**조건부 설정 검사**로는 아래를 확인했다. 실제 통과 Path Event를 추가하거나 선행 미확정을 우회하지 않았다.

- 선행 정책이 허용했다면 Seoul의 `Default SNAT IPv4`는 실제 WAN `Port2`에 대해 MASQ를 선택한다. peer는 `116.122.51.129`가 된다.
- 해당 peer와 원래 peer 모두 WAN ENI의 TCP/4430 SG 검사에서는 **PASS**였다. 일치 Rule ID는 `sgr-034df164f57b56c92`, `sgr-09939a22052cfa301`이다. 다른 ENI의 SG는 사용하지 않았다.
- Cloud `PortB` 주소에 대한 TCP/4430 DNAT은 **일치 없음**, 미해석 selector도 없었다. Cloud까지 도달한다면 Firewall Local Endpoint 흐름이며 일반 WAN → LAN Transit 검사가 아니다.
- 실제 Local Service의 포트/ACL configuration은 첨부 데이터에 없다. 관리 포트 숫자만으로 Local Service 허용을 추정하지 않는다.

## Alias도 실제 데이터로 확인

`15.165.133.185 → eni-0ddebd5da4a537a90 → 10.30.1.212 → Cloud PortB:10 → Parent PortB → WAN`을 자동 Join했다. NAT Index는 이 private 주소로 `Original Destination = #PortB:10`인 `New WAN > PO_NLB DNAT`을 찾았다. 후보 검색 결과이며 실제 NAT 적용 여부는 Source/Service/Interface 조건을 추가 비교해야 한다.

## 변경 및 테스트

이번 추가 확인에서의 수정:

- `tools/validate_firewall_packet_workbook.py`: 전체 Rule 시트의 병렬 Object/Resolved, 분석용 시트, 유일한 교차 참조; 실제 unresolved predicate의 종류와 독립 SG 검사 구분.
- `backend/services/firewall_path_analysis.py`, `firewall_configuration.py`: 빈 Object placeholder보다 실제 `#Interface/Alias`를 우선하는 matcher/Index 수정. 실행 경로를 다시 변경하지 않았다.
- `tests/test_firewall_workbook_resolution.py`: 교차 Resolve·충돌·group·Alias placeholder·독립 검사 분리 및 익명화한 AWS 첨부 형상 회귀.
- `tests/fixtures/firewall_uploaded_aws_shape.json`: 실제 제공한 AWS 구조에서 추출한 익명화 fixture. 운영 IP/ID/이름은 제거했으며 SG 10개/2개의 ENI attachment 구조 및 Prefix List/전체 CIDR sample shape를 유지한다. 전체 운영 정책을 대체하는 fixture는 아니다.
- `tests/test_firewall_supplied_data.py`: 로컬 ignored manifest를 사용해 실제 첨부 데이터의 Object 및 두 query를 API/DNS 없이 재생하는 opt-in 테스트. 영구 익명 fixture 테스트는 이 입력 파일 없이도 실행된다.

실제 입력/보고 JSON은 `runtime/validation/`에 로컬 저장했다. 원본 업로드나 운영 cache/aws.json을 덮어쓰지 않았고, 원본 데이터 파일은 git에 추가하지 않는다.

최종 테스트 결과는 아래에 기록한다. 커밋·푸시는 하지 않는다.

### 검증 결과

- 추가 교차 Resolve / 익명 fixture / 독립 검사 테스트 9개 + 실제 첨부 입력 테스트 3개: **12 passed**.
- 실제 첨부 데이터를 활성화한 전체 테스트: **1,243 passed / 2 failed**, 93.45초.
- 기존 실패 2개는 동일한 Scheduler Index 인터페이스 및 Timeline 항목 수 제한 테스트다. 이번 추가 검증과 관련된 실패는 없다.
- `git diff --check` 통과. 이번 추가 변경에는 Frontend 수정이 없다.
- 운영 API/DNS 호출 없음. 커밋·푸시 없음.

실제 실행 결과 JSON: `runtime/validation/scenario1.json`, `runtime/validation/scenario2.json`. 두 파일의 `independentAwsChecks`는 Forward Path와 분리된 조건 검사임을 명시한다.
