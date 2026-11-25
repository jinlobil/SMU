# Firewall Path Analysis 재작업 보고

## 1. 변경 파일

| 파일 | 변경 |
|---|---|
| `backend/services/firewall_path_analysis.py` | 결정 엔진, 주소/서비스 범위 분석, 역방향 DNAT Exposure, 구조화 결과 |
| `backend/services/firewall_path_decisions.py` | 기존 matcher를 사용하는 우선순위 판정, 서비스 경계 분할, Progress 상태 전이 |
| `frontend/src/pages/FirewallPathCheckPage.tsx` | Raw UI 제거, 결론/Progress/세로 카드, 결과 선택 |
| `frontend/src/styles.css` | 기존 SMU 토큰을 사용하는 반응형 Progress/Stepper 스타일 |
| `tests/test_firewall_path_decisions.py` | 결정 엔진 및 Self Review 회귀 테스트 |
| `tests/test_firewall_path_analysis.py` | 새 상태/전체 범위 분석/NOT_REACHED 계약 검증 |
| `tests/test_firewall_path_analysis_browser.py` | Raw 제거, 결과 선택, Progress, 반응형 검증 |
| `tests/test_firewall_path_layout_browser.py` | 레거시 API 표시 및 새 UI 레이아웃 계약 검증 |
| `tests/test_firewall_path_check_frontend.py` | 새 화면의 정적 계약 검증 |
| `docs/firewall-path-analysis.md` | 본 보고서 |

기존 Firewall/NAT/Route/Interface/Zone/Gateway Export parser, AWS 수집, Scheduler, SSM, Cache schema, Excel Export는 수정하지 않았다. 의존성 추가도 없다.

## 2. Decision Engine 변경

기존 Topology Mapping은 경로 seed로 유지하고 실제 Interface/Alias, Connected/Static Route, NAT 원본 주소 및 Gateway 소유 관계로 보완한다. 없는 설정을 무조건 사용자 확인으로 넘기던 공통 경고 대신, 각 단계의 정확한 판정 이유를 반환한다. NAT 없음은 `NOT_REQUIRED`이며 정상적인 비변환 경로다.

Rule, NAT, Forward Route, SNAT, Gateway, SG, Return Route를 구분한다. Forward Rule이 차단하면 뒤 설정의 개별 판정은 진단용으로 보존하되 패킷 진행 상태는 NOT_REACHED다.

## 3. UNKNOWN 감소를 위한 계산

서비스의 Protocol/Port 경계와 Network의 Rule/Route/Interface/NAT 경계를 계산한다. TCP/UDP Port 65,535개나 CIDR 내부의 개별 IP를 전수 열거하지 않는다. 경계 사이에서 결과가 같은 구간을 평가하고 인접한 동일 서비스 결과를 합친다. 두 Allow Rule이 Network의 절반씩을 허용하는 경우 전체 PASS, 한 절반만 허용하는 경우 구간별 PASS/BLOCK을 담은 WARNING을 반환한다.

IP Protocol 번호도 조건이 같은 집합으로 묶는다. TCP/UDP/ICMP/ICMPv6에 해당하는 IP Protocol 질의는 해당 서비스 조건을 적용한다. 서로 다른 ServiceGroup member의 Protocol과 Port를 잘못 조합하지 않도록 같은 member 내에서 조건을 검사한다.

기존 API의 원본 input, protocol, port, protocolNumber는 구간 평가 후에도 유지한다. 실제 Object가 존재하는 FQDN은 분석 내 DNS memo로 주소를 해석한다. DNS 실패는 정확한 실패 사유로 남긴다.

## 4. Connected Route

기존 Interface/Alias parser 결과의 CIDR을 사용한다. CIDR이 없고 IP Address/Netmask가 있으면 직접 계산한다. Alias는 Parent Interface와 Zone을 연결한다. Connected 후보를 만든 뒤 Static 후보와 longest-prefix를 비교한다. 동일 prefix에서는 Connected를 우선한다.

## 5. NAT

Original Source/Destination/Service, Inbound/Outbound Interface 및 Linked Firewall Rule로 적용 후보를 계산한다. 숫자 Position과 검증 가능한 전체 Top/After chain을 사용하며 XML 배열 순서를 우선순위로 가정하지 않는다. Alias IP가 아니어도 명시적 Original Destination이 일치하는 유일한 DNAT Firewall을 경로 후보로 찾는다.

DNAT/PAT는 Firewall 정책 앞, SNAT/MASQ는 정책/Route 뒤에 적용한다. DNAT 이후 목적지와 서비스가 후속 Rule/Route/SG 판정에 반영된다. SNAT는 원래 outgoing Source SG 판정을 지우지 않는다. 일치 NAT가 없어도 정상 경로이며, NAT API나 필요한 참조가 실제로 누락된 경우만 변환 불확실 상태로 둔다.

## 6. Matched Firewall Rule

기존 matcher와 Export의 순서 복원 helper를 재사용한다. 활성 상태, 주소, 실제 Zone, 서비스 조건 전체가 맞는 Rule 중 우선순위가 가장 높은 Rule 하나를 선택한다. 적용 Rule보다 뒤에 있는 미해석 Object는 이미 결정된 판정을 흐리지 않는다. 실제로 앞에서 shadow할 수 있는 누락 Object만 판정을 막는다. 빈 정책/일치 Allow 없음은 기본 Drop이다. 순서 metadata가 없어 상충하는 경우에는 그 사실을 구체적으로 설명한다.

## 7. Service / ANY

Port 미입력을 UNKNOWN으로 취급하지 않는다. `Any Service Drop`이 먼저 적용되면 전체 서비스 BLOCK이다. 443만 허용되고 나머지가 Drop이면 `1–442 BLOCK`, `443 PASS`, `444–65535 BLOCK`을 제공하며 전체는 WARNING(서비스별 결과 상이)이다. Source/Destination Only의 ANY 범위도 Route/Object 경계와 Zone으로 나눠 실제 Path Engine을 실행한다. 한 IP만 골라 범위 전체를 허용으로 해석하지 않는다.

## 8. Return Route

Connected와 Static longest-prefix로 직접 계산하고 동등 prefix 후보는 Distance로 구분한다. 빈 Gateway의 xfrm Route는 VPN 경로로 인정한다. Site/Topology와 Interface Zone은 Ingress 식별에 사용하지만, Site 이름만으로 존재하지 않는 Return Route를 만들어 PASS로 선언하지 않는다. Connected/Static 모두 없을 때에는 미수집 BGP/OSPF/SD-WAN 경로를 확정할 수 없다고 설명한다. 명시적 Return blackhole은 차단이며 Forward 단계 뒤에 평가한다.

## 9. NOT_REACHED

Backend의 `progress()`가 단일 상태 전이를 담당한다. 최초 BLOCK 다음의 Route/Gateway/Firewall/SG/Return/Destination은 모두 NOT_REACHED, `reached=false`다. 기존 설정 판정은 `configurationStatus`에 남긴다. Progress link의 `active=false`와 UI의 점선/비활성 표현도 같은 결과에서 만들어진다. 후단 UNKNOWN이 최초 BLOCK을 덮지 않는다.

## 10. Source Only

Source와 일치하는 Rule의 Destination Object/Network/FQDN/Zone을 중복 제거해 그룹화한다. 각 범위 전체를 실제 PATH 분석으로 검증한다. 여러 부분 Rule의 합집합이 전체를 덮는 경우에는 단순 `partialKnown` 때문에 WARNING으로 강등하지 않는다. 비활성 Rule은 범위 발견에서 제외한다. 그룹 선택 시 해당 Network의 Progress/Stepper만 보여준다.

## 11. Destination Only

Destination Rule에서 Source 범위를 역으로 찾고 Zone과 실제 Network로 분석한다. 내부 서버의 Translated Destination을 참조하는 DNAT을 찾아 Published Address를 통한 별도 경로도 실제로 검증한다. 단순 NAT 목록을 인터넷 접근 허용의 근거로 쓰지 않는다.

## 12. 제거한 UI

Candidate Firewall Rule 표, 기존 정책/AWS SG 상세 표, Raw Rule/NAT/Route 표, Configuration/Resolved Objects JSON dump, 모두 펼치기/접기 버튼을 제거했다. 개별 `판정 근거 보기`에는 선택 Rule의 짧은 필드만 표시하며 표/JSON은 없다.

## 13. Summary

상단에 상태, Source→Destination, 서비스, 최초 차단 Firewall, 실제 Zone, Matched Rule, Action, 이유를 표시한다. 혼합 결과에서는 하나의 차단 Rule을 전체의 적용 Rule처럼 표시하지 않고 Network/Service/IP별 결과를 선택하도록 한다. 화면의 허용 의미는 Configuration 기준이다.

## 14. Progress Line

Backend 응답의 `progress.nodes/links`를 그대로 표시한다. 통과 구간은 활성 실선, BLOCK node는 강조, 이후 구간은 점선/NOT_REACHED다. Source/NAT/Firewall/Route/Gateway/SG/Destination을 동일 모델로 표현한다. DNAT 뒤 최종 Destination에는 실제 변환된 주소를 보여준다.

## 15. Vertical Stepper

Progress 다음에 한 열의 카드로 표시한다. Firewall 카드는 실제 Zone/Rule/Action/Reason, NAT는 원본→변환 및 Rule, Route는 종류/CIDR/Interface/Zone/Gateway, SG는 방향/이유를 간결하게 보여준다. 차단 이후 카드에서는 도달하지 않았다는 사실만 기본 표시한다. 중복 NAT/Route 설명은 제거했다.

## 16. Responsive 검증

Chromium에서 1440/1024/768/390px의 가로 넘침, 카드 좌표/순서, 근거 펼침 후 넘침, 단방향 선택 결과를 검사했다. 1440/390px 전체 화면 이미지도 직접 검토했다. Progress를 기존 SMU Panel 위에 올려 테마 대비를 확보했고, 기존 Border/Status 토큰을 사용한다. 테마 역할 검사를 통과한다.

## 17–18. 테스트 결과

최종 실행 수치는 아래 최종 검증 절에 기록한다. 기존 matcher/AWS SG/FQDN/API, 새 Decision Engine/브라우저/레이아웃, 전체 pytest 및 Frontend typecheck/build를 실행한다. 운영 Firewall/API 호출이나 실제 probe 트래픽 테스트는 하지 않았다.

## 19–20. Self Review에서 발견하고 수정한 문제

| 확인 방법 | 발견 | 실제 수정/회귀 검증 |
|---|---|---|
| 서비스/Rule 조건 대조 | Port 없음이 불확실 상태로 남음 | 서비스 경계별 전체 분석, Any Drop 확정 |
| ServiceGroup 복수 member 테스트 | TCP protocol과 UDP port가 섞일 수 있음 | 같은 member 단위 조건 상관관계 유지 |
| Rule 우선순위 재검토 | 후순위의 누락 Object도 UNKNOWN을 만들 수 있음 | 앞에서 shadow할 수 있는 Rule만 불확실성 반영 |
| 넓은 CIDR fixture 실행 | 첫 겹치는 Site가 전체 범위의 소유자로 선택됨 | 소유 containment 검증 및 범위 분할 |
| CIDR 합집합 fixture | 여러 Allow Rule이 전체를 덮어도 partial 경고 | Network 구간 전체 판정 및 단방향 강등 제거 |
| 복수 NAT fixture | 숫자 Position과 NAT 소유 주소가 충분히 사용되지 않음 | 숫자 우선순위 및 Original Destination 기반 후보 경로 |
| 기존 API 테스트 | 구간 분석 중 input/protocol/port가 대표 구간으로 덮임 | 원본 API 필드 보존 |
| 전체 pytest | Text 토큰을 Border에 사용하는 테마 역할 위반 | 기존 Border 토큰으로 수정 |
| 브라우저 선택 테스트 | 서비스 select의 접근 가능한 이름이 option 내용에 영향받음 | 명시적 aria-label 및 실제 선택 동작 검증 |
| 1440/390px 이미지 검토 | Progress의 테마 배경 대비, 중복 설명, NAT 이후 목적지 | Panel 재사용, 중복 제거, 실제 변환 주소 표시 |
| Raw/UNKNOWN/NOT_REACHED 검색 | Raw/전체 펼치기, 후단 FAIL/UNKNOWN, 모호한 사유 | Raw 제거, Backend 상태 전이 통일, 구체적 이유 |

단순 테스트 성공 외에 Internal→AWS, Internal→Internet, Internet→DNAT 서버, Office→Office, 명시적 Rule BLOCK, Connected, Static LPM, Source Only, Destination Only, TCP/ANY 등 대표 10개 시나리오를 fixture로 별도 실행해 예상 결과/단계를 비교했다. 운영 상태를 가정한 성공 보고는 하지 않는다.

## 21. 남는 UNKNOWN 및 분석 한계

UNKNOWN은 필요한 Firewall 설정/응답이 없거나 API가 실패한 경우, 실제 참조 Object/서비스 주소가 없거나 FQDN DNS 해석이 실패한 경우, 필요한 Interface/Zone 데이터가 없을 때, Forward/Return Connected·Static Route가 없어 미수집 동적 경로가 필요한 경우, NAT의 변환 주소/서비스/필수 순서를 결정할 데이터가 없는 경우, AWS Cache에 Endpoint/SG 근거가 없을 때 발생할 수 있다. 각각 해당 단계와 구체적 이유를 반환한다.

Gateway의 live Up/Down은 분석 항목으로 만들지 않는다. 설정의 Active/Backup/Weight만 보여주며 런타임 가용성을 이유 없이 UNKNOWN으로 만들지 않는다. ECMP/순서 metadata 부재/부분 서비스·주소 결과는 조건별 차이를 설명하는 WARNING으로 처리한다.

Network/FQDN 조합 256개, 서비스 구간 1024개, 단방향 그룹 500개 분석 한도가 있다. 초과 범위는 미분석이라고 명시하고 전체 PASS로 처리하지 않는다. 복잡한 NAT pool/다중 변환/SD-WAN, 실시간 연결성, 수집되지 않은 동적·Cloud Route 전체 경로까지 증명하지는 않는다. Source/Destination Only는 수집한 정책의 접근 범위이며 미표시 영역을 허용으로 간주하지 않는다.

## 22. 기존 기능/API 회귀

기존 `/api/firewall/path-check`와 호환 필드를 유지한다. 새 `summary/progress/pathSteps/findings/networkResults/serviceResults`는 Backend가 구성하며 UI가 Raw를 해석하지 않는다. 기존 `analysisPath`/`resolvedResults`도 유지한다. Configuration snapshot은 같은 분석 내 재사용한다. 레거시 응답 표시 adapter는 Raw 표 없이 남긴다.

공통 Export parser를 수정하지 않았다. Firewall/NAT/Route/Interface/Zone/Gateway Export 및 기존 AWS SG 회귀는 전체 로컬 테스트로 확인한다. 커밋/푸시는 하지 않는다.

## 최종 검증 결과

- 신규 Decision Engine 회귀 테스트: **29 passed**.
- 관련 Backend/API/SG/FQDN + UI 테스트 범위: **254 passed** (관련 묶음 253건 및 추가 Network 선택 브라우저 1건, 최종 전체 실행에서도 통과).
- 새 UI/기존 레이아웃/정적 Frontend 테스트: **20 passed**.
- 대표 시나리오 **10개** 별도 실행: 예상 상태/경로 일치. 운영 호출 없음.
- Chromium 1440/1024/768/390px 검증 및 1440/390px 이미지 직접 검토 완료.
- Frontend `typecheck` 및 production `build`: 성공. 기존 bundle 크기 경고만 존재.
- 전체 pytest: **1134 passed, 2 failed**, 63.52초. 신규 실패 없음.
- 남은 두 실패는 변경 전부터 동일하게 존재한다.
  - `test_settings_service.py::test_scheduler_runs_every_target_then_index`: 기존 `ScheduledIndex.mode` 계약 불일치.
  - `test_timeline_export.py::test_search_all_is_not_limited_by_timeline_group_item_cap`: 기존 150/100건 제한 불일치.
- `git diff --check`: 통과. 기존 commit `96e9510` 이후 커밋/푸시 미실행.
