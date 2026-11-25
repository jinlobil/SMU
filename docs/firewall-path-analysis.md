# Firewall Path Analysis 구현 보고

## 변경 파일과 기존 구조

- `backend/services/firewall_path_check.py`: 기존 matcher/API 응답 유지, 분석 진입점과 Configuration snapshot 확장.
- `backend/services/firewall_path_analysis.py`: Configuration 기반 PATH/Reachability/Exposure 분석.
- `frontend/src/pages/FirewallPathCheckPage.tsx`: 결론 → 경로 → 접힌 근거 순서.
- `tests/test_firewall_path_analysis.py`: 신규 Backend/API 회귀 테스트.
- `tests/test_firewall_path_analysis_browser.py`: 신규 브라우저 회귀 테스트.
- `tests/test_firewall_path_layout_browser.py`: 확장 응답과 레거시 응답 fixture 동시 검증.
- 본 문서.

기존 구현은 Network Mapping의 고정 경로/예상 Zone에 Rule, Static Route 및 cache 기반 AWS SG 검사를 연결했다. Rule 순서는 숫자 Position 또는 검증된 Top/After chain을 사용했다. 이 matcher, SG 검사 및 export용 NAT/Interface/Alias/Zone/Gateway parser를 재사용한다. Mapping은 후보 seed로 유지하고 실제 연결 Interface/Route/Gateway 소유 관계 및 DNAT 대상으로 경로를 보강한다.

## 분석 모드와 처리 순서

- 두 입력: `PATH`.
- Source만: `SOURCE_REACHABILITY`.
- Destination만: `DESTINATION_EXPOSURE`.
- 모두 공백: HTTP 400.

PATH는 입력/서비스 정규화 → seed 경로 및 SG 네트워크 판단 → Interface/Alias 소유 확인 → Ingress/Return Route → DNAT → Destination Route/Egress Zone → Rule → SNAT → Gateway → 최종 SG/요약 순서로 분석한다. 표시 경로에서 DNAT는 Firewall 앞, SNAT는 뒤에 독립 step으로 나타난다. 각 단계는 설정에 근거한 판정이며 실제 패킷 전송 성공을 뜻하지 않는다.

Source Reachability는 입력과 서비스에 일치할 수 있는 Rule의 Destination Object/Network/FQDN/Zone을 그룹화한다. Destination Exposure는 반대로 Source 범위를 그룹화하고 내부 목적지의 역방향 DNAT 게시 정보도 제공한다. 각 그룹을 동일 PATH 엔진으로 검사한다. IP를 전수 열거하거나 CIDR의 대표 IP 하나로 전체 범위를 허용 판정하지 않는다. ANY는 심볼릭 범위로 남기고 WARNING 처리하며 미해석 Object/FQDN은 UNKNOWN이다. 부분 CIDR 일치는 전체 PASS/전체 BLOCK으로 확대하지 않는다.

## NAT / Interface / Zone / Route / Gateway

NAT는 활성 상태, 원본 주소/서비스, Interface, linked Firewall Rule을 검사한다. 다중 일치는 전체 NAT의 유효한 순서로 결정하고 불명확하면 변환을 확정하지 않는다. 이름 참조는 기존 object/service map에서만 해석한다. 임의의 객체명에서 숫자 IP를 추출하지 않는다. 변환 대상은 단일 host만 확정하며 PAT는 단일 목적지 port만 지원한다. MASQ는 설정된 Egress IP를 사용하되 해석 실패 시 UNKNOWN이다.

Alias는 parent Interface와 Zone을 재사용한다. 실제 Zone과 seed 예상 Zone 불일치는 경고한다. 실제 Interface Zone이 없을 때 seed/xfrm 추론을 구분하고 INFERRED로 표시한다. 추론 Zone 불일치만으로 확정 BLOCK을 만들지 않는다.

Static/Connected Route는 longest-prefix를 사용한다. 동등 prefix의 상충 후보는 모호함으로 표시한다. Return Route 미확인은 UNKNOWN/경고이며 실패로 단정하지 않는다. 명시적 blackhole은 차단 근거다. Gateway는 Egress Interface 설정과 연결해 표시하고 live health, ping 성공, 장애 여부를 추정하지 않는다.

## Rule / SG / 최종 상태

Matched Rule은 활성 조건 전체 일치 및 신뢰 가능한 순서로 결정한다. Candidate Rules는 상세 근거로 분리하고 적용 Rule로 간주하지 않는다. 미해석 Rule Object는 확정 허용/기본 차단 판단을 막는다. 넓은 서비스 질의도 서비스별 차이를 경고한다.

AWS SG는 기존 수집 Cache만 사용한다. Source SG는 원본 outgoing packet, Destination SG는 NAT 이후 packet을 평가한다. AWS private networkPath가 반환되면 Firewall을 임의 삽입하지 않는다. SG stateful 응답에 reverse allow를 추가 요구하지 않는다.

최종 상태는 PASS/BLOCK/WARNING/UNKNOWN이다. 표시 경로에서 최초로 확정된 BLOCK을 `blockedAt`/`primaryReason`으로 사용한다. 뒤 단계는 `reached=false`로 표시한다. UNKNOWN 또는 추론/누락 정보가 있으면 PASS로 단정하지 않는다. Confidence는 CONFIRMED/INFERRED/UNKNOWN이며 Configuration 검증 수준을 의미한다.

## FQDN / 응답 / UI

FQDN은 resolve된 주소의 조합을 실제 주소와 원래 FQDN 조건으로 검사한다. 같은 결과/경로/Rule은 공통 결과로 표시하고 상이한 결과는 MIXED RESULT/WARNING으로 요약한다. `resolvedResults`에는 개별 결과가 남는다. 주소 family 불일치는 UNKNOWN이다.

기존 `/api/firewall/path-check`와 source/destination/path/steps/firewalls/awsSecurityGroups/policySummary/checkedAt를 유지한다. 추가 필드는 `mode`, `summary`, `analysisPath`, `details`, 단방향 `groups`, FQDN `resolvedResults`/pair count다. 기존 `path`는 문자열 Firewall 목록이고 새 구조화 단계는 `analysisPath`를 사용한다. 최종 신규 결론은 `summary`가 기준이다. details에는 candidateRules/routes/returnRoutes/natRules/interfaces/zones/gateways/resolvedObjects/awsSg 등이 들어간다.

기존 컴포넌트/스타일을 사용하며 결론과 차단 위치를 먼저 표시한다. 경로에는 Firewall/SG/NAT/Route/Gateway와 실제 Zone/적용 Rule이 나온다. 큰 표와 원본 근거는 기본 접힘이다. 개별 및 전체 펼치기/접기를 지원하며 새 조회마다 초기화한다. 레거시 응답 렌더링도 유지한다.

Configuration API는 기존 TTL Cache를 유지하고 한 분석 내 각 Firewall/entity를 한 번만 조회한다(refresh 및 FQDN/그룹 분석 포함). 실패는 entity별 격리한다. 인증정보/원본 예외/비밀번호를 응답에 추가하지 않는다. 새로운 의존성은 없다.

## 검증 및 남은 한계

검증 숫자는 작업 완료 응답을 참조한다. Backend에서는 NAT/Zone/Route/Return/Gateway/SG, Rule 순서/기본 Drop, 세 모드, 복수 FQDN/혼합 결과, API 및 Configuration 조회 중복/실패 격리를 검사한다. Chromium에서는 요약/경로/후보 숨김/펼침 상태/초기화/모드/레이아웃을 검사한다. 실제 운영 방화벽 호출이나 probe 트래픽 검증은 수행하지 않는다.

현재 Configuration만으로 동적 routing, AWS route table의 완전한 경로, VPN 실제 가용성, Gateway live 상태, DNS split horizon, 응답 패킷의 전체 다중 hop 경로를 증명할 수 없다. 단방향 분석은 정책 Object 기반 후보 범위이며 주소 구간을 완전히 분할/차집합 계산하는 엔진은 아니다. ANY를 모든 Internet 범위의 확정 허용으로 해석하면 안 된다.

분석량 상한은 FQDN 조합 256개, 단방향 그룹 500개이며 초과 시 WARNING으로 명시한다. 복수 translated host/port 범위, 동등 Route 후보, 미해석 객체, Interface 부재는 보수적으로 남긴다. 후속 개선은 주소/서비스 구간 분할, 다중 경로 모델, 동적 Route/Cloud network data 연결, 예산 초과 분석 pagination이다. 이번 변경에 커밋/푸시는 포함하지 않는다.

### 최종 로컬 실행 결과

- 관련 Backend/API/기존 SG/FQDN 테스트: **205 passed**.
- 신규 및 기존 UI/레이아웃/정적 Frontend 테스트: **18 passed**.
- Frontend `typecheck`, production `build`: 성공(기존 bundle 크기 경고만 존재).
- 전체 pytest: **1103 passed, 2 failed**, 57.27초. 변경 전 확인한 동일한 두 실패만 남았다.
  - `test_settings_service.py::test_scheduler_runs_every_target_then_index`: 기존 `ScheduledIndex.mode` 불일치.
  - `test_timeline_export.py::test_search_all_is_not_limited_by_timeline_group_item_cap`: 기존 150/100건 제한 불일치.
- 신규 테스트는 parametrization 포함 Backend 26건, 브라우저 9건이며 기존 passing test 회귀는 발견되지 않았다.
- `git diff --check`: 성공. 운영 장비 테스트/커밋/푸시 미실행.
