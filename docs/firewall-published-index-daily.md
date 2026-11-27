# Published Address / Index 검색 / 일일 Configuration 수집

2026-11-27 변경 보고. 운영 Firewall/AWS/DNS 호출 없이 제공된 Workbook/AWS JSON, mock 및 로컬 브라우저로 검증했다. 이전 Dynamic Packet Flow 보고의 자체 주소 즉시 종료 설명과 Interval 기반 Firewall 수집 설명은 아래 정책으로 대체한다.

## 판정 흐름

기존에는 DNAT이 매칭되지 않은 Firewall Interface/Alias를 Local Endpoint로 종료했고, DNAT 이후에는 Alias를 참조하는 정책을 변환된 주소만으로 비교하여 놓칠 수 있었다.

현재 흐름은 Endpoint ownership → 실제 Source/Service/Interface 조건 DNAT → 변환 주소 Route 및 Transit Policy → SNAT/Gateway/Next Hop이다. 명시 Alias 참조 정책은 해당 Hop의 원래 Published Destination과 비교한다. 일반 목적지 정책은 변환된 목적지를 계속 사용한다. Alias 소유권만으로 허용하지 않으며 기존 Zone, Enabled, API 순서, 주소, Protocol/Port 검증을 유지한다.

DNAT이 없더라도 현재 Flow에 맞는 명시 Alias Transit 정책을 먼저 평가한다. Drop은 즉시 차단한다. Allow이나 실제 변환/다음 Hop 자료가 없으면 Published Next Hop UNKNOWN으로 남긴다. Alias 주소를 임의 내부 서버로 바꾸지 않는다. Transit/NAT가 없으면 실제 수집된 localServices 또는 Zone Device Access의 ICMP Ping 근거를 확인한다. 근거가 없으면 FIREWALL_ENDPOINT_UNCLASSIFIED이며, 실제 Local Service 대상일 때만 FIREWALL_LOCAL_ENDPOINT를 사용한다. Local ACL 미수집은 허용으로 추정하지 않는다.

`#PortB:n`과 `PortB:n`은 같은 Interface reference를 가리킨다. Alias IP, Parent Interface, 상속 Zone을 Index에 보관하며 원본 Export 행은 변경하지 않는다.

## Index와 검색

| Index | 내용 / 요청 처리 |
|---|---|
| Interface reverse | IP → Interface/Alias, reference → Interface/Alias, Interface → Rule/NAT IDs |
| Firewall Rule | Source/Destination PrefixIndex + unresolved set + FQDN index, 원본 precedence 유지 |
| NAT | Original/Translated Source/Destination PrefixIndex, DNAT/SNAT phase IDs, ServiceIndex, 사전 NAT 순서 |
| Object Group | Refresh/load 시 확장된 Object 목록 및 Network tuple; 요청 중 재귀 확장 없음 |
| Service Group | Refresh/load 시 Protocol/Port 구간 event sweep; bisect 후보 조회 |
| Route | Connected/Static/default 사전 정규화 및 PrefixIndex, bounded 결과 cache |
| AWS | ENI/private/public ownership, SG ID→방향별 Rule; EC2 없는 관리형 ENI 포함 |

PATH는 양쪽 주소·서비스의 후보 교집합을 기존 정확 matcher로 검증한다. SOURCE_ONLY는 Source 후보에서 Destination 범위를, DESTINATION_ONLY는 Destination/NAT 후보에서 Source 범위를 역조회한다. NAT 변환으로 관련되는 범위도 포함한다. Wildcard는 관련 정책/NAT/Route/ownership 경계에서 구간을 나누며 IP를 열거하지 않는다. 동일 predicate fingerprint인 구간만 묶고 coveredNetworks로 전체 범위를 보존한다. Index는 후보 추출용이며 최종 허용 근거가 아니다.

Raw Rule/NAT/Route 전체 테이블을 매 요청 순회하던 흐름, 전체 서비스 구간 생성, 전역 CIDR 반복 분할, AWS SG 전체 Rule 재탐색, 큰 resolvedObjects 반복 복사를 제거했다. 소유 주소/주소 경계 준비는 Memory generation 생성 시 수행한다. 일부 wildcard 범위 분류는 관련 후보와 사전 경계를 순회하며 이를 최종 정책 전체 scan으로 대체하지 않는다.

Generation마다 partition cache(256), route/address lookup cache(8192), 최종 query cache(16)를 제한한다. 동일 Query cache는 TTL이나 Refresh 조건이 아니며 세대 교체 시 폐기한다. 반환은 copy하고 현재 Refresh 상태와 기준 시각을 매번 적용한다.

## 자동 / 수동 Refresh와 실패

`backend/services/settings.py`의 기존 Scheduler를 사용한다. `firewallConfiguration` 설정은 enabled, HH:MM time(기본03:00), timezone=Asia/Seoul, lastAttemptDate, lastSuccessAt을 저장한다. Asia/Seoul 날짜/시각을 명시적으로 계산하고 예정 시각 후 미시도일 때 한 번 실행한다. 시도 날짜를 먼저 저장하므로 실패/재시작도 당일 반복하지 않는다. 다음 날짜에 다시 실행한다. Scheduler 전역 enable과 Firewall target 선택도 필요하다. 기존 다른 Source Interval은 유지하며 일일 전용 실행이 그 다음 실행 시각을 밀지 않는다.

수동 최신 정보 다시 조회는 날짜 Gate 없이 기존 Refresh API로 실행한다. Firewall API 수집 → 기존 Parsing/Normalize → Validation → Search Index 생성 → Snapshot atomic save → 전체 결합 Topology 검증/저장 → Memory generation 교체 → 현재 Query 재분석 순서다. AWS Network Refresh는 기존 설정에 따라 Refresh 경로에서만 수행한다.

한 Firewall/Entity라도 실패하면 전체 새 세대를 공개하지 않고 이전 Memory와 정상 JSON을 유지/복구한다. 실패 사유는 기존 비민감 진단 응답에 보존한다. 기준 시각은 실제 성공 Snapshot checkedAt에서 계산하며 실패 시 변경하지 않는다. 장비별 JSON은 atomic 저장하며 batch 실패는 rollback한다. 여러 파일에 대한 파일시스템 트랜잭션은 아니며 crash 복구는 기존 topology manifest의 snapshot ID 일치 검증을 사용한다.

Backend 재시작은 로컬 JSON/manifest를 검증하고 Index를 재생성한다. 정상 분석은 API/DNS/file reread/idle refresh가 없다. Snapshot이 0개면 즉시 최신 정보 다시 조회 안내를 반환한다.

## 제공 자료 오프라인 시나리오와 성능

전체 Firewall Rule 514개인 제공 Workbook/AWS Cache를 메모리에 준비한 뒤 측정했다. 아래는 같은 개발 환경의 단일 측정이며 HTTP 전송/브라우저 렌더/Index build 시간은 제외한다. 실제 운영 성능 보장은 아니다. API/DNS 메서드를 실패 spy로 대체하여 추가 호출0을 확인했다.

| Query | 첫 조회 | 같은 세대 재조회 | Rule 후보 |
|---|---:|---:|---:|
| PATH TCP50000 | 7.71ms | 0.71ms | 5/514 |
| PATH TCP ANY | 52.10ms | 1.84ms | 5/514 |
| SOURCE_ONLY TCP50000 | 647.03ms | 32.89ms | 58/514 |
| DESTINATION_ONLY TCP50000 | 1255.35ms | 222.99ms | 77/514 |

중간 구현의 첫 단방향 조회는 Source 약7.3초 / Destination 약55초였다. 최종 첫 조회는 약0.65초 /1.26초로 줄었다. 동일 결과 재조회는 세대 cache를 사용하므로 후보 수0/lookup 시간0이 정상이며 cache_hit으로 구분한다.

- Scenario A: 203.236.80.30 → 10.30.1.212 TCP50000은 `New WAN > Po-NLB`, WAN→LAN 정책, DNAT →100.1.2.28, 실제 connected route를 사용하여 PASS. 목표는 Cache의 관리형 NLB ENI이며 instanceId 없는 ENI도 Resolve한다. 명시된 빈 SG 목록은 누락과 구분하여 N/A로 표시한다.
- Scenario B: 같은 주소 TCP ANY는 서비스/실제 경로별로 구간을 보존하여 WARNING. 44300/50000 Allow와 나머지 미확정 결과를 전체 TCP 허용으로 합치지 않는다.
- Scenario C: Synthetic fixture의 명시 Local Service 포트만 Local Endpoint. 제공 자료에 없는 실제 Local Service ACL/포트는 추정하지 않는다.

내부 metrics: endpoint/object/group/service/NAT lookup ms, candidate rule/NAT count, total rule count, policy validation/dynamic path/total ms, cache_hit. debug log 및 응답 metrics에 보관하며 사용자 화면에 개발용 시간/후보 통계를 추가하지 않는다. Frontend는 Backend 실제 Dynamic Step과 서비스 결과를 렌더링하며 새로운 고정 경로를 만들지 않는다.

## 테스트 / Self Review

새 테스트: `test_firewall_published_index.py`(Alias/reference/reverse map, Source/Service 불일치, Transit Drop, NAT/Published 흐름, true Local, ANY, 1000+ noise rule raw scan 금지, 세 가지 mode API/DNS0, 관리형 ENI, no-snapshot 즉시 응답, 세대 cache 격리), `test_firewall_daily_schedule.py`(KST 시각/날짜, Interval 독립, 실패 당일 반복 금지, restart, manual bypass, 다른 Source 예정 시각 유지, 시간 검증).

기존 Dynamic Local fixture에 명시 Local Service 근거를 추가하고 Refresh 실패 테스트는 전체 이전 세대 보존으로 강화했다. 최초 Snapshot 생성 테스트는 유지하며 stage 순서는 Index 검증 후 save로 확인한다.

Self Review에서 수정한 항목: Alias 원본 목적지 손실, Alias Zone 상속, embedded ENI/standalone ENI 중복 생성, 빈 SG와 미수집 구분, ANY 상태가 같아도 경로가 다른 서비스 구간 요약, 큰 객체 반복 복사, 전역 주소 분할, 일일 실행 후 다른 Source 주기 밀림. Local ownership만으로 종료하는 경로와 TTL/idle refresh는 없다. Export/SSM/Launcher 코드는 변경하지 않았다. 추가 Dependency는 없다.

## 변경 파일

- Backend: `firewall_configuration.py`, 신규 `firewall_search_index.py`, `firewall_path_check.py`, `firewall_path_analysis.py`, `firewall_path_decisions.py`, `firewall_packet.py`, `firewall_topology.py`, `firewall_network_mapping.py`, `aws_security_group_path.py`, `settings.py`.
- Frontend: `ConfigPage.tsx`, `FirewallPathCheckPage.tsx`.
- Tests: 신규 `test_firewall_published_index.py`, `test_firewall_daily_schedule.py`; 기존 `test_firewall_dynamic_packet.py`, `test_firewall_configuration.py`, `test_firewall_configuration_bootstrap.py`, `test_firewall_supplied_data.py`.
- Docs: 본 보고서, 현행 정책 링크를 추가한 `firewall-dynamic-packet-flow.md`, `firewall-path-configuration.md`.

## 최종 검증 결과

- 첨부 데이터 opt-in manifest를 포함한 전체 로컬 테스트: **1267 passed, 2 failed**, 90.84초. 새 Alias/Index/일일 Scheduler 및 실제 첨부 데이터 재현 테스트는 통과했다.
- 실패2건은 수정 전에도 재현한 기존 문제: `test_settings_service.py::test_scheduler_runs_every_target_then_index`의 ScheduledIndex mock에 mode 속성 없음, `test_timeline_export.py::test_search_all_is_not_limited_by_timeline_group_item_cap`의 150건 기대/100건 반환. 이번 범위에서 변경하지 않았다.
- Frontend `npm run typecheck`, `npm run build` 통과. 기존 Vite 번들 크기 안내가 남는다.
- `git diff --check` 통과. 커밋/푸시하지 않았다. 실제 운영 수집/통신은 수행하지 않았다.
