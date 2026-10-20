# Source FQDN / Endpoint Protector CAP API

## 원인

Network Path는 Destination만 FQDN normalize/DNS/typed object matching을 지원했다.
Source는 IP/CIDR 검증에서 거부했고 Firewall rule에는 Destination FQDN metadata만 있었다.

DLP는 구버전 cf_log/list, 컬럼 번호 기반 날짜 조건과 filename/filesize 등의 필드를 사용했다.
신규 CAP의 file_name/file_size/event_time_local 등을 그대로 저장하면 기존 소비자가 값을 찾지 못했다.
또 첫 응답의 recordsFiltered보다 수신 행이 적어도 일부 데이터로 완료하던 pagination 문제가 있었다.

## Source FQDN

Source/Destination의 입력 해석과 typed FQDN address matching을 공통 helper로 재사용한다.
기존 normalize_fqdn/resolve_fqdn/fqdn_matches와 FQDNHost/Group 해석을 사용한다.
FQDN은 소문자/IDNA/trailing dot 정규화, exact/domain wildcard 경계 매칭을 적용한다.
Source에도 _Source FQDNs metadata를 붙여 실제 FQDN Host/Group과 Any 정책을 평가한다.
기존 IP/CIDR은 기존 address_match_details 경로를 유지한다.

DNS 응답은 resolvedIps 전체를 반환한다. 1개이면 경로/정적 route 분류에 사용하고,
여러 개거나 미확인인 경우 한 주소를 임의 선택하지 않으며 partial/unknown으로 남긴다.
AWS Endpoint 확인도 모든 Source DNS 주소를 검사하여 여러 서로 다른 대상이면 UNKNOWN이다.
Destination의 기존 FQDN 동작과 같이 FQDN 조회의 SG 결과는 주소 조건을 확정하지 않는
protocol/port 후보 판정이며 임의로 PASS를 만들지 않는다.
Sophos FQDN 정책도 DNS 주소를 IP 정책 허용 근거로 대체하지 않고 typed 객체로 판단한다.

UI는 Source 라벨만 IP / CIDR / FQDN으로 확장했다. 기존 컴포넌트/스타일을 그대로 사용한다.

## CAP 요청

기본 경로는 POST /index.php/cap_logs_crate/list다.
기존 DlpClient 메서드명/호출 인터페이스는 유지하고 내부 요청 module만 선택한다.
startDate/endDate는 Client Local Date 문자열을 그대로 보낸다. 날짜/UTC 변환은 하지 않는다.
하루 기본 범위는 00:00:00~23:59:59로 끝 분/초도 포함한다. 명시적인 start_dt/end_dt는 그대로 사용한다.
startServerDate/endServerDate/startClientUtcDate/endClientUtcDate 및 날짜용 컬럼 인덱스는 CAP에서 사용하지 않는다.
사용자가 제공한 23개 DataTables 컬럼, order column=2 desc, start/length를 사용한다.

recordsTotal/recordsFiltered를 읽고 data 배열을 수집한다.
첫 전체 요청이 일부만 반환하면 같은 module에서 500개 pagination으로 수집한다.
서버가 요청한 length보다 적은 행을 반환해도 실제 받은 행 수로 start를 증가시킨다.
중간 빈 페이지/고유 레코드 부족은 오류로 처리하여 불완전한 결과를 정상 Cache로 덮어쓰지 않는다.
_id를 우선으로 중복 제거하고 기존 loclogid 등 구버전 ID도 지원한다.
새 API 오류를 cf_log 조회로 바꾸어 숨기지 않는다. 기존 timeout retry도 같은 module에서만 한다.

## 필드와 구버전 호환

신규 원본 필드를 모두 보존하고 아래 별칭을 함께 제공한다. 0/false도 값으로 보존한다.
신규 필드가 존재하면 오래된 별칭보다 우선하며 원본 dict를 변형하지 않는다.

| 신규 | 기존 소비자 별칭 |
|---|---|
| event_time_local | eventtimelocal |
| client_time_utc | eventtime |
| file_name / file_size / file_hash | filename / filesize / filehash |
| destination_details | destinationDetails |
| email_sender / email_subject | emailSender / emailSubject |
| serial_no | serialno |
| shadow_exists / shadow_is_deleted | shadowExists / is_deleted |
| repository_type | repositoryType |
| loc_log_id | loclogid |
| os_type | os_value |

machine_name/client_name/destination/destination_type 등 같은 이름의 필드도 원본으로 유지한다.
표시/보고서는 숫자 event_id보다 event_name을 우선 사용하되 event_id 자체는 보존한다.
file_size=0도 화면에서 None으로 바꾸지 않는다. destination_details는 새 상세 필드로 우선 표시한다.
JSONL 수집 시, 기존 raw Cache의 화면/인덱스 읽기 시, 보고서 raw loader에서 동일한 변환을 사용한다.
기존 통계/검색/Timeline/XLSX는 기존 TransferService/Index 경로를 재사용한다.
이미 만들어진 과거 인덱스는 기존 인덱스 갱신 기능으로 재생성해야 할 수 있다.

기본은 CAP이다. 구버전 서버가 필요할 때만 env/DLP_env.txt에 DLP_LOG_MODULE=cf_log를
명시하면 기존 요청 builder/endpoint를 사용한다. 이 설정은 기존 연동 화면에서 다른 값을 저장할 때도 보존한다. 설정이 없으면 CAP이며 자동 Legacy fallback은 없다.
로그인/session/인증정보 처리 방식은 변경하지 않았다. 운영 Endpoint Protector에는 접속하지 않았다.

## 변경 파일

- backend/services/fqdn.py: Source 오류 문맥을 지원하는 공통 normalize
- backend/services/firewall_path_check.py: 양측 입력/정책 helper와 Source FQDN 경로
- backend/services/firewall_rule_export.py: Source typed FQDN metadata
- backend/services/aws_security_group_path.py: Source DNS 전체의 Endpoint 확인 및 보수적 SG 결과
- frontend/src/pages/FirewallPathCheckPage.tsx: 기존 Source 입력 라벨 확장
- backend/clients/legacy_collectors.py: CAP 기본 요청/Legacy 명시 설정/필드 변환/pagination
- backend/services/integrations.py: 기존 연동 설정 저장 시 명시된 Legacy module 보존
- backend/services/dlp_fields.py: lossless 신규 필드 및 구버전 별칭
- backend/services/transfers.py: Cache 읽기/표시/0 값 처리
- backend/services/report.py, backend/services/legacy_report.py: 보고서 raw 및 이벤트 표시 호환
- tests/test_firewall_source_fqdn.py: Source IP/CIDR/FQDN/Host/Group/wildcard/DNS/API/SG/브라우저
- tests/test_dlp_cap_api.py: 요청/응답/날짜/필드/구버전/짧은 페이지/원본 Cache/검색/통계/XLSX/보고서
- docs/source-fqdn-dlp-cap.md

## 로컬 검증과 운영 확인

관련 테스트 결과는 아래 최종 검증 기록을 참조한다. npm run typecheck 및 npm run build 통과.
Chromium으로 Source FQDN 입력/전송을 확인했으며 모든 API는 mock했다.
로컬 환경에서 기존 backend/requirements.txt에 명시된 msoffcrypto-tool 6.0.0을 설치했고
브라우저 검사용 Playwright를 보완했다. 프로젝트의 production dependency는 추가하지 않았다.

실제 운영에서는 신규 로그인/session과 CAP 조회 권한, Client Local Date 범위 해석,
해당 서버의 pagination/실제 필드, Sophos의 FQDN 객체 및 실제 DNS 결과를 확인해야 한다.
운영 요청/인증정보/쿠키를 코드에 넣지 않았다.

최종 검증:
- 관련 기능/연동/브라우저/보고서 테스트: 208 passed (2.89s).
- 전체 로컬 pytest (Chromium 포함, skip 없음): 747 passed, 2 failed (33.44s).
- 실패 2개는 기존 ScheduledIndex.mode 테스트 대역 누락과 Timeline 기대 150/실제 100 불일치로 동일하다.
- npm run typecheck, npm run build, git diff --check 통과. 기존 Vite 큰 chunk 경고는 유지된다.
- MailScreenClient는 변경 전 HEAD와 AST가 동일함을 확인했다.
- 운영 Endpoint Protector 접속 없음. 프로젝트 Python dependency 추가 없음.
