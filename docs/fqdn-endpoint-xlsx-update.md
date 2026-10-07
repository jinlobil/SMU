# Firewall FQDN, Endpoint IP, 공통 XLSX 수정

## Path와 SG 표시

main에 병합된 Path 레이아웃과 VPC 판정을 재사용한다. Path의 `overflow:auto`가
내부 스크롤의 원인이었으며, 기존 flex wrap/축소 레이아웃을 그대로 유지한다.
캐시에서 정확히 식별한 ENI VpcId(누락 시 Instance VpcId)를 비교한다.
동일 VPC는 SG Outbound → SG Inbound만 검사하며 Sophos 조회를 삽입하지 않는다.
다른 VPC/누락 VpcId의 중간 경로는 확인 불가다. Static Route는 실제 선택된
Firewall 단계에서만 조회하며, Route 존재로 Cloud 경유를 추정하지 않는다.

IP Query의 SG PASS 표는 `matches` 중 Exact MATCH만 표시한다. FAIL에서는
불일치 평가 목록을 숨기고 `일치하는 Allow Rule 없음`을 표시한다.
UNKNOWN에서는 매칭 후보만 표시한다. Sophos의 허용/차단 근거 Rule 표는 유지한다.

## FQDN 정책과 DNS

Destination은 기존 IP/CIDR 및 일반 FQDN을 지원한다. 호스트 이름은 IDNA,
대소문자, 마지막 root dot를 정규화하고 URL/port/잘못된 IP·label 입력은 거부한다.

기존 Sophos XML 파서가 FQDNHost의 실제 FQDN과 FQDNHostGroup 구성원을 읽어
Rule Destination 객체에 typed FQDN 패턴을 연결한다. 이름이나 표시 문자열만
같다고 매칭하지 않는다. Exact hostname 또는 `*.example.com`의 DNS label
경계로 매칭한다. Wildcard는 하위 도메인에 적용하며 bare apex는 매칭하지 않는다.
기존 Source IP, Protocol/Port, Rule Order, Allow/Drop/Reject 판정은 재사용한다.

DNS는 Network Path/Zone/EC2·ENI 식별 및 Static Route의 보조 정보만 제공한다.
DNS IP를 Firewall의 Destination IP Rule 비교에 대입하지 않는다. DNS 지연은
2초로 제한하고 동시에 대기하는 lookup은 최대 4개다. DNS 실패 또는 여러 대상의
불명확한 경로에서는 확인 불가 상태를 유지한다. Resolve 결과가 없으면 Destination
Zone을 추정하지 않는다. 여러 DNS IP의 AWS 식별 결과가 동일 EC2/ENI로 모이지
않으면 AWS Inbound를 확정하지 않는다.

FQDN SG 검사는 방향·Protocol·Port만 평가한다. Rule의 주소/CIDR/SG Reference는
정확한 허용 근거로 사용하지 않는다. 해당 Port Rule이 있으면 UNKNOWN(화면의
`확인 필요`)과 `Source/Destination 조건은 FQDN 기준으로 판정하지 않음`을 표시한다.
Port Rule이 없고 캐시가 완전하면 FAIL, AWS 대상이 아니면 N/A다. 캐시/DNS 누락은
UNKNOWN이다. Port와 관계없는 Rule은 표에 표시하지 않는다.

## Endpoint

기존 `classify_endpoint_ips()`를 화면과 Endpoint XLSX 모두 사용한다.
CIDR containment와 IP range 비교를 사용하며 raw cache를 수정하지 않는다.

| 분류 | 대역 |
|---|---|
| 유선 | 101.1.0.0/22, 101.3.0.0/24, 101.3.1.1–4, 101.2.1.1–149 |
| 무선 | 101.1.4.0/22, 101.3.1.5–254, 101.2.1.150–250 |
| VPN | 106.1.0.0/16 |
| ZTNA | 100.64.0.1 exact |
| AWS | 100.1.0.0/22, 10.10.0.0/16, 10.20.0.0/16 |
| NCP | 10.0.0.0/16 |
| 기타 | 그 외 및 잘못된 값 |

각 분류의 모든 distinct IP를 보존한다. 화면은 빈 분류를 `-`로 표시하며 XLSX에는
AWS IP/NCP IP 컬럼을 추가하고 나머지 컬럼은 유지한다.

## 공통 XLSX

모든 생성 경로는 기존 `write_xlsx_workbook()`/`write_xlsx()`를 거친다.
Writer의 기본값을 기존 AWS 관리대장 스타일로 통일하고 `semantic_cell_style()`이
실제 상태/Action/Direction/보안 제품 컬럼에만 의미 색상을 지정한다.
이름·설명에 `Fail`, `Sophos` 같은 단어가 있어도 색상을 적용하지 않는다.

- Header: Navy, White Bold, Center, Thin Border, Autofilter, Header Freeze.
- Body: White, Black, Thin Border, Vertical Center, 내용 기반 Column Width.
- 정상/실패: Green/Red Fill + White Bold.
- Sophos: Blue Fill + White Bold.
- Action: Allow/Accept Light Green, Drop/Reject/Deny Light Red + Dark Font.
- Direction: Inbound Light Blue, Outbound Light Orange + Dark Font.

적용 대상: Detection, Email/XDR, Firewall Detection, Inbound Mail, Outbound Mail,
DLP, Timeline, Firewall Rule 및 분석 Sheet, Endpoint, AWS EC2, AWS SG와 공통 Writer를
사용하는 Config/향후 Export.

기존 AWS 전용 색상 우선순위·SG EC2 Mapping merge·그룹 상단 경계는 유지한다.
Timeline은 Summary + 6개 Source의 7 Sheet와 2열 Summary cover 구조를 유지한다.
Summary에도 공통 색상/Border/Freeze를 적용하지만 표가 아니므로 Autofilter는 넣지
않는다. 데이터 처리나 Source별 컬럼은 변경하지 않는다.

## 검증과 제약

FQDN 객체/그룹/Wildcard·Service·DNS 분리·API·SG port-only 검증,
Endpoint 경계 및 화면/Excel 값 일치 검증, 실제 Laborer 6개 Source XLSX 검증,
AWS merge/특수 스타일·Timeline 7 Sheet 회귀 검증을 포함한다.
XLSX ZIP CRC 및 모든 XML/relationships 파싱을 검사한다.
Chromium 1440/1024/390px에서 Path 카드/스크롤과 SG 표시를 검증한다.

AWS Route Table/Peering/TGW/NACL/NAT/Prefix List API나 실제 Ping/TCP는 추가하지
않는다. FQDN 객체를 수집하지 못하면 이름만 보고 FQDN 정책 허용을 추정하지 않는다.
현재 매핑으로 선택되는 Firewall만 검사하며 DNS가 없는 중간 경로를 새로 추측하지
않는다. 실제 패킷 연결성 보장은 하지 않는다.

검증 결과:

- 전체 Python 검사(브라우저 제외): **555 passed**, 기존 실패 2개.
- 관련 Path/FQDN/SG/Endpoint/XLSX 검사: **226 passed**.
- Chromium 레이아웃 및 SG 표시 검사: **5 passed**.
- `npm run typecheck`, `npm run build`: 통과.
- 기존 실패: 스케줄러 `ScheduledIndex.mode` 누락,
  Timeline `search_all`의 150개 기대 대비 100개 반환.
  두 데이터 처리 로직은 이번 요청 범위에 따라 수정하지 않았다.

## 변경 파일

구현:

- `backend/services/fqdn.py`
- `backend/services/firewall_path_check.py`
- `backend/services/firewall_rule_export.py`
- `backend/services/aws_security_group_path.py`
- `backend/services/endpoints.py`
- `backend/services/endpoint_export.py`
- `backend/services/spreadsheet.py`
- `frontend/src/pages/FirewallPathCheckPage.tsx`
- `frontend/src/pages/EndpointPage.tsx`

검증:

- `tests/test_firewall_path_fqdn.py`
- `tests/test_firewall_path_layout_browser.py`
- `tests/test_common_xlsx_style.py`
- `tests/test_endpoint_ip_export.py`
- `tests/test_endpoint_service.py`
- `tests/test_aws_security_group_path.py`
- `tests/test_aws_export_inventory.py`
- `tests/test_firewall_rule_export.py`
- `tests/test_timeline_export.py`

문서: `docs/fqdn-endpoint-xlsx-update.md`.
