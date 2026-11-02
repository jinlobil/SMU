# SSM Runtime/Platform 필드 확장

## 기존 흐름 감사

LNL-ServerInventory → GetCommandInvocation → parse_inventory → SsmInventoryCollector.collect
→ RefreshService의 기존 atomic save → cache/aws.json.ssm_inventory.instances[InstanceId] 경로다.
플랫폼 필드를 받을 별도 DB/ORM/response model은 없다.

기존 웹에는 전체 SSM 상태만 있었고 AWS Instance Detail은 EC2 원본/SG만 제공했다.
WAS/WEB/DB가 표시되던 기존 소비자는 Excel이었다. 따라서 기존 웹 테이블을 변경하는 대신
인스턴스 상세 모달에 Cache 기반 SSM 정보를 연결했다. 별도 Inventory 화면/API/디자인은 만들지 않았다.

## 변경 파일과 내용

- backend/services/ssm_inventory.py: parse_inventory의 scalar 필드에 was_platform/web_platform/db_platform 추가.
  기존 WAS/WEB/DB 반복 제품 레코드, 필수 key 검사, 로그, SSM 호출/step/retry/Gate는 변경하지 않았다.
- backend/services/aws_assets.py: AwsAssetService.detail에서 Instance ID로 해당 SSM Cache 레코드를 연결해
  기존 detail 응답에 ssmInventory를 추가한다. 기존 instance/SG/ENI 필드는 그대로다.
  레코드/신규 필드가 없는 Cache에도 세 필드를 null로 반환하며 Cache를 수정하지 않는다.
- frontend/src/pages/AwsAssetPage.tsx: 기존 AWS Instance Detail 모달에 Server Inventory (SSM) 표시.
  기존 table-wrap/table/status-pill을 재사용하고 CSS 파일/색상/디자인은 추가하지 않았다.
  내용 증가로 기존 overflow:hidden에 잘리지 않도록 해당 모달의 overflowY만 auto로 지정했다.
  제품은 종류/Product/Version/Path/Status로 표시하고 세 Platform은 별도 항목으로 표시한다.
- tests/test_ssm_platform_fields.py: 요청의 4가지 출력, 복수 Runtime, None/구버전,
  stale/Gate/force, 실제 atomic Refresh, Cache-only API와 legacy Cache 검증.
- tests/test_ssm_platform_browser.py: Chromium에서 신규/구버전 상세 모달, 복수 제품,
  문자열 보존, '-' 기본값, stale 표시, 기존 SG/원본 표시 검증.
- docs/ssm-platform-fields.md: 분석/호환성/검증 기록.

## Parser 및 저장 계약

신규 KV key는 WAS_PLATFORM / WEB_PLATFORM / DB_PLATFORM이다.
내부 Cache 레코드는 기존 snake_case convention으로 was_platform/web_platform/db_platform을 사용한다.
기존 partition('=') scalar 처리로 한 줄 전체를 받으며 세미콜론/제품명/버전을 재해석하지 않는다.
예를 들어 PHP 5.1.4; Node.js 20.18.0은 정확히 그 문자열로 저장한다.
기존 scalar normalization과 동일하게 바깥 공백을 정리하고 None/unknown/N/A/빈 값은 null이다.
BOM/CRLF 처리는 기존과 같다. 제품 배열과 Runtime 문자열을 서로 추론/조합하지 않는다.

Cache 예시 (기존 레코드 필드에 추가):

```json
{
  "was_platform": "Java 1.8.0_131; Java 17.0.12",
  "web_platform": null,
  "db_platform": "ASE 16.0.03.03"
}
```

성공한 parse dict를 그대로 직렬화하는 기존 구조여서 Refresh serialization/schema 변경은 필요 없다.
실패 시 기존 _failed 경로가 레코드를 유지하므로 신규 필드도 stale 상태에서 보존된다.
기존 Cache 파일을 초기화/삭제하거나 읽을 때 필드를 채워 다시 저장하지 않는다.
DB schema/migration 및 새 Python dependency는 없다.

## API / UI

GET /api/aws/instances/{instance_id}의 data.ssmInventory에 기존 SSM 필드와 신규 세 필드가 들어간다.
API 바깥 객체 키는 attachedSecurityGroups 등과 동일한 camelCase이며, Cache 레코드 필드는
기존 SSM snake_case를 유지한다. 인스턴스 목록/API 및 /api/aws/ssm-inventory 상태 응답은 변경하지 않는다.
조회는 Cache만 읽으며 AWS/SSM/Sophos API를 호출하지 않는다.

AWS Asset 목록에서 인스턴스 상세를 열면 기존 SG/EC2 원본 앞에 SSM 정보가 표시된다.
Hostname/OS/Kernel/설치일과 WAS Platform/WEB Platform/DB Platform을 표시하고,
WAS/WEB/DB 제품은 버전/경로/상태를 잃지 않도록 별도 제품 테이블로 표시한다.
미수집/구버전/null은 '-'로 표시하며 stale 정상 데이터는 '이전 정상 수집 데이터'로 표시한다.

## 범위와 운영 확인

운영 SSM Document 자체, SendCommand/PluginName/25초 grace/Throttling retry,
Asia/Seoul 일 1회/force 정책은 변경하지 않았다. 운영 AWS 호출도 하지 않는다.
이번 요청은 웹 표시까지의 확장으로, Excel 컬럼과 기존 DB Platform 계산은 변경하지 않았다.
기존 Excel Sheet/Style/소비 동작은 회귀 테스트로 확인한다.

운영에서는 새 필드가 실제 stdout에 포함되는지 기존 SSM 전용 강제 갱신 후 확인하면 된다.
당일 자동 시도 이력이 있으면 일반 Scheduler가 다시 실행하지 않는 기존 정책은 유지된다.
구버전 Cache에 플랫폼 데이터가 없으면 수집 전까지 '-'로 표시한다.

## 검증 결과

- 요청 Case 1~4, 복수 Runtime 문자열, None/빈 값/구버전 출력, stale 및 일자 Gate,
  기존 atomic JSON 저장, Cache-only 인스턴스 API, 신규/구버전 Chromium 표시·스크롤 검증.
- 관련 SSM/AWS/Excel/브라우저: 124 passed (9.21s).
- 전체 로컬 pytest (Chromium 포함, skip 없음): 764 passed, 2 failed (39.59s).
- 기존 실패 2개: test_scheduler_runs_every_target_then_index의 ScheduledIndex.mode 누락,
  test_search_all_is_not_limited_by_timeline_group_item_cap의 기대 150/실제 100 불일치.
- npm run typecheck, npm run build, git diff --check 통과. 기존 Vite 큰 chunk 경고는 유지된다.
- 운영 AWS 호출, Document 변경, Cache 초기화는 하지 않았다.
