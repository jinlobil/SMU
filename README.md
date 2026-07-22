# SMU Local Web Migration

기존 PyQt 애플리케이션을 Python 백엔드와 React/TypeScript 프론트엔드로 단계적으로 이전합니다.

## Windows에서 처음 실행

1. Python 3와 Node.js LTS를 설치합니다.
2. `start_local.bat`을 더블클릭합니다.
3. 첫 실행이면 Python 가상환경과 필요한 패키지를 자동으로 설치합니다.
4. 정상적으로 준비되면 `http://127.0.0.1:5173`이 브라우저에서 자동으로 열립니다.

설치만 다시 실행하려면 `setup_local.bat`을 사용합니다. 설치 상세 출력은 `runtime/logs/setup.log`에 저장됩니다.

## 실행

- Windows: `start_local.bat`
- Linux/macOS: `./start_local.sh`

실행 중 출력은 화면과 `runtime/logs/launcher.log`에 동시에 저장됩니다. 백엔드에서 처리되지 않은 오류는 `runtime/logs/web_errors.log`에 요청 ID와 함께 저장됩니다. 실행 프로세스가 비정상 종료되면 실행 스크립트는 오류 경로를 표시하고 터미널을 즉시 닫지 않습니다.

### 정상 실행 시 확인할 내용

1. 명령 프롬프트에 `Starting backend`, `Starting frontend`가 표시됩니다.
2. `Frontend ready: http://127.0.0.1:5173`이 표시됩니다.
3. 브라우저가 자동으로 열리고 `Python 백엔드 연결 완료`가 표시됩니다.
4. `http://127.0.0.1:8765/api/health`에 접속하면 `status`가 `ok`로 표시됩니다.

Python의 `>>>`만 표시된다면 정상 실행이 아닙니다. Windows CMD가 UTF-8 BAT 내용을 잘못 해석하는 경우를 방지하기 위해 실행 BAT는 ASCII와 Windows CRLF 형식만 사용합니다. 반드시 새 `start_local.bat`을 실행하고, 계속 발생하면 `runtime/logs/bootstrap.log`와 명령 프롬프트 화면을 전달해주세요.

### 오류 발생 시 전달할 파일

- 실행 또는 프로세스 오류: `runtime/logs/launcher.log`
- 최초 설치 오류: `runtime/logs/setup.log`
- BAT 실행 위치 및 시작 오류: `runtime/logs/bootstrap.log`
- 백엔드 API 오류: `runtime/logs/web_errors.log`
- 백엔드 전체 요청 기록: `runtime/logs/web_app.log`

프론트엔드에서 처리되지 않은 JavaScript 오류도 `/api/client-errors`를 통해 백엔드의 `web_errors.log`에 자동 저장됩니다.

## 현재 범위

- FastAPI 상태 확인 API: `GET /api/health`
- Endpoint 조회 API: `GET /api/endpoints`
- Endpoint 검색, 정렬, 페이지 이동 웹 화면
- Organization 조회 API: `GET /api/organizations`
- Asset 하위 메뉴와 Organization 검색, 정렬, 페이지 이동 화면
- Endpoint·Organization Sophos 백그라운드 새로고침 Job API와 진행 상태
- 요청별 ID와 영구 오류 로그
- React/TypeScript 연결 상태 화면
- 백엔드와 프론트엔드를 함께 감시하는 로컬 실행기

### Endpoint 화면 확인

1. 기존 데스크톱 앱과 동일한 프로젝트 경로의 `cache/endpoints.json`을 사용합니다.
2. 왼쪽 메뉴에서 `Asset`이 선택되고 `Endpoint` 목록이 표시되어야 합니다.
3. 검색 조건을 선택하고 검색어를 입력하면 250ms 후 결과가 갱신되어야 합니다.
4. 표 머리글을 누르면 오름차순·내림차순 정렬이 변경되어야 합니다.
5. 데이터가 50개를 넘으면 `이전`과 `다음` 버튼으로 페이지를 이동할 수 있어야 합니다.

캐시가 없으면 오류로 종료하지 않고 `아직 Endpoint 캐시가 없습니다` 안내가 표시됩니다.

### Organization 화면 확인

1. `Asset` 아래의 `Organization`을 선택합니다.
2. `cache/user_groups.json`의 부서별 사용자가 한 행씩 표시되어야 합니다.
3. 전체, DeptCode, DeptName, User 검색과 표 머리글 정렬이 동작해야 합니다.
4. `env/User_group_env.txt`에 부서 코드 매핑이 있으면 매핑된 부서명이 표시되어야 합니다.

각 Asset 화면의 `Sophos 새로고침` 버튼은 백그라운드 작업을 생성합니다. Endpoint는 `cache/endpoints.json`, Organization은 `cache/user_groups.json`과 `cache/users.json`을 안전하게 교체하며, 완료되면 화면이 자동으로 다시 조회됩니다. 실패하면 버튼 옆에 오류 안내가 표시되고 상세 예외는 `runtime/logs/web_errors.log`에 저장됩니다.

`start_local.bat`은 백엔드 의존성 누락도 검사하고 필요한 경우 자동 설치를 다시 실행합니다.

다른 상위 메뉴는 아직 데이터 화면이 구현되지 않았으며, 클릭하면 `마이그레이션 진행 예정` 안내가 표시되는 것이 정상입니다. 다음 단계에서는 Detection 메뉴와 첫 Detection 조회 화면을 연결합니다.

### Endpoint 컨텍스트 메뉴와 상세 정보

- IP 셀을 마우스 오른쪽 버튼으로 누르면 각 IP의 `복사`, `VirusTotal` 버튼과 `View Raw Detail`이 표시됩니다.
- 한 셀에 IP가 여러 개면 IP별로 분리된 작업 버튼이 표시됩니다.
- Endpoint 행을 더블클릭해도 Raw Detail 창이 열립니다.
- 상세 데이터는 `GET /api/endpoints/{endpointId}`에서 현재 캐시 행을 가져오므로 브라우저 목록 응답에 전체 Raw 데이터를 포함하지 않습니다.
