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

Python의 `>>>`만 표시된다면 정상 실행이 아닙니다. 반드시 `start_local.bat`을 실행하고, 계속 발생하면 `runtime/logs/bootstrap.log`와 명령 프롬프트 화면을 전달해주세요.

### 오류 발생 시 전달할 파일

- 실행 또는 프로세스 오류: `runtime/logs/launcher.log`
- 최초 설치 오류: `runtime/logs/setup.log`
- BAT 실행 위치 및 시작 오류: `runtime/logs/bootstrap.log`
- 백엔드 API 오류: `runtime/logs/web_errors.log`
- 백엔드 전체 요청 기록: `runtime/logs/web_app.log`

## 현재 범위

- FastAPI 상태 확인 API: `GET /api/health`
- 요청별 ID와 영구 오류 로그
- React/TypeScript 연결 상태 화면
- 백엔드와 프론트엔드를 함께 감시하는 로컬 실행기

다음 단계에서는 기존 Endpoint 조회 로직을 Python 서비스로 분리하고 첫 실제 데이터 API와 화면을 연결합니다.
