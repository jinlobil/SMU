# SMU Local Web Migration

기존 PyQt 애플리케이션을 Python 백엔드와 React/TypeScript 프론트엔드로 단계적으로 이전합니다.

## 개발 환경 준비

```bash
python -m venv .venv
.venv/bin/pip install -r backend/requirements.txt
cd frontend && npm install
```

Windows에서는 `.venv\\Scripts\\pip`을 사용합니다.

## 실행

- Windows: `start_local.bat`
- Linux/macOS: `./start_local.sh`

실행 중 출력은 화면과 `runtime/logs/launcher.log`에 동시에 저장됩니다. 백엔드에서 처리되지 않은 오류는 `runtime/logs/web_errors.log`에 요청 ID와 함께 저장됩니다. 실행 프로세스가 비정상 종료되면 실행 스크립트는 오류 경로를 표시하고 터미널을 즉시 닫지 않습니다.

## 현재 범위

- FastAPI 상태 확인 API: `GET /api/health`
- 요청별 ID와 영구 오류 로그
- React/TypeScript 연결 상태 화면
- 백엔드와 프론트엔드를 함께 감시하는 로컬 실행기

다음 단계에서는 기존 Endpoint 조회 로직을 Python 서비스로 분리하고 첫 실제 데이터 API와 화면을 연결합니다.
