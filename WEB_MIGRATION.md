# SMU 로컬 웹 실행 방법

## 사용자가 다운로드하고 실행할 파일

1. 이 변경사항이 `main`에 병합된 뒤 GitHub 저장소 오른쪽 위의 **Code**
   버튼을 누릅니다. 병합 전 시험하려면 왼쪽 위 브랜치 선택에서 이 PR의
   브랜치를 선택합니다.
2. **Download ZIP**을 누르고, 받은 ZIP 파일의 압축을 풉니다.
3. 기존 SMU에서 사용하던 `env`와 `cache` 폴더가 따로 있다면 압축을 푼
   SMU 폴더 안에 그대로 복사합니다.
4. 최초 한 번만 **`INSTALL_WEB.bat`**을 더블클릭합니다.
5. 이후에는 **`START_WEB.bat`**만 더블클릭합니다.

> ZIP 안에 `INSTALL_WEB.bat`과 `START_WEB.bat`이 보이지 않는다면 이전
> `main` ZIP을 받은 것입니다. 이번 PR이 병합된 후 다시 Download ZIP을
> 하거나, GitHub 왼쪽 위 브랜치 메뉴에서 이번 PR 브랜치를 선택해 받으세요.

> 설치창에 `is not recognized as an internal or external command`가 반복되면
> 한글이 포함된 이전 배치 파일의 Windows 문자 인코딩 문제입니다. 새 ZIP의
> **영문 파일 `INSTALL_WEB.bat`**을 실행하세요. 이 파일은 Windows 버전과
> 코드 페이지에 상관없이 해석되도록 실행 내용 전체를 ASCII로 작성했습니다.

최초 설치에는 **Python 3.11 이상**과 **Node.js LTS**가 필요합니다.
`INSTALL_WEB.bat`은 Node.js가 없으면 Windows의 `winget`으로 LTS 버전을
자동 설치합니다. 자동 설치 후 창을 닫고 `INSTALL_WEB.bat`을 한 번 더
실행하면 됩니다. `winget`도 없는 PC에서는 Node.js 한국어 다운로드 페이지를
자동으로 열어 줍니다. 설치 파일은 전용 `.venv`를 만들고 Python/웹 패키지를
설치한 다음 React 화면을 빌드하고 브라우저를 자동으로 엽니다. 평소 실행 주소는
`http://127.0.0.1:8000`입니다.

> `env` 폴더에는 API 연결 설정이 들어 있으므로 GitHub에 올리지 말고 기존
> PC에서만 복사해서 사용하세요. 기존 데이터까지 유지하려면 `cache` 폴더도
> 함께 복사하세요.

## 개발자 참고

The web application is a local-only replacement shell for the PyQt UI. Existing
JSON/JSONL caches, SQLite read models, theme files, and Python business logic are
reused. The legacy UI remains available during functional-parity migration.

## Development

```bash
python -m pip install -r requirements-web.txt
cd web_frontend && npm install && npm run build && cd ..
python run_web.py
```

Open `http://127.0.0.1:8000`. The server deliberately binds only to the loopback
interface. Interactive API documentation is available at `/api/docs`.

## Architecture

* `web_backend/`: FastAPI facade around reusable Python storage and services.
* `web_frontend/`: React/TypeScript user interface with motion and responsive data views.
* `run_web.py`: single local launcher that opens the default browser.
* `uimain_window.py`: retained as the functional reference while parity is verified.

The API performs filtering and pagination before returning records so large local
datasets do not block browser rendering. Long-running indexing is represented as
a background job and can be polled without freezing the interface.
