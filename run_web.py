from __future__ import annotations

import threading
import webbrowser
from pathlib import Path

def main() -> None:
    frontend = Path(__file__).resolve().parent / "web_frontend" / "dist" / "index.html"
    if not frontend.exists():
        raise SystemExit(
            "웹 화면이 아직 설치되지 않았습니다. Windows에서는 "
            "SMU_WEB_설치_및_실행.bat을 먼저 실행하세요."
        )
    import uvicorn

    url = "http://127.0.0.1:8000"
    threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    uvicorn.run("web_backend.app:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    main()
