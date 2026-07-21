@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
title SMU Web 설치 및 실행

echo.
echo ================================================
echo   SMU Web - 최초 설치 및 실행
echo ================================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo [오류] Python을 찾을 수 없습니다.
    echo https://www.python.org/downloads/ 에서 Python 3.11 이상을 설치하세요.
    echo 설치 화면에서 "Add python.exe to PATH"를 반드시 체크하세요.
    pause
    exit /b 1
)

where npm >nul 2>nul
if errorlevel 1 (
    echo [오류] Node.js를 찾을 수 없습니다.
    echo https://nodejs.org/ 에서 LTS 버전을 설치한 뒤 이 파일을 다시 실행하세요.
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo [1/4] Python 전용 환경을 생성합니다...
    python -m venv .venv || goto :failed
) else (
    echo [1/4] 기존 Python 환경을 사용합니다.
)

echo [2/4] Python 웹 모듈을 설치합니다...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements-web.txt || goto :failed

echo [3/4] 웹 화면 모듈을 설치합니다...
call npm --prefix web_frontend install || goto :failed

echo [4/4] 웹 화면을 빌드합니다...
call npm --prefix web_frontend run build || goto :failed

echo.
echo 설치가 완료되었습니다. SMU Web을 시작합니다.
echo 다음 실행부터는 "SMU_WEB_실행.bat"만 더블클릭하세요.
echo.
".venv\Scripts\python.exe" run_web.py
exit /b 0

:failed
echo.
echo [실패] 설치 중 오류가 발생했습니다. 위 오류 메시지를 확인하세요.
pause
exit /b 1
