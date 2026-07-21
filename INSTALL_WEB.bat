@echo off
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0"
title SMU Web Setup

echo.
echo ================================================
echo   SMU Web - automatic setup
echo ================================================
echo.

where python >nul 2>nul
if errorlevel 1 goto :no_python

where npm >nul 2>nul
if errorlevel 1 goto :install_node
goto :install_smu

:install_node
echo [안내] Node.js LTS가 없어 자동 설치를 시도합니다.
where winget >nul 2>nul
if errorlevel 1 goto :no_node_installer
winget install --id OpenJS.NodeJS.LTS --exact --accept-package-agreements --accept-source-agreements
if errorlevel 1 goto :node_failed
echo.
echo Node.js 설치가 완료되었습니다.
echo Windows가 새 PATH를 적용하도록 이 창을 닫은 뒤
echo INSTALL_WEB.bat을 다시 더블클릭해 주세요.
pause
exit /b 0

:install_smu
if not exist ".venv\Scripts\python.exe" (
    echo [1/4] Python 전용 환경을 생성합니다...
    python -m venv .venv || goto :failed
) else (
    echo [1/4] 기존 Python 환경을 사용합니다.
)

echo [2/4] Python 웹 모듈을 설치합니다...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements-web.txt || goto :failed

echo [3/4] React 웹 모듈을 설치합니다...
call npm --prefix web_frontend install || goto :failed

echo [4/4] React 웹 화면을 빌드합니다...
call npm --prefix web_frontend run build || goto :failed

echo.
echo 설치가 완료되었습니다.
echo 다음부터 START_WEB.bat만 더블클릭하면 됩니다.
echo 지금 SMU Web을 시작합니다.
".venv\Scripts\python.exe" run_web.py
exit /b %errorlevel%

:no_python
echo [오류] Python이 설치되어 있지 않거나 PATH에 등록되지 않았습니다.
echo 아래 페이지에서 Python 3.11 이상을 설치하세요.
echo https://www.python.org/downloads/windows/
echo 설치 첫 화면의 "Add python.exe to PATH"를 반드시 체크하세요.
start "" "https://www.python.org/downloads/windows/"
pause
exit /b 1

:no_node_installer
echo [오류] Node.js와 winget을 찾을 수 없습니다.
echo 지금 열리는 페이지에서 LTS 버튼을 눌러 설치한 뒤 이 파일을 다시 실행하세요.
start "" "https://nodejs.org/ko/download"
pause
exit /b 1

:node_failed
echo [오류] Node.js 자동 설치가 실패했습니다.
echo 지금 열리는 페이지에서 LTS를 직접 설치한 뒤 이 파일을 다시 실행하세요.
start "" "https://nodejs.org/ko/download"
pause
exit /b 1

:failed
echo.
echo [실패] 설치 중 오류가 발생했습니다. 위 오류 메시지를 확인하세요.
pause
exit /b 1
