@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
title SMU Web

if not exist ".venv\Scripts\python.exe" goto :setup
if not exist "web_frontend\dist\index.html" goto :setup

echo SMU Web을 시작합니다.
echo 브라우저가 자동으로 열리지 않으면 http://127.0.0.1:8000 을 여세요.
echo 종료하려면 이 창에서 Ctrl+C를 누르세요.
".venv\Scripts\python.exe" run_web.py
exit /b %errorlevel%

:setup
echo 최초 설치가 필요합니다. 설치 파일을 실행합니다.
call "%~dp0SMU_WEB_설치_및_실행.bat"
