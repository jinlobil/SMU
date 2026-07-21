@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title SMU Web

if not exist ".venv\Scripts\python.exe" goto setup
if not exist "web_frontend\dist\index.html" goto setup

echo Starting SMU Web...
echo If the browser does not open, visit http://127.0.0.1:8000
echo Press Ctrl+C in this window to stop the server.
echo Full log: %~dp0logs\web_server.log
".venv\Scripts\python.exe" run_web.py
if errorlevel 1 goto server_failed
exit /b 0

:server_failed
echo.
echo SMU Web stopped with an error.
echo Opening the complete log in Notepad...
if exist "%~dp0logs\web_server.log" start "" notepad "%~dp0logs\web_server.log"
pause
exit /b 1

:setup
echo Initial setup is required. Starting INSTALL_WEB.bat...
call "%~dp0INSTALL_WEB.bat"
