@echo off
setlocal EnableExtensions
cd /d "%~dp0"
if not exist "logs\web_server.log" (
    echo No web server log exists yet.
    echo Run START_WEB.bat first.
    pause
    exit /b 1
)
start "" notepad "%~dp0logs\web_server.log"
