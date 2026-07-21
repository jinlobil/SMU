@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title SMU Web Setup

echo.
echo ================================================
echo   SMU Web - automatic setup
echo ================================================
echo.

where python >nul 2>nul
if errorlevel 1 goto no_python

where npm >nul 2>nul
if errorlevel 1 goto install_node
goto install_smu

:install_node
echo Node.js LTS was not found. Trying automatic installation...
where winget >nul 2>nul
if errorlevel 1 goto no_node_installer
winget install --id OpenJS.NodeJS.LTS --exact --accept-package-agreements --accept-source-agreements
if errorlevel 1 goto node_failed
echo.
echo Node.js was installed successfully.
echo Close this window, then double-click INSTALL_WEB.bat again.
pause
exit /b 0

:install_smu
if not exist ".venv\Scripts\python.exe" (
    echo [1/5] Creating a private Python environment...
    python -m venv .venv || goto failed
) else (
    echo [1/5] Using the existing Python environment.
)

echo [2/5] Installing Python web packages...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements-web.txt || goto failed

echo [3/5] Installing React packages...
call npm --prefix web_frontend install || goto failed

echo [4/5] Building the React interface...
call npm --prefix web_frontend run build || goto failed

echo [5/5] Checking the complete web application...
".venv\Scripts\python.exe" run_web.py --check || goto failed

echo.
echo Setup completed. Starting SMU Web now.
echo Use START_WEB.bat next time.
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

:no_python
echo Python was not found or is not available on PATH.
echo Install Python 3.11 or later from the page that will open now.
echo IMPORTANT: Check "Add python.exe to PATH" during installation.
start "" "https://www.python.org/downloads/windows/"
pause
exit /b 1

:no_node_installer
echo Node.js and Windows Package Manager were not found.
echo Install the Node.js LTS version from the page that will open now.
start "" "https://nodejs.org/en/download"
pause
exit /b 1

:node_failed
echo Automatic Node.js installation failed.
echo Install the Node.js LTS version from the page that will open now.
start "" "https://nodejs.org/en/download"
pause
exit /b 1

:failed
echo.
echo Setup failed. Review the error shown above.
pause
exit /b 1
