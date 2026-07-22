@echo off
setlocal EnableExtensions
cd /d "%~dp0"

if not exist "runtime\logs" mkdir "runtime\logs"
set "BOOT_LOG=%~dp0runtime\logs\bootstrap.log"
echo [%date% %time%] start_local.bat launched>"%BOOT_LOG%"
echo Preparing SMU Local Web...
echo Project: %~dp0
echo Bootstrap log: %BOOT_LOG%
echo.

if not exist "%~dp0run_local.py" goto missing_launcher
if not exist "%~dp0.venv\Scripts\python.exe" goto run_setup
if not exist "%~dp0frontend\node_modules" goto run_setup
goto launch

:run_setup
echo First-run setup is required.
call "%~dp0setup_local.bat"
if errorlevel 1 goto failed

:launch
echo Starting backend and frontend...
echo The browser will open at http://127.0.0.1:5173 when ready.
echo.
"%~dp0.venv\Scripts\python.exe" "%~dp0run_local.py"
if errorlevel 1 goto failed
exit /b 0

:missing_launcher
echo ERROR: run_local.py was not found.
echo ERROR: run_local.py missing>>"%BOOT_LOG%"
goto failed

:failed
echo.
echo ERROR: Setup or startup failed.
echo Send every file in: %~dp0runtime\logs
echo This window will remain open.
pause
exit /b 1
