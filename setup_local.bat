@echo off
setlocal EnableExtensions
cd /d "%~dp0"

if not exist "runtime\logs" mkdir "runtime\logs"
set "SETUP_LOG=%~dp0runtime\logs\setup.log"
echo [%date% %time%] SMU setup started>"%SETUP_LOG%"

echo [1/4] Checking the Python virtual environment...
if exist "%~dp0.venv\Scripts\python.exe" goto python_ready

where py.exe >nul 2>&1
if errorlevel 1 goto try_python
echo Creating .venv with the Python launcher...
py.exe -3 -m venv "%~dp0.venv" >>"%SETUP_LOG%" 2>&1
goto check_venv

:try_python
where python.exe >nul 2>&1
if errorlevel 1 goto no_python
echo Creating .venv with python.exe...
python.exe -m venv "%~dp0.venv" >>"%SETUP_LOG%" 2>&1

:check_venv
if not exist "%~dp0.venv\Scripts\python.exe" goto setup_failed

:python_ready
set "VENV_PYTHON=%~dp0.venv\Scripts\python.exe"
echo [2/4] Installing Python packages. This can take a few minutes...
"%VENV_PYTHON%" -m pip install --upgrade pip >>"%SETUP_LOG%" 2>&1
if errorlevel 1 goto setup_failed
"%VENV_PYTHON%" -m pip install -r "%~dp0backend\requirements.txt" >>"%SETUP_LOG%" 2>&1
if errorlevel 1 goto setup_failed

echo [3/4] Checking Node.js and npm...
where npm.cmd >nul 2>&1
if errorlevel 1 goto no_node

echo [4/4] Installing frontend packages. This can take a few minutes...
pushd "%~dp0frontend"
call npm.cmd install >>"%SETUP_LOG%" 2>&1
set "NPM_EXIT=%ERRORLEVEL%"
popd
if not "%NPM_EXIT%"=="0" goto setup_failed

echo [%date% %time%] SMU setup completed>>"%SETUP_LOG%"
echo Setup completed successfully.
exit /b 0

:no_python
echo ERROR: Python 3 was not found. Install Python and enable Add Python to PATH.
echo ERROR: Python not found>>"%SETUP_LOG%"
goto failed

:no_node
echo ERROR: Node.js/npm was not found. Install Node.js LTS.
echo ERROR: npm not found>>"%SETUP_LOG%"
goto failed

:setup_failed
echo ERROR: A setup command failed.

:failed
echo Send this log file: %SETUP_LOG%
echo This window will remain open.
pause
exit /b 1
