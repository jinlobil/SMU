@echo off
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0"

if not exist "runtime\logs" mkdir "runtime\logs"
set "SETUP_LOG=%~dp0runtime\logs\setup.log"
echo [%date% %time%] SMU setup started>"%SETUP_LOG%"

echo [1/4] Python 가상환경을 확인합니다.
if exist ".venv\Scripts\python.exe" goto python_ready

where py >nul 2>&1
if not errorlevel 1 (
  echo Python Launcher로 .venv를 생성합니다.
  py -3 -m venv ".venv" >>"%SETUP_LOG%" 2>&1
) else (
  where python >nul 2>&1
  if errorlevel 1 goto no_python
  echo python 명령으로 .venv를 생성합니다.
  python -m venv ".venv" >>"%SETUP_LOG%" 2>&1
)
if not exist ".venv\Scripts\python.exe" goto setup_failed

:python_ready
set "VENV_PYTHON=%~dp0.venv\Scripts\python.exe"

echo [2/4] Python 패키지를 설치합니다. 처음에는 시간이 걸릴 수 있습니다.
"%VENV_PYTHON%" -m pip install --upgrade pip >>"%SETUP_LOG%" 2>&1
if errorlevel 1 goto setup_failed
"%VENV_PYTHON%" -m pip install -r "backend\requirements.txt" >>"%SETUP_LOG%" 2>&1
if errorlevel 1 goto setup_failed

echo [3/4] Node.js와 npm을 확인합니다.
where npm.cmd >nul 2>&1
if errorlevel 1 goto no_node

echo [4/4] 프론트엔드 패키지를 설치합니다. 처음에는 시간이 걸릴 수 있습니다.
pushd "frontend"
call npm.cmd install >>"%SETUP_LOG%" 2>&1
set "NPM_EXIT=%ERRORLEVEL%"
popd
if not "%NPM_EXIT%"=="0" goto setup_failed

echo [%date% %time%] SMU setup completed>>"%SETUP_LOG%"
echo.
echo 설치가 완료되었습니다.
exit /b 0

:no_python
echo ERROR: Python 3을 찾지 못했습니다. Python 설치 시 Add Python to PATH를 선택해주세요.
echo ERROR: Python not found>>"%SETUP_LOG%"
goto failed

:no_node
echo ERROR: Node.js/npm을 찾지 못했습니다. Node.js LTS를 설치해주세요.
echo ERROR: npm not found>>"%SETUP_LOG%"
goto failed

:setup_failed
echo ERROR: 설치 명령이 실패했습니다. 아래 로그를 전달해주세요.

:failed
echo %SETUP_LOG%
echo 이 창은 자동으로 닫히지 않습니다.
pause
exit /b 1

