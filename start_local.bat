@echo off
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0"

if not exist "runtime\logs" mkdir "runtime\logs"
set "BOOT_LOG=%~dp0runtime\logs\bootstrap.log"
echo [%date% %time%] start_local.bat launched>"%BOOT_LOG%"
echo SMU 로컬 웹 실행을 준비합니다.
echo 실행 위치: %~dp0
echo 부트스트랩 로그: %BOOT_LOG%
echo.

if not exist "run_local.py" (
  echo ERROR: run_local.py가 없습니다. 압축을 다시 풀거나 저장소 위치를 확인해주세요.
  echo ERROR: run_local.py missing>>"%BOOT_LOG%"
  goto failed
)

if not exist ".venv\Scripts\python.exe" (
  echo 최초 실행 준비가 필요합니다. 자동 설치를 시작합니다.
  call "%~dp0setup_local.bat"
  if errorlevel 1 goto failed
)

if not exist "frontend\node_modules" (
  echo 프론트엔드 패키지가 없습니다. 자동 설치를 시작합니다.
  call "%~dp0setup_local.bat"
  if errorlevel 1 goto failed
)

echo Python 대화형 화면이 아니라 SMU 실행기를 시작합니다.
echo 정상이라면 잠시 후 브라우저가 http://127.0.0.1:5173 으로 열립니다.
echo.
"%~dp0.venv\Scripts\python.exe" "%~dp0run_local.py"
set EXIT_CODE=%ERRORLEVEL%
if "%EXIT_CODE%"=="0" exit /b 0

:failed
echo.
echo 실행 또는 설치 오류가 발생했습니다.
echo 전달할 로그 폴더: %~dp0runtime\logs
echo 이 창은 자동으로 닫히지 않습니다.
pause
exit /b 1
