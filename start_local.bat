@echo off
setlocal
cd /d "%~dp0"
python run_local.py
set EXIT_CODE=%ERRORLEVEL%
if not "%EXIT_CODE%"=="0" (
  echo.
  echo 실행 오류가 runtime\logs\launcher.log에 저장되었습니다.
  echo 이 창은 자동으로 닫히지 않습니다.
  pause
)
exit /b %EXIT_CODE%

