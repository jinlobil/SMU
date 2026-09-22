@echo off
setlocal EnableExtensions
cd /d "%~dp0"

echo Stopping SMU process monitor processes...
echo Stop the local web server first, or it will launch the watchdog again.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$items=Get-CimInstance Win32_Process; foreach($item in $items){if($item.CommandLine -match 'system_monitor[.]watchdog'){Stop-Process -Id $item.ProcessId -Force -ErrorAction SilentlyContinue}}; Start-Sleep -Milliseconds 500; foreach($item in $items){if($item.CommandLine -match 'system_monitor[.]collector' -or $item.CommandLine -match 'system_monitor[.]fetcher' -or $item.CommandLine -match 'system_monitor[.]indexer' -or $item.CommandLine -match 'system_monitor[.]laborer' -or $item.CommandLine -match 'system_monitor[.]learner'){Stop-Process -Id $item.ProcessId -Force -ErrorAction SilentlyContinue}}"
if errorlevel 1 goto failed

echo Watchdog, Collector, Fetcher, Indexer, Laborer, and Learner processes stopped.
exit /b 0

:failed
echo ERROR: Failed to stop one or more monitor processes.
pause
exit /b 1
