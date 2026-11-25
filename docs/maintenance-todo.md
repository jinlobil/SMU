# Separate maintenance backlog

## stop_system_monitor.bat — pending, not part of Firewall Export

After SMU exits, improve cleanup of watchdog, collector, fetcher, indexer, laborer
and learner processes. This task must be implemented and reviewed separately.

- Exclude the current PowerShell process itself from termination targets.
- Stop watchdog first, then requery Win32_Process.
- Stop the remaining child Monitor processes using the fresh process list.
- Decide success/failure from actual surviving target processes after cleanup.
- On success, exit silently without a message or pause.
- Only on failure, show an error and pause.

The current Firewall Export change does not modify the BAT or process-management code.
