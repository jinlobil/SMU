import datetime as dt
import logging
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from system_monitor.logging_utils import daily_file_handler


ROOT = Path(__file__).resolve().parent
LOG_DIR = ROOT / "runtime" / "logs"
LAUNCH_LOG = LOG_DIR / "launcher.log"
launcher_log = logging.getLogger("smu.launcher")
launcher_log.setLevel(logging.INFO)
launcher_log.propagate = False
BACKEND_READY_TIMEOUT_SECONDS = 30.0
SERVICE_CHECK_INTERVAL_SECONDS = 2.0
HEALTH_FAILURE_THRESHOLD = 3
RESTART_WINDOW_SECONDS = 60.0
MAX_RESTARTS_PER_WINDOW = 3


@dataclass
class ManagedService:
    name: str
    url: str
    command: list[str]
    cwd: Path
    essential: bool = False
    process: subprocess.Popen[str] | None = None
    restart_times: list[float] = field(default_factory=list)
    health_failures: int = 0
    last_health: bool | None = None
    disabled: bool = False


def configure_launcher_log() -> None:
    expected = str(LAUNCH_LOG.resolve())
    current = next((handler for handler in launcher_log.handlers if getattr(handler, "baseFilename", None) == expected), None)
    if current is not None:
        return
    for handler in launcher_log.handlers:
        handler.close()
    launcher_log.handlers.clear()
    launcher_log.addHandler(daily_file_handler(LAUNCH_LOG, retention_days=30))


def write_line(message: str) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    configure_launcher_log()
    line = f"{dt.datetime.now().isoformat(timespec='seconds')} {message}"
    print(line, flush=True)
    launcher_log.info(message)


def relay_output(name: str, process: subprocess.Popen[str]) -> None:
    if process.stdout is None:
        return
    for line in process.stdout:
        write_line(f"[{name}] {line.rstrip()}")


def start_process(name: str, command: list[str], cwd: Path) -> subprocess.Popen[str]:
    write_line(f"Starting {name}: executable={command[0]} command={' '.join(command)}")
    platform_options = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
    child_environment = os.environ.copy()
    child_environment.update({"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"})
    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=child_environment,
        **platform_options,
    )
    write_line(f"Started {name}: monitored_pid={process.pid} executable={command[0]}")
    threading.Thread(target=relay_output, args=(name, process), daemon=True).start()
    return process


def http_service_healthy(url: str, timeout: float = 1.0) -> bool:
    request = urllib.request.Request(
        url,
        headers={
            "Connection": "close",
            "User-Agent": "smu-launcher-health/1.0",
            "X-SMU-Health-Probe": "launcher",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response.read()
            return 200 <= response.status < 400
    except OSError:
        return False


def wait_for_service(url: str, process: subprocess.Popen[str], name: str, timeout_seconds: float = BACKEND_READY_TIMEOUT_SECONDS) -> bool:
    """Wait for HTTP readiness, tolerating a wrapper exit when the service is already healthy."""
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        healthy = http_service_healthy(url, timeout=min(1.0, max(0.05, deadline - time.monotonic())))
        return_code = process.poll()
        if healthy:
            write_line(f"{name.capitalize()} ready: url={url} monitored_pid={process.pid} http_health=healthy process_exit_code={return_code}")
            return True
        if return_code is not None:
            raise RuntimeError(f"{name} process exited during startup: monitored_pid={process.pid} code={return_code} http_health=unhealthy")
        time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))
    return False


def stop_process_tree(name: str, process: subprocess.Popen[str]) -> None:
    """Terminate the complete owned process tree so Node/Vite cannot become orphaned."""
    return_code = process.poll()
    write_line(f"Process tree cleanup: service={name} monitored_pid={process.pid} process_exit_code={return_code}")
    if return_code is not None:
        return
    if os.name == "nt":
        result = subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        write_line(f"Process tree cleanup result: service={name} method=taskkill exit_code={result.returncode}")
    else:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except ProcessLookupError:
            return
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        if os.name != "nt":
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            process.kill()
        process.wait(timeout=5)


def stop_processes(processes: list[tuple[str, subprocess.Popen[str]]]) -> None:
    for name, process in reversed(processes):
        stop_process_tree(name, process)


def hold_terminal() -> None:
    message = f"오류 내용이 저장되었습니다: {LAUNCH_LOG}"
    write_line(message)
    if sys.stdin.isatty():
        input("터미널을 닫지 않았습니다. 오류를 복사한 뒤 Enter를 누르면 종료합니다... ")


def ensure_port_available(port: int, service: str) -> None:
    """Fail before spawning when an older SMU process still owns the port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.5)
        if probe.connect_ex(("127.0.0.1", port)) == 0:
            raise RuntimeError(
                f"{service} port {port} is already in use. Close the previous SMU window/process and start again."
            )


def ensure_frontend_dependencies(npm_command: str) -> None:
    """Repair stale node_modules left behind after package.json changes."""
    frontend = ROOT / "frontend"
    check = subprocess.run(
        [npm_command, "list", "react-router-dom", "vite", "echarts", "echarts-for-react", "tslib", "--depth=0"],
        cwd=frontend,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if check.returncode == 0:
        return
    write_line("Frontend dependencies changed; running npm install...")
    install = subprocess.run([npm_command, "install"], cwd=frontend, check=False)
    if install.returncode != 0:
        raise RuntimeError("Frontend dependency installation failed. See the npm output above and runtime/logs/setup.log.")


def resolve_frontend_command() -> list[str]:
    node = shutil.which("node")
    vite_cli = ROOT / "frontend" / "node_modules" / "vite" / "bin" / "vite.js"
    if node is None:
        raise RuntimeError("node executable was not found after frontend dependency setup.")
    if not vite_cli.is_file():
        raise RuntimeError(f"Vite CLI was not found: {vite_cli}")
    return [node, str(vite_cli), "--host", "127.0.0.1", "--port", "5173"]


def _restart_allowed(service: ManagedService, now: float) -> bool:
    service.restart_times[:] = [stamp for stamp in service.restart_times if now - stamp < RESTART_WINDOW_SECONDS]
    return len(service.restart_times) < MAX_RESTARTS_PER_WINDOW


def restart_service(service: ManagedService, now: float | None = None) -> bool:
    now = time.monotonic() if now is None else now
    if not _restart_allowed(service, now):
        return False
    service.restart_times.append(now)
    attempt = len(service.restart_times)
    write_line(f"Restart attempt: service={service.name} attempt={attempt}/{MAX_RESTARTS_PER_WINDOW} window_seconds={RESTART_WINDOW_SECONDS:.0f}")
    if service.process is not None:
        stop_process_tree(service.name, service.process)
    try:
        service.process = start_process(service.name, service.command, service.cwd)
        if not wait_for_service(service.url, service.process, service.name):
            raise RuntimeError(f"HTTP readiness timeout: {service.url}")
        service.health_failures = 0
        service.last_health = True
        return True
    except Exception as exc:
        service.last_health = False
        write_line(f"Restart failed: service={service.name} attempt={attempt} error={type(exc).__name__}: {exc}")
        return False


def monitor_service(service: ManagedService, now: float | None = None) -> None:
    """Health-check and independently recover one service; raise only after its restart budget is exhausted."""
    if service.disabled:
        return
    process = service.process
    return_code = process.poll() if process is not None else None
    healthy = http_service_healthy(service.url)
    if healthy != service.last_health or return_code is not None:
        write_line(
            f"Service health: service={service.name} monitored_pid={getattr(process, 'pid', None)} "
            f"process_exit_code={return_code} http_health={'healthy' if healthy else 'unhealthy'}"
        )
    service.last_health = healthy
    if healthy:
        service.health_failures = 0
        if return_code is not None:
            write_line(f"Process/HTTP mismatch: service={service.name} wrapper_exited=true HTTP service remains healthy; no dependent service will be stopped")
        return
    service.health_failures += 1
    if return_code is None and service.health_failures < HEALTH_FAILURE_THRESHOLD:
        return
    now = time.monotonic() if now is None else now
    if restart_service(service, now):
        return
    if _restart_allowed(service, now):
        return
    reason = (
        f"{service.name} recovery exhausted: attempts={MAX_RESTARTS_PER_WINDOW} "
        f"window_seconds={RESTART_WINDOW_SECONDS:.0f} process_exit_code={return_code} http_health=unhealthy"
    )
    if service.essential:
        raise RuntimeError(reason)
    service.disabled = True
    write_line(f"SERVICE FATAL {reason}; backend and background workloads remain running")


def main() -> int:
    services: list[ManagedService] = []
    try:
        npm_command = shutil.which("npm")
        if npm_command is None:
            raise RuntimeError("npm을 찾을 수 없습니다. Node.js를 설치해주세요.")

        ensure_frontend_dependencies(npm_command)
        frontend_command = resolve_frontend_command()
        ensure_port_available(8765, "Backend")
        ensure_port_available(5173, "Frontend")

        backend = ManagedService(
            "backend",
            "http://127.0.0.1:8765/api/health",
            [sys.executable, "-m", "uvicorn", "backend.app:app", "--host", "127.0.0.1", "--port", "8765", "--no-access-log"],
            ROOT,
            essential=True,
        )
        backend.process = start_process(backend.name, backend.command, backend.cwd)
        services.append(backend)
        write_line("Waiting for backend before starting frontend...")
        if not wait_for_service(backend.url, backend.process, backend.name, BACKEND_READY_TIMEOUT_SECONDS):
            raise RuntimeError(f"Backend did not become ready within {BACKEND_READY_TIMEOUT_SECONDS:.0f} seconds: {backend.url}")

        frontend = ManagedService("frontend", "http://127.0.0.1:5173", frontend_command, ROOT / "frontend")
        frontend.process = start_process(frontend.name, frontend.command, frontend.cwd)
        services.append(frontend)
        if not wait_for_service(frontend.url, frontend.process, frontend.name):
            raise RuntimeError(f"Frontend did not become ready: {frontend.url}")
        write_line(f"Launcher log: {LAUNCH_LOG}")
        write_line(f"Backend error log: {LOG_DIR / 'web_errors.log'}")
        write_line("Starting SMU local web. Open http://127.0.0.1:5173 in a browser when needed.")

        while True:
            for service in services:
                monitor_service(service)
            time.sleep(SERVICE_CHECK_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        write_line("Shutdown requested by user")
        return 0
    except Exception as exc:
        write_line(f"FATAL {type(exc).__name__}: {exc}")
        stop_processes([(service.name, service.process) for service in services if service.process is not None])
        services.clear()
        hold_terminal()
        return 1
    finally:
        stop_processes([(service.name, service.process) for service in services if service.process is not None])


if __name__ == "__main__":
    raise SystemExit(main())
