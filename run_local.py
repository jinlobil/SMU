import datetime as dt
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path


ROOT = Path(__file__).resolve().parent
LOG_DIR = ROOT / "runtime" / "logs"
LAUNCH_LOG = LOG_DIR / "launcher.log"


def write_line(message: str) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    line = f"{dt.datetime.now().isoformat(timespec='seconds')} {message}"
    print(line, flush=True)
    with LAUNCH_LOG.open("a", encoding="utf-8") as stream:
        stream.write(line + "\n")


def relay_output(name: str, process: subprocess.Popen[str]) -> None:
    if process.stdout is None:
        return
    for line in process.stdout:
        write_line(f"[{name}] {line.rstrip()}")


def start_process(name: str, command: list[str], cwd: Path) -> subprocess.Popen[str]:
    write_line(f"Starting {name}: {' '.join(command)}")
    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    threading.Thread(target=relay_output, args=(name, process), daemon=True).start()
    return process


def wait_for_service(url: str, process: subprocess.Popen[str], name: str, attempts: int = 60) -> bool:
    """Wait for an HTTP service while also detecting an early process exit."""
    for _ in range(attempts):
        return_code = process.poll()
        if return_code is not None:
            raise RuntimeError(f"{name} process exited during startup: code={return_code}")
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    write_line(f"{name.capitalize()} ready: {url}")
                    return True
        except OSError:
            time.sleep(0.5)
    return False


def open_browser_when_ready(frontend: subprocess.Popen[str]) -> None:
    """Open the UI only after both the backend and Vite are accepting requests."""
    url = "http://127.0.0.1:5173"
    if wait_for_service(url, frontend, "frontend"):
        webbrowser.open(url)
    else:
        write_line(f"WARNING Frontend did not become ready within 30 seconds: {url}")


def hold_terminal() -> None:
    message = f"오류 내용이 저장되었습니다: {LAUNCH_LOG}"
    write_line(message)
    if sys.stdin.isatty():
        input("터미널을 닫지 않았습니다. 오류를 복사한 뒤 Enter를 누르면 종료합니다... ")


def main() -> int:
    processes: list[tuple[str, subprocess.Popen[str]]] = []
    try:
        npm_command = shutil.which("npm")
        if npm_command is None:
            raise RuntimeError("npm을 찾을 수 없습니다. Node.js를 설치해주세요.")

        backend = start_process(
            "backend",
            [sys.executable, "-m", "uvicorn", "backend.app:app", "--host", "127.0.0.1", "--port", "8765"],
            ROOT,
        )
        processes.append(("backend", backend))
        backend_url = "http://127.0.0.1:8765/api/health"
        write_line("Waiting for backend before starting frontend...")
        if not wait_for_service(backend_url, backend, "backend"):
            raise RuntimeError(f"Backend did not become ready within 30 seconds: {backend_url}")

        frontend = start_process("frontend", [npm_command, "run", "dev"], ROOT / "frontend")
        processes.append(("frontend", frontend))
        write_line(f"Launcher log: {LAUNCH_LOG}")
        write_line(f"Backend error log: {LOG_DIR / 'web_errors.log'}")
        write_line("Starting SMU local web. The browser will open when it is ready.")
        threading.Thread(target=open_browser_when_ready, args=(frontend,), daemon=True).start()

        while True:
            for name, process in processes:
                return_code = process.poll()
                if return_code is not None:
                    raise RuntimeError(f"{name} process exited unexpectedly: code={return_code}")
            threading.Event().wait(0.5)
    except KeyboardInterrupt:
        write_line("Shutdown requested by user")
        return 0
    except Exception as exc:
        write_line(f"FATAL {type(exc).__name__}: {exc}")
        hold_terminal()
        return 1
    finally:
        for _, process in processes:
            if process.poll() is None:
                process.terminate()


if __name__ == "__main__":
    raise SystemExit(main())
