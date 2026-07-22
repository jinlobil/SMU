import datetime as dt
import shutil
import subprocess
import sys
import threading
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


def hold_terminal() -> None:
    message = f"오류 내용이 저장되었습니다: {LAUNCH_LOG}"
    write_line(message)
    if sys.stdin.isatty():
        input("터미널을 닫지 않았습니다. 오류를 복사한 뒤 Enter를 누르면 종료합니다... ")


def main() -> int:
    processes: list[tuple[str, subprocess.Popen[str]]] = []
    try:
        if shutil.which("npm") is None:
            raise RuntimeError("npm을 찾을 수 없습니다. Node.js를 설치해주세요.")

        backend = start_process(
            "backend",
            [sys.executable, "-m", "uvicorn", "backend.app:app", "--host", "127.0.0.1", "--port", "8765"],
            ROOT,
        )
        frontend = start_process("frontend", ["npm", "run", "dev"], ROOT / "frontend")
        processes.extend([("backend", backend), ("frontend", frontend)])
        write_line("SMU local web started: http://127.0.0.1:5173")

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

