import socket
import subprocess
from pathlib import Path

import pytest

import run_local


class FakeProcess:
    def __init__(self, pid=123, return_code=None):
        self.pid = pid
        self.return_code = return_code
        self.waited = False
        self.killed = False

    def poll(self):
        return self.return_code

    def wait(self, timeout=None):
        self.waited = True
        self.return_code = 0
        return 0

    def kill(self):
        self.killed = True
        self.return_code = -9


def service(name="frontend", process=None):
    return run_local.ManagedService(
        name,
        f"http://127.0.0.1/{name}",
        ["executable"],
        Path("."),
        essential=name == "backend",
        process=process or FakeProcess(),
    )


def quiet(monkeypatch):
    monkeypatch.setattr(run_local, "write_line", lambda message: None)


def test_wrapper_exit_with_healthy_frontend_does_not_restart_or_stop_backend(monkeypatch):
    quiet(monkeypatch)
    frontend = service(process=FakeProcess(return_code=0))
    monkeypatch.setattr(run_local, "http_service_healthy", lambda url: True)
    monkeypatch.setattr(run_local, "restart_service", lambda *args, **kwargs: pytest.fail("healthy service must not restart"))

    run_local.monitor_service(frontend, now=100.0)

    assert frontend.health_failures == 0


def test_dead_frontend_restarts_frontend_only(monkeypatch):
    quiet(monkeypatch)
    frontend = service(process=FakeProcess(return_code=1))
    backend = service("backend", FakeProcess(pid=456))
    restarted = []
    monkeypatch.setattr(run_local, "http_service_healthy", lambda url: False)
    monkeypatch.setattr(run_local, "restart_service", lambda target, now=None: restarted.append(target.name) or True)

    run_local.monitor_service(frontend, now=100.0)

    assert restarted == ["frontend"]
    assert backend.process.poll() is None


def test_frontend_restart_exhaustion_is_fatal_without_stopping_backend(monkeypatch):
    messages = []
    monkeypatch.setattr(run_local, "write_line", messages.append)
    frontend = service(process=FakeProcess(return_code=1))
    frontend.restart_times = [80.0, 90.0, 95.0]
    monkeypatch.setattr(run_local, "http_service_healthy", lambda url: False)

    run_local.monitor_service(frontend, now=100.0)

    assert frontend.disabled is True
    assert any("SERVICE FATAL frontend recovery exhausted" in message for message in messages)
    assert any("backend and background workloads remain running" in message for message in messages)


def test_backend_restart_exhaustion_remains_launcher_fatal(monkeypatch):
    quiet(monkeypatch)
    backend = service("backend", FakeProcess(return_code=1))
    backend.restart_times = [80.0, 90.0, 95.0]
    monkeypatch.setattr(run_local, "http_service_healthy", lambda url: False)

    with pytest.raises(RuntimeError, match="backend recovery exhausted"):
        run_local.monitor_service(backend, now=100.0)


def test_windows_shutdown_uses_taskkill_for_complete_process_tree(monkeypatch):
    quiet(monkeypatch)
    process = FakeProcess(pid=5173)
    commands = []
    monkeypatch.setattr(run_local.os, "name", "nt")

    class Result:
        returncode = 0

    monkeypatch.setattr(run_local.subprocess, "run", lambda command, **kwargs: commands.append(command) or Result())

    run_local.stop_process_tree("frontend", process)

    assert commands == [["taskkill", "/PID", "5173", "/T", "/F"]]
    assert process.waited


def test_dead_backend_recovers_without_stopping_frontend(monkeypatch):
    quiet(monkeypatch)
    backend = service("backend", FakeProcess(pid=8765, return_code=1))
    frontend = service(process=FakeProcess(pid=5173))
    restarted = []
    monkeypatch.setattr(run_local, "http_service_healthy", lambda url: False)
    monkeypatch.setattr(run_local, "restart_service", lambda target, now=None: restarted.append(target.name) or True)

    run_local.monitor_service(backend, now=100.0)

    assert restarted == ["backend"]
    assert frontend.process.poll() is None


def test_existing_orphan_port_is_rejected():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        with pytest.raises(RuntimeError, match=f"port {port} is already in use"):
            run_local.ensure_port_available(port, "Frontend")


def test_frontend_command_runs_vite_with_node_not_npm_wrapper(monkeypatch, tmp_path):
    frontend = tmp_path / "frontend"
    vite = frontend / "node_modules" / "vite" / "bin" / "vite.js"
    vite.parent.mkdir(parents=True)
    vite.write_text("", encoding="utf-8")
    monkeypatch.setattr(run_local, "ROOT", tmp_path)
    monkeypatch.setattr(run_local.shutil, "which", lambda executable: "C:/Node/node.exe" if executable == "node" else None)

    command = run_local.resolve_frontend_command()

    assert command == ["C:/Node/node.exe", str(vite), "--host", "127.0.0.1", "--port", "5173"]
    assert "npm" not in command[0].lower()


def test_health_probe_consumes_response_and_identifies_itself(monkeypatch):
    class Response:
        status = 200

        def __init__(self):
            self.read_called = False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self):
            self.read_called = True
            return b'{}'

    response = Response()
    captured = {}

    def open_request(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return response

    monkeypatch.setattr(run_local.urllib.request, "urlopen", open_request)

    assert run_local.http_service_healthy("http://127.0.0.1:8765/api/health", timeout=0.75)
    assert response.read_called
    assert captured["timeout"] == 0.75
    assert captured["request"].get_header("Connection") == "close"
    assert captured["request"].get_header("User-agent") == "smu-launcher-health/1.0"
    assert captured["request"].get_header("X-smu-health-probe") == "launcher"


def test_child_process_output_is_forced_to_utf8(monkeypatch, tmp_path):
    quiet(monkeypatch)
    captured = {}

    class Started(FakeProcess):
        stdout = []

    def popen(command, **kwargs):
        captured.update(kwargs)
        return Started()

    monkeypatch.setattr(run_local.subprocess, "Popen", popen)
    run_local.start_process("backend", ["python", "server.py"], tmp_path)

    assert captured["encoding"] == "utf-8"
    assert captured["env"]["PYTHONUTF8"] == "1"
    assert captured["env"]["PYTHONIOENCODING"] == "utf-8"
