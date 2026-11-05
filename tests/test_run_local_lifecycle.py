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


@pytest.mark.parametrize('failure', ['timeout', 'http_503'])
def test_live_backend_unhealthy_never_recovers_or_kills_even_with_exhausted_budget(monkeypatch, failure):
    import logging
    from urllib.error import HTTPError
    backend = service('backend', FakeProcess(pid=8765))
    backend.restart_times = [80.0, 90.0, 95.0]
    messages = []
    monkeypatch.setattr(run_local, 'write_line', lambda message, **kw: messages.append((message, kw.get('level', logging.INFO))))
    def probe(*args, **kwargs):
        if failure == 'timeout': raise TimeoutError('fixture timeout')
        raise HTTPError(backend.url, 503, 'Service unavailable', {}, None)
    monkeypatch.setattr(run_local.urllib.request, 'urlopen', probe)
    monkeypatch.setattr(run_local, 'restart_service', lambda *a, **kw: pytest.fail('Live backend must not invoke recovery'))
    monkeypatch.setattr(run_local, '_restart_allowed', lambda *a: pytest.fail('Health must not consult recovery budget'))
    monkeypatch.setattr(run_local, 'stop_process_tree', lambda *a: pytest.fail('Live backend must not be stopped'))
    monkeypatch.setattr(run_local.subprocess, 'run', lambda *a, **kw: pytest.fail('Health must not execute taskkill'))
    for _ in range(12): run_local.monitor_service(backend, now=100.0)
    assert backend.process.poll() is None and backend.health_failures == 12
    assert backend.last_health is False and backend.disabled is False
    assert backend.restart_times == [80.0, 90.0, 95.0]
    assert not backend.process.killed and not backend.process.waited
    warnings = [message for message, level in messages if level == logging.WARNING]
    assert len(warnings) == 12
    assert all('process_exit_code=None http_health=unhealthy' in message for message in warnings)
    assert not any('recovery exhausted' in message or 'Restart attempt' in message for message, _ in messages)


def test_backend_health_recovers_without_restart_and_resets_status(monkeypatch):
    backend = service('backend'); health = iter([False, False, True, True]); messages = []
    monkeypatch.setattr(run_local, 'write_line', lambda message, **kw: messages.append(message))
    monkeypatch.setattr(run_local, 'http_service_healthy', lambda _: next(health))
    monkeypatch.setattr(run_local, 'restart_service', lambda *a, **kw: pytest.fail('Live backend must not restart'))
    for _ in range(4): run_local.monitor_service(backend, now=100)
    assert backend.last_health is True and backend.health_failures == 0 and backend.restart_times == []
    assert any('http_health=healthy' in message for message in messages)


@pytest.mark.parametrize('ready', [True, False, 'probe_error'])
def test_actual_backend_exit_recovers_once_and_keeps_unready_replacement_running(monkeypatch, ready):
    import logging
    backend = service('backend', FakeProcess(pid=8765, return_code=1))
    frontend = service('frontend', FakeProcess(pid=5173))
    backend.restart_times = [80.0, 90.0]  # Last permitted recovery must not become fatal just for HTTP.
    replacement = FakeProcess(pid=8766); started = []; cleaned = []; messages = []
    monkeypatch.setattr(run_local, 'write_line', lambda message, **kw: messages.append((message, kw.get('level', logging.INFO))))
    monkeypatch.setattr(run_local, 'http_service_healthy', lambda _: False)
    def cleanup(name, process):
        assert process.poll() is not None, 'Must never clean up a live replacement for HTTP failures'
        cleaned.append((name, process.pid))
    monkeypatch.setattr(run_local, 'stop_process_tree', cleanup)
    monkeypatch.setattr(run_local, 'start_process', lambda name, *args: started.append(name) or replacement)
    def readiness(*args):
        if ready == 'probe_error': raise RuntimeError('fixture readiness probe error')
        return ready
    monkeypatch.setattr(run_local, 'wait_for_service', readiness)
    monkeypatch.setattr(run_local.subprocess, 'run', lambda *a, **kw: pytest.fail('No taskkill for live replacement'))
    run_local.monitor_service(backend, now=100)
    for _ in range(5): run_local.monitor_service(backend, now=101)
    assert started == ['backend'] and cleaned == [('backend', 8765)]
    assert backend.process is replacement and replacement.poll() is None
    assert backend.restart_times == [80.0, 90.0, 100]
    assert not replacement.killed and not replacement.waited
    assert frontend.process.poll() is None and not frontend.process.killed
    assert not any('recovery exhausted' in message for message, _ in messages)
    if ready is not True: assert any('Backend readiness warning' in message and level == logging.WARNING for message, level in messages)


def test_dead_backend_recovers_even_if_http_is_served_by_another_process(monkeypatch):
    quiet(monkeypatch)
    backend = service('backend', FakeProcess(return_code=1)); restarted = []
    monkeypatch.setattr(run_local, 'http_service_healthy', lambda _: True)
    monkeypatch.setattr(run_local, 'restart_service', lambda target, now: restarted.append(target.name) or True)
    run_local.monitor_service(backend, now=100)
    assert restarted == ['backend'] and backend.health_failures == 0


def test_live_frontend_keeps_existing_health_threshold_recovery(monkeypatch):
    quiet(monkeypatch)
    frontend = service(); restarted = []
    monkeypatch.setattr(run_local, 'http_service_healthy', lambda _: False)
    monkeypatch.setattr(run_local, 'restart_service', lambda target, now: restarted.append(target.name) or True)
    for _ in range(run_local.HEALTH_FAILURE_THRESHOLD): run_local.monitor_service(frontend, now=100)
    assert restarted == ['frontend']


def test_defensive_restart_guard_does_not_touch_live_backend_or_budget(monkeypatch):
    import logging
    backend = service('backend'); backend.restart_times = [80, 90, 95]; warnings = []
    monkeypatch.setattr(run_local, 'write_line', lambda message, **kw: warnings.append(kw.get('level')))
    monkeypatch.setattr(run_local, '_restart_allowed', lambda *a: pytest.fail('Live backend must not use budget'))
    monkeypatch.setattr(run_local, 'stop_process_tree', lambda *a: pytest.fail('Must not kill backend'))
    monkeypatch.setattr(run_local, 'start_process', lambda *a: pytest.fail('Must not spawn backend'))
    assert run_local.restart_service(backend, now=100) is True
    assert backend.restart_times == [80, 90, 95] and warnings == [logging.WARNING]


def test_backend_initial_readiness_timeout_continues_to_monitor_until_user_shutdown(monkeypatch):
    backend, frontend = FakeProcess(pid=8765), FakeProcess(pid=5173)
    events = []; messages = []
    monkeypatch.setattr(run_local, 'write_line', lambda message, **kw: messages.append(message))
    monkeypatch.setattr(run_local.shutil, 'which', lambda _: 'npm')
    monkeypatch.setattr(run_local, 'ensure_frontend_dependencies', lambda *a: None)
    monkeypatch.setattr(run_local, 'resolve_frontend_command', lambda: ['node', 'vite'])
    monkeypatch.setattr(run_local, 'ensure_port_available', lambda *a: None)
    monkeypatch.setattr(run_local, 'start_process', lambda name, *a: backend if name == 'backend' else frontend)
    monkeypatch.setattr(run_local, 'wait_for_service', lambda url, process, name, *a: name != 'backend')
    def monitor(target):
        events.append(('monitor', target.name))
        assert target.process.poll() is None
        raise KeyboardInterrupt()  # Only deliberate shutdown may clean the live processes.
    monkeypatch.setattr(run_local, 'monitor_service', monitor)
    monkeypatch.setattr(run_local, 'stop_processes', lambda processes: events.append(('shutdown', [name for name, _ in processes])))
    monkeypatch.setattr(run_local, 'restart_service', lambda *a, **kw: pytest.fail('Readiness must not trigger recovery'))
    assert run_local.main() == 0
    assert events == [('monitor', 'backend'), ('shutdown', ['backend', 'frontend'])]
    assert any('Backend readiness warning' in message for message in messages)
    assert not any('FATAL' in message or 'recovery exhausted' in message for message in messages)
