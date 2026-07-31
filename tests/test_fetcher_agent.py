from system_monitor.fetcher import FetcherAgent


def test_fetcher_retries_transient_watchdog_index_notification(tmp_path, monkeypatch):
    import io
    import json
    import urllib.error
    agent = FetcherAgent(tmp_path); calls = []
    class Response:
        def __enter__(self): return self
        def __exit__(self, *_args): return False
        def read(self): return json.dumps({"id": "index-1"}).encode()
    def open_request(_request, timeout=0):
        calls.append(timeout)
        if len(calls) == 1: raise urllib.error.HTTPError("url", 503, "starting", {}, io.BytesIO(b'{"error":"Indexer starting"}'))
        return Response()
    monkeypatch.setattr("system_monitor.fetcher.urllib.request.urlopen", open_request)
    monkeypatch.setattr("system_monitor.fetcher.time.sleep", lambda _seconds: None)

    assert agent._notify_watchdog("fetch-1") == {"id": "index-1"}
    assert len(calls) == 2


def test_fetcher_runs_all_selected_targets_and_notifies_watchdog_for_scheduler(tmp_path, monkeypatch):
    agent = FetcherAgent(tmp_path)
    calls = []
    monkeypatch.setattr(agent, "_collect", lambda _service, target, _start, _end, progress: (progress(f"{target} collecting"), calls.append(target), {"rows": 1})[-1])
    monkeypatch.setattr(agent, "_notify_watchdog", lambda job_id: {"id": f"index-{job_id}", "status": "queued"})
    job = agent.submit(["detections", "inbound", "users"], "2026-07-30", "2026-07-31", chain_index=True)

    # Run one queued job without starting another process.
    original_wait = agent.wake.wait
    monkeypatch.setattr(agent.wake, "wait", lambda _timeout: agent.stop.set())
    agent.worker_loop()
    monkeypatch.setattr(agent.wake, "wait", original_wait)
    current = agent.get(job["id"])

    assert calls == ["detections", "inbound", "users"]
    assert current["status"] == "completed"
    assert current["result"]["indexJob"]["id"].startswith("index-")


def test_fetcher_single_cache_job_does_not_request_index(tmp_path, monkeypatch):
    agent = FetcherAgent(tmp_path)
    monkeypatch.setattr(agent, "_collect", lambda *_args: {"rows": 2})
    monkeypatch.setattr(agent, "_notify_watchdog", lambda _job_id: (_ for _ in ()).throw(AssertionError("single collection must not chain index")))
    job = agent.submit(["endpoints"], None, None, chain_index=False)
    monkeypatch.setattr(agent.wake, "wait", lambda _timeout: agent.stop.set())

    agent.worker_loop()

    current = agent.get(job["id"])
    assert current["status"] == "completed"
    assert current["result"]["endpoints"]["status"] == "SUCCESS"
    assert "indexJob" not in current["result"]
