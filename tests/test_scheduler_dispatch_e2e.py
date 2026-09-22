import json
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer
from urllib.parse import urlencode

from backend.services.settings import SchedulerService
from system_monitor.fetcher import FetcherAgent, handler_for


class HttpFetcherPipeline:
    def __init__(self, base_url):
        self.base_url = base_url
        self.events = []
        self.statuses = []
        self.learner_mode = None

    def request(self, path, method="GET"):
        request = urllib.request.Request(self.base_url + path, method=method)
        with urllib.request.urlopen(request, timeout=2) as response:
            return json.loads(response.read())

    def start_fetch_job(self, targets, start, end, chain_index=False):
        self.events.append(("fetch", list(targets)))
        query = urlencode({"targets": ",".join(targets), "chain_index": "1" if chain_index else "0"})
        return self.request(f"/jobs?{query}", "POST")

    def wait_for_fetch_job(self, job, progress, wait_for_index=False):
        deadline = time.time() + 3
        while time.time() < deadline:
            current = self.request(f"/jobs/{job['id']}")
            if not self.statuses or self.statuses[-1] != current["status"]:
                self.statuses.append(current["status"])
            progress(current["message"])
            if current["status"] == "completed":
                if wait_for_index:
                    self.events.append(("index", current["result"]["indexJob"]["id"]))
                return current["result"]
            if current["status"] == "failed":
                raise RuntimeError(current["error"]["message"])
            time.sleep(.01)
        raise TimeoutError("fetcher job did not finish")

    def start_learner_job(self, mode="incremental"):
        self.learner_mode = mode
        self.events.append(("learner", mode))
        return {"id": "learner-1"}

    def wait_for_learner_job(self, job, progress):
        progress("Learner completed")
        return {"ok": True}


class UnusedRefresh:
    pass


def start_fetcher(tmp_path, monkeypatch):
    agent = FetcherAgent(tmp_path)
    collected = []

    def collect(_service, target, _today, progress):
        progress(f"{target} running")
        time.sleep(.04)
        collected.append(target)
        return {"rows": 1}

    monkeypatch.setattr(agent, "_collect_scheduled_target", collect)
    monkeypatch.setattr(agent, "_notify_watchdog", lambda job_id: {"id": f"index-{job_id}"})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(agent))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Thread(target=agent.worker_loop, daemon=True).start()
    return agent, server, collected


def test_scheduler_dispatches_fetcher_indexer_and_learner_in_order(tmp_path, monkeypatch):
    agent, server, collected = start_fetcher(tmp_path, monkeypatch)
    try:
        pipeline = HttpFetcherPipeline(f"http://127.0.0.1:{server.server_address[1]}")
        scheduler = SchedulerService(tmp_path, UnusedRefresh(), pipeline)
        scheduler.save({"enabled": False, "interval": 10, "targets": ["detections", "inbound", "learner"]})

        scheduler._run_cycle()

        state = scheduler.get()
        assert collected == ["detections", "inbound"]
        assert pipeline.statuses[0] in {"queued", "running"}
        assert pipeline.statuses[-1] == "completed"
        assert pipeline.events[0] == ("fetch", ["detections", "inbound"])
        assert pipeline.events[1][0] == "index"
        assert pipeline.events[2] == ("learner", "incremental")
        assert state["running"] is False and state["phase"] == "idle"
        assert state["targetStatus"]["learner"]["status"] == "SUCCESS"
    finally:
        agent.stop.set();agent.wake.set();server.shutdown();server.server_close()


def test_detection_only_run_now_reaches_real_fetcher_http_api(tmp_path, monkeypatch):
    agent, server, collected = start_fetcher(tmp_path, monkeypatch)
    try:
        pipeline = HttpFetcherPipeline(f"http://127.0.0.1:{server.server_address[1]}")
        scheduler = SchedulerService(tmp_path, UnusedRefresh(), pipeline)
        accepted = scheduler.run_now({"enabled": True, "interval": 5, "targets": ["detections"]})
        assert accepted["accepted"] is True
        deadline = time.time() + 3
        while scheduler.get()["running"] or not collected:
            assert time.time() < deadline
            time.sleep(.01)
        assert collected == ["detections"]
        assert pipeline.statuses[-1] == "completed"
        assert scheduler.get()["targetStatus"]["detections"]["status"] == "SUCCESS"
    finally:
        agent.stop.set();agent.wake.set();server.shutdown();server.server_close()
