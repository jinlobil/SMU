"""Compare the retired Finding overview load with the daily aggregate dashboard."""
import json
import sys
import tempfile
import time
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.services.learner.dashboard import LearnerDashboardService
from backend.services.learner.store import LearnerStore


def run(finding_count=100_000):
    with tempfile.TemporaryDirectory() as directory:
        store = LearnerStore(Path(directory))
        gate = json.dumps({"visible": True, "category": "REVIEW_REQUIRED", "evidenceFamilies": ["FREQUENCY"], "reasons": ["reason"]})
        findings = [(f"f-{index}", "detections", f"e-{index}", "FREQUENCY_SPIKE", "title", "summary", "{}", "[]", "{}", "[]", f"2026-08-{index % 14 + 1:02d}", 1, gate) for index in range(finding_count)]
        metrics, current = [], date(2026, 7, 1)
        while current <= date(2026, 8, 14):
            metrics.append((current.isoformat(), "detections", 10_000, 20, 10, 3)); current += timedelta(days=1)
        with store.connect() as db:
            db.executemany("INSERT INTO learner_findings(finding_id,source,event_id,finding_type,title,summary,observed_json,reasons_json,baseline_json,related_event_ids_json,created_at,gate_visible,gate_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", findings)
            db.executemany("INSERT INTO learner_daily_metrics VALUES(?,?,?,?,?,?)", metrics)
        store.rebuild_operational()
        start = time.perf_counter(); store.summary(); store.operational_findings(limit=30); before = time.perf_counter() - start
        start = time.perf_counter(); LearnerDashboardService(store).dashboard(end="2026-08-14"); after = time.perf_counter() - start
        return {"findings": finding_count, "beforeSeconds": before, "afterSeconds": after, "speedup": before / after}


if __name__ == "__main__":
    print(json.dumps(run(), ensure_ascii=False))
