"""Reproducible before/after benchmark for the Learner finding list hot path."""
import argparse
import json
import tempfile
import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.services.learner.store import LearnerStore


def run(size: int):
    with tempfile.TemporaryDirectory() as directory:
        store = LearnerStore(Path(directory))
        gate = json.dumps({"visible": True, "category": "REVIEW_REQUIRED", "evidenceFamilies": ["FREQUENCY"], "reasons": ["reason"]})
        rows = [(f"f-{index}", "detections", f"event-{index // 3}", "FREQUENCY_SPIKE", "title", "summary", "{}", "[]", "{}", "[]", f"2026-08-{index % 28 + 1:02d}T10:00:{index % 60:02d}", 1, gate) for index in range(size)]
        with store.connect() as db:
            db.executemany("INSERT INTO learner_findings(finding_id,source,event_id,finding_type,title,summary,observed_json,reasons_json,baseline_json,related_event_ids_json,created_at,gate_visible,gate_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        start = time.perf_counter()
        with store.connect() as db:
            keys = db.execute("SELECT source,CASE WHEN event_id IS NULL OR event_id='' THEN finding_id ELSE event_id END key,MAX(created_at) sort_time FROM learner_findings WHERE gate_visible=1 GROUP BY source,key ORDER BY sort_time DESC LIMIT 30").fetchall()
            clauses = " OR ".join("(source=? AND (CASE WHEN event_id IS NULL OR event_id='' THEN finding_id ELSE event_id END)=?)" for _ in keys)
            db.execute("SELECT * FROM learner_findings WHERE " + clauses, [value for row in keys for value in (row["source"], row["key"])]).fetchall()
        before = time.perf_counter() - start
        build_start = time.perf_counter(); store.rebuild_operational(); build = time.perf_counter() - build_start
        start = time.perf_counter(); store.operational_findings(limit=30); after = time.perf_counter() - start
        with store.connect() as db:
            before_plan = [row[3] for row in db.execute("EXPLAIN QUERY PLAN SELECT source,event_id,MAX(created_at) FROM learner_findings WHERE gate_visible=1 GROUP BY source,event_id ORDER BY MAX(created_at) DESC LIMIT 30")]
            after_plan = [row[3] for row in db.execute("EXPLAIN QUERY PLAN SELECT * FROM learner_operational_findings WHERE gate_visible=1 ORDER BY created_at DESC LIMIT 30")]
        return {"rawFindings": size, "operationalFindings": (size + 2) // 3, "beforeSeconds": before, "afterSeconds": after, "speedup": before / after, "oneTimeBuildSeconds": build, "beforePlan": before_plan, "afterPlan": after_plan}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--sizes", nargs="+", type=int, default=[10_000, 50_000, 100_000]); args = parser.parse_args()
    for requested in args.sizes:
        print(json.dumps(run(requested), ensure_ascii=False))
