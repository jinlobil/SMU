import json
from datetime import date, timedelta

from backend.services.learner.dashboard import LearnerDashboardService, anomaly_series
from backend.services.learner.store import LearnerStore


def add_metrics(store, start, end, detection=100, inbound=50):
    rows = []
    current = start
    while current <= end:
        rows.extend([(current.isoformat(), "detections", detection, 1, 0, 0), (current.isoformat(), "inbound", inbound, 0, 0, 0)])
        current += timedelta(days=1)
    with store.connect() as db:
        db.executemany("INSERT OR REPLACE INTO learner_daily_metrics VALUES(?,?,?,?,?,?)", rows)


def test_month_totals_daily_averages_and_source_sum(tmp_path):
    store = LearnerStore(tmp_path)
    add_metrics(store, date(2026, 7, 1), date(2026, 7, 31))
    add_metrics(store, date(2026, 8, 1), date(2026, 8, 14), 120, 40)
    result = LearnerDashboardService(store).dashboard(end="2026-08-14")
    assert result["kpi"]["previousTotal"] == 31 * 150
    assert result["kpi"]["previousDailyAverage"] == 150
    assert result["kpi"]["currentTotal"] == 14 * 160
    assert result["kpi"]["currentDailyAverage"] == 160
    assert result["kpi"]["dailyAverageChangePct"] == 6.7
    detection = next(row for row in result["sourceComparison"] if row["source"] == "detections")
    assert detection["previousTotal"] == 3100 and detection["currentTotal"] == 1680


def test_anomaly_threshold_has_no_time_leak_and_classifies_high_low_normal():
    start = date(2026, 1, 1)
    counts = {(start + timedelta(days=index)).isoformat(): 100 for index in range(12)}
    counts["2026-01-09"] = 200
    counts["2026-01-10"] = 100
    counts["2026-01-11"] = 0
    original = anomaly_series(counts, date(2026, 1, 8), date(2026, 1, 11), start)
    counts["2026-01-12"] = 100_000
    with_future = anomaly_series(counts, date(2026, 1, 8), date(2026, 1, 11), start)
    assert original == with_future
    assert {row["day"]: row["status"] for row in original} == {"2026-01-08": "NORMAL", "2026-01-09": "HIGH", "2026-01-10": "NORMAL", "2026-01-11": "LOW"}


def test_anomaly_top_and_source_contribution(tmp_path):
    store = LearnerStore(tmp_path)
    add_metrics(store, date(2026, 7, 1), date(2026, 8, 14))
    with store.connect() as db:
        db.execute("UPDATE learner_daily_metrics SET event_count=900,frequency_count=3 WHERE day='2026-08-13' AND source='detections'")
        db.execute("UPDATE learner_daily_metrics SET event_count=100,new_behavior_count=2 WHERE day='2026-08-13' AND source='inbound'")
    result = LearnerDashboardService(store).dashboard(start="2026-07-16", end="2026-08-14")
    anomaly = next(row for row in result["anomalies"] if row["day"] == "2026-08-13")
    assert anomaly["status"] == "HIGH"
    assert anomaly["contributions"][0]["source"] == "detections"
    assert anomaly["contributions"][0]["percent"] == 90.0
    assert "Detection" in anomaly["causeSummary"] and "활동 증가" in anomaly["causeSummary"]


def test_dashboard_hot_path_never_reads_large_finding_tables(tmp_path):
    store = LearnerStore(tmp_path)
    add_metrics(store, date(2026, 7, 1), date(2026, 8, 14))
    raw = [(f"finding-{index}", "detections", f"event-{index}", "NEW_BEHAVIOR", "{}", "[]", "{}", "[]", "2026-08-01", 0, "{}") for index in range(100_000)]
    with store.connect() as db:
        db.executemany("INSERT INTO learner_findings(finding_id,source,event_id,finding_type,observed_json,reasons_json,baseline_json,related_event_ids_json,created_at,gate_visible,gate_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)", raw)
    statements = []
    original_connect = store.connect
    def traced_connect():
        connection = original_connect(); connection.set_trace_callback(statements.append); return connection
    store.connect = traced_connect
    result = LearnerDashboardService(store).dashboard(end="2026-08-14")
    assert result["kpi"]["currentTotal"] > 0
    assert not any("learner_findings" in statement.lower() or "learner_operational_findings" in statement.lower() for statement in statements)
