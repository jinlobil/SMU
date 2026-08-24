import json
from datetime import date, timedelta

from backend.services.learner.dashboard import (
    DAY_TYPE_MIN_SAMPLES,
    ROLLING_BASELINE_DAYS,
    SAME_WEEKDAY_MAX_SAMPLES,
    SAME_WEEKDAY_MIN_SAMPLES,
    LearnerDashboardService,
    anomaly_series,
    day_range,
)
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
    assert result["kpi"]["peakCount"] == 160
    assert result["kpi"]["peakDay"] == "2026-08-14"
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


def test_weekday_seasonality_treats_normal_weekends_as_normal_and_detects_spikes():
    start = date(2026, 1, 5)  # Monday
    counts = {}
    for offset in range(13 * 7):
        current = start + timedelta(days=offset)
        counts[current.isoformat()] = 200 if current.weekday() >= 5 else 1000
    counts["2026-03-31"] = 2500  # Tuesday surge
    counts["2026-04-05"] = 800  # Sunday surge
    rows = anomaly_series(counts, date(2026, 3, 30), date(2026, 4, 5), start)
    by_day = {row["day"]: row for row in rows}
    assert by_day["2026-04-04"]["status"] == "NORMAL"
    assert by_day["2026-03-31"]["status"] == "HIGH"
    assert by_day["2026-04-05"]["status"] == "HIGH"
    assert by_day["2026-04-05"]["baselineMethod"] == "SAME_WEEKDAY"
    assert by_day["2026-04-05"]["sampleSize"] <= SAME_WEEKDAY_MAX_SAMPLES


def test_seasonal_baseline_fallback_order_is_explicit():
    current = date(2026, 3, 2)
    long_start = current - timedelta(days=70)
    long_counts = {day.isoformat(): 100 for day in day_range(long_start, current)}
    same_weekday = anomaly_series(long_counts, current, current, long_start)[0]
    assert same_weekday["baselineMethod"] == "SAME_WEEKDAY"
    assert same_weekday["sampleSize"] >= SAME_WEEKDAY_MIN_SAMPLES

    group_start = current - timedelta(days=20)
    group_counts = {day.isoformat(): 100 for day in day_range(group_start, current)}
    day_type = anomaly_series(group_counts, current, current, group_start)[0]
    assert day_type["baselineMethod"] == "WEEKDAY_WEEKEND"
    assert day_type["sampleSize"] >= DAY_TYPE_MIN_SAMPLES

    rolling_start = current - timedelta(days=9)
    rolling_counts = {day.isoformat(): 100 for day in day_range(rolling_start, current)}
    rolling = anomaly_series(rolling_counts, current, current, rolling_start)[0]
    assert rolling["baselineMethod"] == "ROLLING"
    assert rolling["sampleSize"] <= ROLLING_BASELINE_DAYS


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
    assert anomaly["contributions"][0]["percent"] == 94.1
    assert "Detection" in anomaly["causeSummary"] and "증가" in anomaly["causeSummary"]


def test_default_kpi_and_top_list_include_high_but_retain_low_detail(tmp_path):
    store = LearnerStore(tmp_path)
    add_metrics(store, date(2026, 5, 1), date(2026, 8, 14))
    with store.connect() as db:
        db.execute("UPDATE learner_daily_metrics SET event_count=900 WHERE day='2026-08-13' AND source='detections'")
        db.execute("UPDATE learner_daily_metrics SET event_count=0 WHERE day='2026-08-12'")
    result = LearnerDashboardService(store).dashboard(start="2026-07-16", end="2026-08-14")
    statuses = {row["day"]: row["status"] for row in result["anomalies"]}
    assert statuses["2026-08-13"] == "HIGH"
    assert statuses["2026-08-12"] == "LOW"
    assert all(row["status"] == "HIGH" for row in result["topAnomalies"])
    assert result["kpi"]["anomalyDays"] == sum(row["status"] == "HIGH" for row in result["anomalies"])


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


def test_lazy_store_wiring_does_not_open_or_migrate_database(tmp_path):
    store = LearnerStore(tmp_path, initialize=False)
    assert not store.path.exists()
    assert store.dashboard_readiness() == "warming"


def test_schema_migration_never_backfills_derived_tables(tmp_path):
    store = LearnerStore(tmp_path)
    with store.connect() as db:
        db.execute("INSERT INTO learner_processed_events VALUES('detections','event','2026-08-01','hash')")
        db.execute("INSERT INTO learner_findings(finding_id,source,event_id,finding_type,observed_json,reasons_json,baseline_json,related_event_ids_json,created_at) VALUES('finding','detections','event','NEW_BEHAVIOR','{}','[]','{}','[]','2026-08-01')")
        db.execute("DELETE FROM learner_schema_meta")
    LearnerStore(tmp_path)
    with store.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM learner_daily_metrics").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM learner_operational_findings").fetchone()[0] == 0
        assert db.execute("SELECT value FROM learner_schema_meta WHERE key='schema_version'").fetchone()[0] == "5"


def test_month_selection_aligns_previous_month_and_keeps_missing_days_null(tmp_path):
    store = LearnerStore(tmp_path)
    add_metrics(store, date(2026, 7, 1), date(2026, 7, 31), 100, 50)
    add_metrics(store, date(2026, 8, 1), date(2026, 8, 24), 120, 60)
    result = LearnerDashboardService(store).dashboard(month="2026-08")
    assert result["selectedMonth"] == "2026-08"
    assert result["comparisonMonth"] == "2026-07"
    assert result["months"]["currentDays"] == 24
    assert result["months"]["previousDays"] == 31
    assert result["trend"][23]["currentCount"] == 180
    assert result["trend"][24]["currentCount"] is None
    assert result["trend"][24]["previousCount"] == 150
    assert result["kpi"]["currentDailyAverage"] == 180


def test_month_selection_rolls_any_month_to_its_previous_month(tmp_path):
    store = LearnerStore(tmp_path)
    add_metrics(store, date(2026, 5, 1), date(2026, 6, 30))
    result = LearnerDashboardService(store).dashboard(month="2026-06")
    assert (result["selectedMonth"], result["comparisonMonth"]) == ("2026-06", "2026-05")


def test_new_source_missing_previous_month_is_not_zero_or_fake_growth(tmp_path):
    store = LearnerStore(tmp_path)
    rows = [(f"2026-08-{day:02d}", "firewall", 10, 0, 0, 0) for day in range(1, 25)]
    with store.connect() as db:
        db.executemany("INSERT OR REPLACE INTO learner_daily_metrics VALUES(?,?,?,?,?,?)", rows)
    result = LearnerDashboardService(store).dashboard(source="firewall", month="2026-08")
    comparison = next(row for row in result["sourceComparison"] if row["source"] == "firewall")
    assert comparison["previousTotal"] is None
    assert comparison["changePct"] is None
    assert comparison["status"] == "INSUFFICIENT"
    assert result["coverage"]["previous"]["status"] == "INSUFFICIENT"
