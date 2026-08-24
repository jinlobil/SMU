from __future__ import annotations

import math
import statistics
from datetime import date, timedelta

from .common import SOURCES
from .store import LearnerStore

SOURCE_LABELS = {
    "detections": "Detection", "xdr": "Email XDR", "inbound": "Inbound",
    "outbound": "Outbound", "dlp": "DLP", "firewall": "Firewall",
}
SAME_WEEKDAY_MIN_SAMPLES = 6
SAME_WEEKDAY_MAX_SAMPLES = 12
DAY_TYPE_MIN_SAMPLES = 10
DAY_TYPE_HISTORY_DAYS = 56
ROLLING_BASELINE_DAYS = 30
ROLLING_MIN_SAMPLES = 7
HISTORY_LOOKBACK_DAYS = max(SAME_WEEKDAY_MAX_SAMPLES * 7, DAY_TYPE_HISTORY_DAYS, ROLLING_BASELINE_DAYS)


def month_start(value: date) -> date:
    return value.replace(day=1)


def previous_month(value: date) -> tuple[date, date]:
    end = month_start(value) - timedelta(days=1)
    return month_start(end), end


def day_range(start: date, end: date):
    return [start + timedelta(days=offset) for offset in range((end - start).days + 1)]


def anomaly_series(counts: dict[str, int], start: date, end: date, history_start: date):
    """Evaluate each day only from its preceding rolling history (no time leak)."""
    output = []
    for current in day_range(start, end):
        history_end = current - timedelta(days=1)
        available = day_range(history_start, history_end) if history_end >= history_start else []
        same_weekday = [counts.get(day.isoformat(), 0) for day in available if day.weekday() == current.weekday()][-SAME_WEEKDAY_MAX_SAMPLES:]
        day_type_start = current - timedelta(days=DAY_TYPE_HISTORY_DAYS)
        current_is_weekend = current.weekday() >= 5
        day_type = [counts.get(day.isoformat(), 0) for day in available if day >= day_type_start and (day.weekday() >= 5) == current_is_weekend]
        rolling_start = current - timedelta(days=ROLLING_BASELINE_DAYS)
        rolling = [counts.get(day.isoformat(), 0) for day in available if day >= rolling_start]
        if len(same_weekday) >= SAME_WEEKDAY_MIN_SAMPLES:
            history, baseline_method, minimum_samples = same_weekday, "SAME_WEEKDAY", SAME_WEEKDAY_MIN_SAMPLES
        elif len(day_type) >= DAY_TYPE_MIN_SAMPLES:
            history, baseline_method, minimum_samples = day_type, "WEEKDAY_WEEKEND", DAY_TYPE_MIN_SAMPLES
        else:
            history, baseline_method, minimum_samples = rolling, "ROLLING", ROLLING_MIN_SAMPLES
        actual = counts.get(current.isoformat(), 0)
        if len(history) < minimum_samples:
            output.append({"day": current.isoformat(), "count": actual, "average": None, "upper": None, "lower": None, "deviationPct": None, "status": "INSUFFICIENT_HISTORY", "baselineMethod": baseline_method, "sampleSize": len(history)})
            continue
        center = float(statistics.median(history))
        mad = float(statistics.median(abs(value - center) for value in history))
        robust_sigma = mad * 1.4826
        # Stable histories still need a non-zero explainable count tolerance.
        sigma = robust_sigma if robust_sigma > 0 else max(1.0, math.sqrt(max(center, 1.0)))
        upper, lower = center + 3 * sigma, max(0.0, center - 3 * sigma)
        status = "HIGH" if actual > upper else "LOW" if actual < lower else "NORMAL"
        deviation = ((actual - center) / center * 100) if center else (100.0 if actual else 0.0)
        output.append({"day": current.isoformat(), "count": actual, "average": round(center, 2), "upper": round(upper, 2), "lower": round(lower, 2), "deviationPct": round(deviation, 1), "status": status, "baselineMethod": baseline_method, "sampleSize": len(history)})
    return output


class LearnerDashboardService:
    def __init__(self, store: LearnerStore):
        self.store = store

    def dashboard(self, source="", start="", end=""):
        bounds = self.store.daily_metric_bounds()
        if not bounds:
            today = date.today().isoformat()
            return self._empty(source, start or today, end or today)
        minimum, maximum = map(date.fromisoformat, bounds)
        anchor = min(date.fromisoformat(end), maximum) if end else maximum
        trend_start = max(date.fromisoformat(start), minimum) if start else max(minimum, anchor - timedelta(days=29))
        if trend_start > anchor:
            trend_start = anchor
        current_start = month_start(anchor)
        previous_start, previous_end = previous_month(anchor)
        load_start = max(minimum, min(previous_start, trend_start - timedelta(days=HISTORY_LOOKBACK_DAYS)))
        rows = self.store.daily_metrics(load_start.isoformat(), anchor.isoformat())
        by_source = {name: {} for name in SOURCES}
        finding_metrics = {name: {} for name in SOURCES}
        for row in rows:
            by_source[row["source"]][row["day"]] = int(row["event_count"])
            finding_metrics[row["source"]][row["day"]] = row
        selected_counts = self._selected_counts(by_source, source)
        trend = anomaly_series(selected_counts, trend_start, anchor, load_start)
        anomalies = [item for item in trend if item["status"] in {"HIGH", "LOW"}]
        anomaly_details = [self._anomaly_detail(item, by_source, finding_metrics, source) for item in anomalies]
        high_anomalies = [item for item in anomaly_details if item["status"] == "HIGH"]
        high_anomalies.sort(key=lambda item: item["deviationPct"] or 0, reverse=True)
        current_days = (anchor - current_start).days + 1
        previous_days = (previous_end - previous_start).days + 1
        current_total = self._period_total(selected_counts, current_start, anchor)
        previous_total = self._period_total(selected_counts, previous_start, previous_end)
        current_average = current_total / current_days
        previous_average = previous_total / previous_days
        change = current_average - previous_average
        change_pct = change / previous_average * 100 if previous_average else (100.0 if current_average else 0.0)
        new_behavior = sum(int(finding_metrics[name].get(day.isoformat(), {}).get("new_behavior_count", 0)) for name in SOURCES for day in day_range(current_start, anchor) if not source or name == source)
        spread = sum(int(finding_metrics[name].get(day.isoformat(), {}).get("spread_count", 0)) for name in SOURCES for day in day_range(current_start, anchor) if not source or name == source)
        current_values = [(selected_counts.get(day.isoformat(), 0), day.isoformat()) for day in day_range(current_start, anchor)]
        peak_count, peak_day = max(current_values, default=(0, ""))
        comparisons = [self._source_comparison(name, by_source[name], previous_start, previous_end, current_start, anchor) for name in SOURCES]
        return {
            "range": {"start": trend_start.isoformat(), "end": anchor.isoformat()},
            "source": source,
            "sourceLabel": SOURCE_LABELS.get(source, "전체"),
            "kpi": {"currentTotal": current_total, "currentDailyAverage": round(current_average, 1), "previousTotal": previous_total, "previousDailyAverage": round(previous_average, 1), "dailyAverageChange": round(change, 1), "dailyAverageChangePct": round(change_pct, 1), "anomalyDays": len(high_anomalies), "peakCount": peak_count, "peakDay": peak_day, "newBehavior": new_behavior, "spread": spread},
            "months": {"current": current_start.strftime("%Y-%m"), "previous": previous_start.strftime("%Y-%m"), "currentDays": current_days, "previousDays": previous_days},
            "trend": trend,
            "anomalies": anomaly_details,
            "topAnomalies": high_anomalies[:5],
            "sourceComparison": comparisons,
        }

    @staticmethod
    def _selected_counts(by_source, source):
        if source:
            return by_source.get(source, {})
        output = {}
        for values in by_source.values():
            for day, count in values.items():
                output[day] = output.get(day, 0) + count
        return output

    @staticmethod
    def _period_total(counts, start, end):
        return sum(counts.get(day.isoformat(), 0) for day in day_range(start, end))

    def _source_comparison(self, source, counts, previous_start, previous_end, current_start, anchor):
        previous_days = (previous_end - previous_start).days + 1
        current_days = (anchor - current_start).days + 1
        previous_total = self._period_total(counts, previous_start, previous_end)
        current_total = self._period_total(counts, current_start, anchor)
        previous_average, current_average = previous_total / previous_days, current_total / current_days
        change = current_average - previous_average
        rate = change / previous_average * 100 if previous_average else (100.0 if current_average else 0.0)
        status = "UP" if rate > 5 else "DOWN" if rate < -5 else "SIMILAR"
        return {"source": source, "label": SOURCE_LABELS[source], "previousTotal": previous_total, "previousDailyAverage": round(previous_average, 1), "currentTotal": current_total, "currentDailyAverage": round(current_average, 1), "dailyChange": round(change, 1), "changePct": round(rate, 1), "status": status}

    def _anomaly_detail(self, anomaly, by_source, finding_metrics, selected_source):
        day, total = anomaly["day"], anomaly["count"]
        names = [selected_source] if selected_source else list(SOURCES)
        contributions = [{"source": name, "label": SOURCE_LABELS[name], "count": by_source[name].get(day, 0)} for name in names]
        contributions.sort(key=lambda item: item["count"], reverse=True)
        for item in contributions:
            item["percent"] = round(item["count"] / total * 100, 1) if total else 0.0
        metrics = {"newBehavior": 0, "frequency": 0, "spread": 0}
        for name in names:
            row = finding_metrics[name].get(day, {})
            metrics["newBehavior"] += int(row.get("new_behavior_count", 0))
            metrics["frequency"] += int(row.get("frequency_count", 0))
            metrics["spread"] += int(row.get("spread_count", 0))
        causes = []
        if contributions and contributions[0]["count"]:
            causes.append(f'{contributions[0]["label"]} {contributions[0]["percent"]:.1f}% 기여')
        for key, label in (("frequency", "활동 증가"), ("newBehavior", "신규 행동"), ("spread", "확산 행동")):
            if metrics[key]: causes.append(f"{label} {metrics[key]:,}건")
        return {**anomaly, "contributions": contributions, "findingMetrics": metrics, "causes": causes[:3], "causeSummary": " · ".join(causes[:2]) or "집계 변화 확인 필요"}

    @staticmethod
    def _empty(source, start, end):
        return {"range": {"start": start, "end": end}, "source": source, "sourceLabel": SOURCE_LABELS.get(source, "전체"), "kpi": {"currentTotal": 0, "currentDailyAverage": 0, "previousTotal": 0, "previousDailyAverage": 0, "dailyAverageChange": 0, "dailyAverageChangePct": 0, "anomalyDays": 0, "peakCount": 0, "peakDay": "", "newBehavior": 0, "spread": 0}, "months": {}, "trend": [], "anomalies": [], "topAnomalies": [], "sourceComparison": []}
