from __future__ import annotations

import calendar
import math
import statistics
from datetime import date, timedelta

from .common import SOURCES
from .store import LearnerStore

SOURCE_LABELS = {"detections":"Detection","xdr":"Email XDR","inbound":"Inbound","outbound":"Outbound","dlp":"DLP","firewall":"Firewall"}
SAME_WEEKDAY_MIN_SAMPLES=6
SAME_WEEKDAY_MAX_SAMPLES=12
DAY_TYPE_MIN_SAMPLES=10
DAY_TYPE_HISTORY_DAYS=56
ROLLING_BASELINE_DAYS=30
ROLLING_MIN_SAMPLES=7
HISTORY_LOOKBACK_DAYS=max(SAME_WEEKDAY_MAX_SAMPLES*7,DAY_TYPE_HISTORY_DAYS,ROLLING_BASELINE_DAYS)


def month_start(value:date)->date:return value.replace(day=1)
def month_end(value:date)->date:return value.replace(day=calendar.monthrange(value.year,value.month)[1])
def previous_month(value:date)->tuple[date,date]:
    end=month_start(value)-timedelta(days=1);return month_start(end),end
def day_range(start:date,end:date):return [start+timedelta(days=i) for i in range((end-start).days+1)]


def anomaly_series(counts:dict[str,int],start:date,end:date,history_start:date):
    """Evaluate T from available observations strictly before T; absence is not zero."""
    output=[]
    for current in day_range(start,end):
        actual=counts.get(current.isoformat())
        if actual is None:
            output.append({"day":current.isoformat(),"count":None,"average":None,"upper":None,"lower":None,"deviationPct":None,"status":"NO_DATA","baselineMethod":None,"sampleSize":0});continue
        available=[day for day in day_range(history_start,current-timedelta(days=1)) if day.isoformat() in counts] if current>history_start else []
        same=[counts[d.isoformat()] for d in available if d.weekday()==current.weekday()][-SAME_WEEKDAY_MAX_SAMPLES:]
        day_type_start=current-timedelta(days=DAY_TYPE_HISTORY_DAYS);weekend=current.weekday()>=5
        grouped=[counts[d.isoformat()] for d in available if d>=day_type_start and (d.weekday()>=5)==weekend]
        rolling_start=current-timedelta(days=ROLLING_BASELINE_DAYS)
        rolling=[counts[d.isoformat()] for d in available if d>=rolling_start]
        if len(same)>=SAME_WEEKDAY_MIN_SAMPLES: history,method,minimum=same,"SAME_WEEKDAY",SAME_WEEKDAY_MIN_SAMPLES
        elif len(grouped)>=DAY_TYPE_MIN_SAMPLES: history,method,minimum=grouped,"WEEKDAY_WEEKEND",DAY_TYPE_MIN_SAMPLES
        else: history,method,minimum=rolling,"ROLLING",ROLLING_MIN_SAMPLES
        if len(history)<minimum:
            output.append({"day":current.isoformat(),"count":actual,"average":None,"upper":None,"lower":None,"deviationPct":None,"status":"INSUFFICIENT_HISTORY","baselineMethod":method,"sampleSize":len(history)});continue
        center=float(statistics.median(history));mad=float(statistics.median(abs(v-center) for v in history));robust=mad*1.4826
        sigma=robust if robust>0 else max(1.0,math.sqrt(max(center,1.0)));upper,lower=center+3*sigma,max(0.0,center-3*sigma)
        status="HIGH" if actual>upper else "LOW" if actual<lower else "NORMAL";deviation=((actual-center)/center*100) if center else (100.0 if actual else 0.0)
        output.append({"day":current.isoformat(),"count":actual,"average":round(center,2),"upper":round(upper,2),"lower":round(lower,2),"deviationPct":round(deviation,1),"status":status,"baselineMethod":method,"sampleSize":len(history)})
    return output


class LearnerDashboardService:
    def __init__(self,store:LearnerStore):self.store=store

    def dashboard(self,source="",month="",start="",end=""):
        bounds=self.store.daily_metric_bounds()
        if not bounds:
            selected=month or date.today().strftime("%Y-%m");return self._empty(source,selected)
        minimum,maximum=map(date.fromisoformat,bounds)
        selected_start=date.fromisoformat(f"{month}-01") if month else month_start(min(date.fromisoformat(end),maximum) if end else maximum)
        selected_end=month_end(selected_start);previous_start,previous_end=previous_month(selected_start)
        load_start=max(minimum,selected_start-timedelta(days=HISTORY_LOOKBACK_DAYS))
        load_end=min(selected_end,maximum)
        rows=self.store.daily_metrics(load_start.isoformat(),load_end.isoformat()) if load_end>=load_start else []
        by_source={name:{} for name in SOURCES};finding_metrics={name:{} for name in SOURCES}
        for row in rows:
            by_source[row["source"]][row["day"]]=int(row["event_count"]);finding_metrics[row["source"]][row["day"]]=row
        selected_counts=self._selected_counts(by_source,source)
        current_counts={k:v for k,v in selected_counts.items() if selected_start.isoformat()<=k<=selected_end.isoformat()}
        previous_counts={k:v for k,v in selected_counts.items() if previous_start.isoformat()<=k<=previous_end.isoformat()}
        anomaly_end=min(selected_end,maximum)
        evaluated=anomaly_series(selected_counts,selected_start,anomaly_end,load_start) if anomaly_end>=selected_start else []
        evaluated_by_day={int(item["day"][-2:]):item for item in evaluated}
        trend=[]
        for day_number in range(1,32):
            current_day=self._day_or_none(selected_start,day_number);previous_day=self._day_or_none(previous_start,day_number)
            current_value=current_counts.get(current_day.isoformat()) if current_day else None
            previous_value=previous_counts.get(previous_day.isoformat()) if previous_day else None
            anomaly=evaluated_by_day.get(day_number,{"average":None,"upper":None,"lower":None,"deviationPct":None,"status":"NO_DATA","baselineMethod":None,"sampleSize":0})
            delta=current_value-previous_value if current_value is not None and previous_value is not None else None
            rate=delta/previous_value*100 if delta is not None and previous_value else (0.0 if delta==0 else None)
            trend.append({**anomaly,"dayOfMonth":day_number,"day":current_day.isoformat() if current_day else None,"currentCount":current_value,"previousDay":previous_day.isoformat() if previous_day else None,"previousCount":previous_value,"monthDelta":delta,"monthChangePct":round(rate,1) if rate is not None else None})
        anomalies=[self._anomaly_detail(item,by_source,finding_metrics,source,selected_start,previous_start) for item in trend if item["status"] in {"HIGH","LOW"}]
        high=sorted((item for item in anomalies if item["status"]=="HIGH"),key=lambda item:item["deviationPct"] or 0,reverse=True)
        current_total=sum(current_counts.values());previous_total=sum(previous_counts.values());current_days=len(current_counts);previous_days=len(previous_counts)
        current_average=current_total/current_days if current_days else None;previous_average=previous_total/previous_days if previous_days else None
        change=current_average-previous_average if current_average is not None and previous_average is not None else None
        change_pct=change/previous_average*100 if change is not None and previous_average else None
        peak_count,peak_day=max(((v,k) for k,v in current_counts.items()),default=(0,""))
        comparisons=[self._source_comparison(name,by_source[name],previous_start,previous_end,selected_start,selected_end) for name in SOURCES]
        return {"range":{"start":selected_start.isoformat(),"end":selected_end.isoformat()},"source":source,"sourceLabel":SOURCE_LABELS.get(source,"전체"),"selectedMonth":selected_start.strftime("%Y-%m"),"comparisonMonth":previous_start.strftime("%Y-%m"),"kpi":{"currentTotal":current_total,"currentDailyAverage":self._round(current_average),"previousTotal":previous_total,"previousDailyAverage":self._round(previous_average),"dailyAverageChange":self._round(change),"dailyAverageChangePct":self._round(change_pct),"anomalyDays":len(high),"peakCount":peak_count,"peakDay":peak_day},"months":{"current":selected_start.strftime("%Y-%m"),"previous":previous_start.strftime("%Y-%m"),"currentDays":current_days,"previousDays":previous_days},"coverage":{"current":self._coverage(current_counts,selected_start,selected_end),"previous":self._coverage(previous_counts,previous_start,previous_end)},"trend":trend,"anomalies":anomalies,"topAnomalies":high[:5],"sourceComparison":comparisons}

    @staticmethod
    def _round(value):return round(value,1) if value is not None else None
    @staticmethod
    def _day_or_none(start,number):
        return start.replace(day=number) if number<=calendar.monthrange(start.year,start.month)[1] else None
    @staticmethod
    def _selected_counts(by_source,source):
        if source:return by_source.get(source,{})
        output={}
        for values in by_source.values():
            for day,count in values.items():output[day]=output.get(day,0)+count
        return output
    @staticmethod
    def _coverage(counts,start,end):
        keys=sorted(k for k in counts if start.isoformat()<=k<=end.isoformat());expected=(end-start).days+1
        return {"status":"INSUFFICIENT" if not keys else "COMPLETE" if len(keys)==expected else "PARTIAL","firstAvailableDay":keys[0] if keys else None,"lastAvailableDay":keys[-1] if keys else None,"observedDays":len(keys),"expectedDays":expected}
    def _source_comparison(self,source,counts,previous_start,previous_end,current_start,current_end):
        previous={k:v for k,v in counts.items() if previous_start.isoformat()<=k<=previous_end.isoformat()};current={k:v for k,v in counts.items() if current_start.isoformat()<=k<=current_end.isoformat()}
        pc,cc=self._coverage(previous,previous_start,previous_end),self._coverage(current,current_start,current_end);pa=sum(previous.values())/len(previous) if previous else None;ca=sum(current.values())/len(current) if current else None
        comparable=bool(previous and current) and min(previous)==previous_start.isoformat() and min(current)==current_start.isoformat();change=ca-pa if comparable else None;rate=change/pa*100 if comparable and pa else None
        status="INSUFFICIENT" if not comparable else "UP" if rate>5 else "DOWN" if rate<-5 else "SIMILAR"
        return {"source":source,"label":SOURCE_LABELS[source],"previousTotal":sum(previous.values()) if previous else None,"previousDailyAverage":self._round(pa),"currentTotal":sum(current.values()) if current else None,"currentDailyAverage":self._round(ca),"dailyChange":self._round(change),"changePct":self._round(rate),"status":status,"coverage":{"previous":pc,"current":cc}}
    def _anomaly_detail(self,anomaly,by_source,finding_metrics,selected_source,current_month,previous_month_start):
        day_number=anomaly["dayOfMonth"];current_day=self._day_or_none(current_month,day_number);previous_day=self._day_or_none(previous_month_start,day_number);names=[selected_source] if selected_source else list(SOURCES)
        rows=[]
        for name in names:
            current=by_source[name].get(current_day.isoformat()) if current_day else None;previous=by_source[name].get(previous_day.isoformat()) if previous_day else None;delta=current-previous if current is not None and previous is not None else None
            rows.append({"source":name,"label":SOURCE_LABELS[name],"count":current,"previousCount":previous,"delta":delta})
        positive=sum(max(item["delta"] or 0,0) for item in rows);current_total=anomaly["currentCount"] or 0
        for item in rows:item["percent"]=round(max(item["delta"] or 0,0)/positive*100,1) if positive else (round((item["count"] or 0)/current_total*100,1) if current_total else 0.0);item["mode"]="DELTA" if positive else "SHARE"
        rows.sort(key=lambda item:((item["delta"] or 0) if positive else (item["count"] or 0)),reverse=True)
        metrics={"newBehavior":0,"frequency":0,"spread":0}
        for name in names:
            row=finding_metrics[name].get(current_day.isoformat(),{}) if current_day else {};metrics["newBehavior"]+=int(row.get("new_behavior_count",0));metrics["frequency"]+=int(row.get("frequency_count",0));metrics["spread"]+=int(row.get("spread_count",0))
        causes=[]
        if rows and (rows[0]["delta"] or rows[0]["count"]):causes.append(f'{rows[0]["label"]} {"증가 " + format(rows[0]["delta"], ",") + "건" if rows[0]["delta"] is not None else format(rows[0]["percent"], ".1f") + "% 기여"}')
        for key,label in (("frequency","반복 행동 증가"),("newBehavior","신규 행동"),("spread","확산 행동")):
            if metrics[key]:causes.append(f"{label} {metrics[key]:,}건")
        return {**anomaly,"contributions":rows,"findingMetrics":metrics,"causes":causes[:3],"causeSummary":" · ".join(causes[:2]) or "집계 변화 확인 필요"}
    @staticmethod
    def _empty(source,month):
        previous,_=previous_month(date.fromisoformat(month+"-01"));return {"range":{"start":month+"-01","end":month+"-01"},"source":source,"sourceLabel":SOURCE_LABELS.get(source,"전체"),"selectedMonth":month,"comparisonMonth":previous.strftime("%Y-%m"),"kpi":{"currentTotal":0,"currentDailyAverage":None,"previousTotal":0,"previousDailyAverage":None,"dailyAverageChange":None,"dailyAverageChangePct":None,"anomalyDays":0,"peakCount":0,"peakDay":""},"months":{"current":month,"previous":previous.strftime("%Y-%m"),"currentDays":0,"previousDays":0},"coverage":{},"trend":[],"anomalies":[],"topAnomalies":[],"sourceComparison":[]}
