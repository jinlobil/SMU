"""Streaming deterministic Learner engine.

The event index remains the source of truth.  This engine keeps derived baseline
state in memory per source, writes to an isolated staging database in bounded
batches, and activates the staging database only after a successful run.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable

from .adapters import ADAPTERS
from .common import SOURCES, WINDOWS, Behavior
from .gate import behavior_signatures, evaluate
from .store import LearnerStore, SCHEMA_VERSION

BATCH_SIZE = 2_000
RELATED_LIMIT = 100
ENGINE_VERSION = "2"


@dataclass
class Baseline:
    total: int = 0
    first_seen: str = ""
    last_seen: str = ""
    daily: dict[str, int] = field(default_factory=dict)

    def prior(self) -> int:
        return self.total

    def add(self, event_time: str) -> None:
        day = event_time[:10]
        self.total += 1
        self.first_seen = self.first_seen or event_time
        self.last_seen = event_time
        self.daily[day] = self.daily.get(day, 0) + 1
        cutoff = (date.fromisoformat(day) - timedelta(days=181)).isoformat()
        self.daily = {key: value for key, value in self.daily.items() if key >= cutoff}


@dataclass
class Group:
    representative: Behavior
    event_count: int = 0
    users: set[str] = field(default_factory=set)
    devices: set[str] = field(default_factory=set)
    departments: set[str] = field(default_factory=set)
    related: list[str] = field(default_factory=list)

    def add(self, behavior: Behavior) -> None:
        self.event_count += 1
        if behavior.person_key:
            self.users.add(behavior.person_key)
        if behavior.endpoint_key:
            self.devices.add(behavior.endpoint_key)
        if behavior.department:
            self.departments.add(behavior.department)
        if len(self.related) < RELATED_LIMIT and behavior.event_id not in self.related:
            self.related.append(behavior.event_id)


class StreamingLearnerEngine:
    def __init__(self, root: Path, store: LearnerStore, batch_size: int = BATCH_SIZE):
        self.root = root
        self.events = root / "cache/index/events_index.db"
        self.store = store
        self.batch_size = batch_size
        self.sql_counts = defaultdict(int)

    def _event_db(self):
        if not self.events.exists():
            raise RuntimeError("events_index.db가 없습니다. 먼저 인덱싱을 실행하세요.")
        db = sqlite3.connect(f"{self.events.resolve().as_uri()}?mode=ro", uri=True)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA busy_timeout=30000")
        return db

    def count(self, source: str, after: tuple[str, str] | None = None) -> int:
        query = "SELECT COUNT(*) FROM event_list_rows WHERE kind=?"
        params: list[str] = [source]
        if after:
            query += " AND (event_time>? OR (event_time=? AND record_id>?))"
            params += [after[0], after[0], after[1]]
        with self._event_db() as db:
            self.sql_counts["input_select"] += 1
            return int(db.execute(query, params).fetchone()[0])

    def stream(self, source: str, after: tuple[str, str] | None = None):
        query = "SELECT kind,record_id,event_time,row_json FROM event_list_rows WHERE kind=?"
        params: list[str] = [source]
        if after:
            query += " AND (event_time>? OR (event_time=? AND record_id>?))"
            params += [after[0], after[0], after[1]]
        query += " ORDER BY event_time ASC,record_id ASC"
        db = self._event_db()
        cursor = db.execute(query, params)
        self.sql_counts["input_select"] += 1
        try:
            while True:
                chunk = cursor.fetchmany(self.batch_size)
                if not chunk:
                    break
                yield chunk
        finally:
            cursor.close()
            db.close()

    def incremental_plan(self, source: str, cancelled=lambda:False):
        """Return (rebuild, watermark) without loading event rows into a list."""
        with self.store.connect() as db:
            state=db.execute("SELECT * FROM learner_source_state WHERE source=? AND engine_version=?",(source,ENGINE_VERSION)).fetchone()
            if not state:return True,None
            known={row[0]:row[1] for row in db.execute("SELECT event_id,row_hash FROM learner_processed_events WHERE source=?",(source,))}
        seen=0;changed=False
        for chunk in self.stream(source):
            if cancelled():
                from .service import LearnerCancelled
                raise LearnerCancelled("분석 중단 요청")
            for row in chunk:
                seen+=1;digest=hashlib.sha256((row["event_time"]+row["row_json"]).encode()).hexdigest();previous=known.get(row["record_id"])
                if previous is not None and previous!=digest:changed=True;break
            if changed:break
        if changed or seen!=int(state["event_count"])+self.count(source,(state["last_event_time"],state["last_event_id"])):
            return True,None
        return False,(state["last_event_time"],state["last_event_id"])

    def load_state(self, source: str) -> dict[tuple[str, str, str, str], Baseline]:
        states = {}
        with self.store.connect() as db:
            self.sql_counts["state_select"] += 1
            for row in db.execute("SELECT * FROM learner_analysis_state WHERE source=?", (source,)):
                states[(row["scope_type"], row["scope_key"], row["behavior_type"], row["behavior_key"])] = Baseline(
                    row["total_count"], row["first_seen"], row["last_seen"], json.loads(row["daily_json"] or "{}")
                )
        return states

    @staticmethod
    def state_key(scope_type: str, scope_key: str, behavior: Behavior):
        return scope_type, scope_key, behavior.behavior_type, behavior.behavior_key

    def load_group(self, source: str, day: str) -> dict[tuple[str, str], Group]:
        groups = {}
        with self.store.connect() as db:
            self.sql_counts["group_select"] += 1
            rows = db.execute("SELECT * FROM learner_group_state WHERE source=? AND event_day=?", (source, day)).fetchall()
        for row in rows:
            rep = Behavior(**json.loads(row["representative_json"]))
            groups[(row["behavior_type"], row["behavior_key"])] = Group(
                rep, row["event_count"], set(json.loads(row["users_json"])), set(json.loads(row["devices_json"])),
                set(json.loads(row["departments_json"])), list(json.loads(row["related_json"])),
            )
        return groups

    @staticmethod
    def _finding(behavior: Behavior, kind: str, title: str, summary: str, reasons: list[str], baseline: dict, related: list[str], observed=None):
        signature = f"{kind}:{behavior.source}:{behavior.event_id}" if kind == "NEW_BEHAVIOR" else f"{kind}:{behavior.source}:{behavior.event_id}:{behavior.behavior_type}:{behavior.behavior_key}"
        return {
            "finding_id": hashlib.sha256(signature.encode()).hexdigest()[:32], "source": behavior.source,
            "event_id": behavior.event_id, "finding_type": kind, "title": title, "summary": summary,
            "person_key": behavior.person_key, "endpoint_key": behavior.endpoint_key, "user_name": behavior.user_name,
            "user_id": behavior.user_id, "email": behavior.email, "hostname": behavior.hostname,
            "department": behavior.department, "observed": observed if observed is not None else behavior.observed,
            "reasons": reasons, "baseline": baseline, "related": related, "created_at": behavior.event_time,
        }

    def _existing_evidence(self, source: str):
        frequency, spread = set(), set()
        with self.store.connect() as db:
            self.sql_counts["evidence_select"] += 1
            rows = db.execute("SELECT finding_type,observed_json,baseline_json FROM learner_findings WHERE source=? AND finding_type IN ('FREQUENCY_SPIKE','SIMILAR_GROUP')", (source,)).fetchall()
        for row in rows:
            if row["finding_type"] == "FREQUENCY_SPIKE":
                frequency.update(behavior_signatures(row))
            elif json.loads(row["baseline_json"] or "{}").get("spread"):
                spread.update(behavior_signatures(row))
        return frequency, spread

    def _finalize_groups(self, source: str, day: str, groups: dict[tuple[str, str], Group], states, findings, frequency, spread, changed_signatures, cancelled):
        for index, ((behavior_type, behavior_key), group) in enumerate(groups.items(), 1):
            if index % 500 == 0 and cancelled():
                from .service import LearnerCancelled
                raise LearnerCancelled("분석 중단 요청")
            if group.event_count < 10:
                continue
            signature = (behavior_type, behavior_key)
            diversity = {"groupCount": group.event_count, "eventCount": group.event_count, "distinctUsers": len(group.users),
                         "distinctDevices": len(group.devices), "distinctDepartments": len(group.departments),
                         "spread": len(group.users) >= 2 or len(group.devices) >= 2,
                         "entitySpreadCount": max(len(group.users), len(group.devices))}
            findings.append(self._finding(group.representative, "SIMILAR_GROUP", "비슷한 이벤트",
                f"동일한 행동이 {group.event_count:,}건 확인되었습니다.",
                [f"같은 분석일에 정규화된 행동 값이 {group.event_count:,}건 일치했습니다."], diversity, group.related))
            if diversity["spread"]:
                spread.add(signature)
            global_state = states.get(("global", "*", behavior_type, behavior_key), Baseline())
            day_value = date.fromisoformat(day)
            prior = sum(global_state.daily.get((day_value - timedelta(days=offset)).isoformat(), 0) for offset in range(1, 8))
            average = prior / 7
            if average > 0 and group.event_count >= max(10, average * 3):
                findings.append(self._finding(group.representative, "FREQUENCY_SPIKE", "최근 활동 증가",
                    f"하루 {group.event_count:,}건으로 최근 7일 평균보다 크게 증가했습니다.",
                    [f"최근 1일 {group.event_count:,}건", f"이전 7일 일평균 {average:.1f}건", "최소 10건 및 3배 증가 기준을 충족했습니다."],
                    {"count1d": group.event_count, "prior7d": prior, "priorDailyAverage": average}, group.related))
                frequency.add(signature)
            changed_signatures.add(signature)

    def _save_groups(self, source: str, day: str, groups: dict[tuple[str, str], Group], cancelled=lambda:False):
        rows = []
        for (behavior_type, behavior_key), group in groups.items():
            representative=group.representative.json();observed=representative.get("observed") or {};representative["observed"]={"behaviorType":observed.get("behaviorType",behavior_type),"value":observed.get("value",behavior_key)}
            rows.append((source, day, behavior_type, behavior_key, group.event_count, json.dumps(sorted(group.users)),
                         json.dumps(sorted(group.devices)), json.dumps(sorted(group.departments), ensure_ascii=False),
                         json.dumps(group.related), json.dumps(representative, ensure_ascii=False)))
        with self.store.connect() as db:
            db.execute("DELETE FROM learner_group_state WHERE source=?", (source,))
            for start in range(0, len(rows), self.batch_size):
                if cancelled():
                    from .service import LearnerCancelled
                    raise LearnerCancelled("분석 중단 요청")
                db.executemany("INSERT OR REPLACE INTO learner_group_state VALUES(?,?,?,?,?,?,?,?,?,?)", rows[start:start+self.batch_size])
                self.sql_counts["group_write"] += len(rows[start:start+self.batch_size])

    def _save_states(self, source: str, states, anchor: str, cancelled):
        now = datetime.now(timezone.utc).isoformat(); rows = []; stats = []
        anchor_day = date.fromisoformat(anchor[:10])
        with self.store.connect() as db:
            db.execute("DELETE FROM learner_analysis_state WHERE source=?", (source,)); db.execute("DELETE FROM behavior_stats WHERE source=?", (source,))
        for index, ((scope_type, scope_key, behavior_type, behavior_key), state) in enumerate(states.items(), 1):
            if index % self.batch_size == 0 and cancelled():
                from .service import LearnerCancelled
                raise LearnerCancelled("분석 중단 요청")
            rows.append((source, scope_type, scope_key, behavior_type, behavior_key, state.total, state.first_seen, state.last_seen, json.dumps(state.daily)))
            counts = [sum(value for day, value in state.daily.items() if day >= (anchor_day - timedelta(days=window)).isoformat()) for window in WINDOWS]
            stats.append((source, scope_type, scope_key, behavior_type, behavior_key, *counts, state.total, state.first_seen, state.last_seen, now))
            if len(rows)>=self.batch_size:
                with self.store.connect() as db:
                    db.executemany("INSERT OR REPLACE INTO learner_analysis_state VALUES(?,?,?,?,?,?,?,?,?)", rows)
                    db.executemany("INSERT OR REPLACE INTO behavior_stats VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", stats)
                self.sql_counts["state_write"] += len(rows);rows.clear();stats.clear()
        if rows:
            with self.store.connect() as db:
                db.executemany("INSERT OR REPLACE INTO learner_analysis_state VALUES(?,?,?,?,?,?,?,?,?)", rows)
                db.executemany("INSERT OR REPLACE INTO behavior_stats VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", stats)
            self.sql_counts["state_write"] += len(rows)

    def _save_findings(self, source: str, findings, frequency, spread, changed_signatures, full_source: bool, cancelled):
        if full_source:
            with self.store.connect() as db:
                db.execute("DELETE FROM learner_findings WHERE source=?", (source,));db.execute("DELETE FROM learner_finding_signatures WHERE source=?", (source,))
        rows=[]; mappings=[]
        for finding in findings:
            raw={"finding_type":finding["finding_type"],"observed_json":json.dumps(finding["observed"],ensure_ascii=False),"baseline_json":json.dumps(finding["baseline"],ensure_ascii=False)}
            gate=evaluate(raw,frequency,spread)
            rows.append((finding["finding_id"],finding["source"],finding["event_id"],finding["finding_type"],finding["title"],finding["summary"],finding["person_key"],finding["endpoint_key"],finding["user_name"],finding["user_id"],finding["email"],finding["hostname"],finding["department"],raw["observed_json"],json.dumps(finding["reasons"],ensure_ascii=False),raw["baseline_json"],json.dumps(finding["related"]),finding["created_at"],int(gate["visible"]),json.dumps(gate,ensure_ascii=False)))
            for signature in behavior_signatures(raw):mappings.append((source,*signature,finding["finding_id"]))
        for start in range(0,len(rows),self.batch_size):
            if cancelled():
                from .service import LearnerCancelled
                raise LearnerCancelled("분석 중단 요청")
            with self.store.connect() as db:
                db.executemany("INSERT OR REPLACE INTO learner_findings VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",rows[start:start+self.batch_size])
            self.sql_counts["finding_write"]+=len(rows[start:start+self.batch_size])
        for start in range(0,len(mappings),self.batch_size):
            if cancelled():
                from .service import LearnerCancelled
                raise LearnerCancelled("분석 중단 요청")
            with self.store.connect() as db:db.executemany("INSERT OR REPLACE INTO learner_finding_signatures VALUES(?,?,?,?)",mappings[start:start+self.batch_size])
        if not full_source and changed_signatures:
            with self.store.connect() as db:
                db.execute("CREATE TEMP TABLE changed_signatures(behavior_type TEXT,behavior_key TEXT,PRIMARY KEY(behavior_type,behavior_key))")
                db.executemany("INSERT OR IGNORE INTO changed_signatures VALUES(?,?)",changed_signatures)
                affected=db.execute("SELECT DISTINCT f.* FROM learner_findings f JOIN learner_finding_signatures s ON s.finding_id=f.finding_id JOIN changed_signatures c ON c.behavior_type=s.behavior_type AND c.behavior_key=s.behavior_key WHERE f.source=?",(source,)).fetchall()
                updates=[]
                for index,row in enumerate(affected,1):
                    if index%500==0 and cancelled():
                        from .service import LearnerCancelled
                        raise LearnerCancelled("분석 중단 요청")
                    gate=evaluate(row,frequency,spread);updates.append((int(gate["visible"]),json.dumps(gate,ensure_ascii=False),row["finding_id"]))
                db.executemany("UPDATE learner_findings SET gate_visible=?,gate_json=? WHERE finding_id=?",updates)
                self.sql_counts["gate_update"]+=len(updates)

    def source(self, source: str, after: tuple[str,str]|None, target_start: str, target_end: str, progress: Callable, cancelled: Callable, full_source: bool):
        states={} if full_source else self.load_state(source)
        frequency,spread=(set(),set()) if full_source else self._existing_evidence(source)
        findings=[];changed_signatures=set();processed_buffer=[];current_day="";groups={};done=0;last_time="";last_id=""
        total=self.count(source,after)
        for chunk in self.stream(source,after):
            if cancelled():
                from .service import LearnerCancelled
                raise LearnerCancelled("분석 중단 요청")
            for raw in chunk:
                day=raw["event_time"][:10]
                if current_day and day!=current_day:
                    progress({"phase":"FINALIZE_GROUPS","message":f"{source} · 행동 그룹 정리","sourceProcessed":done,"sourceTotal":total})
                    self._finalize_groups(source,current_day,groups,states,findings,frequency,spread,changed_signatures,cancelled);groups={}
                if day!=current_day:
                    current_day=day
                    if not full_source:groups=self.load_group(source,day)
                event=json.loads(raw["row_json"]);event_id=raw["record_id"];event_time=raw["event_time"];behaviors=ADAPTERS[source](event_id,event_time,event)
                new=[];pending=[]
                for behavior in behaviors:
                    counts={scope_type:states.get(self.state_key(scope_type,scope_key,behavior),Baseline()).prior() for scope_type,scope_key in behavior.scopes()}
                    if counts.get("device",0)==0 and counts.get("user",0)==0 and counts.get("global",0)==0:new.append((behavior,counts))
                    pending.append(behavior)
                    key=(behavior.behavior_type,behavior.behavior_key);groups.setdefault(key,Group(behavior)).add(behavior)
                in_target=(not target_start or event_time>=target_start) and (not target_end or event_time<target_end+"T99")
                if new and in_target:
                    primary=new[0][0];baselines=[{"behaviorType":b.behavior_type,"behaviorKey":b.behavior_key,"counts":counts} for b,counts in new]
                    findings.append(self._finding(primary,"NEW_BEHAVIOR","새로운 행동",f"하나의 이벤트에서 새로운 행동 {len(new):,}개가 확인되었습니다.",[f"새로운 행동 '{b.observed.get('value','')}'이(가) 전체 과거 이력에서 처음 확인되었습니다." for b,_ in new],{**baselines[0]["counts"],"behaviors":baselines},[event_id],{"event":event,"newBehaviors":[b.observed for b,_ in new]}))
                # Apply only after all evidence for the current event was evaluated.
                for behavior in pending:
                    for scope_type,scope_key in behavior.scopes():states.setdefault(self.state_key(scope_type,scope_key,behavior),Baseline()).add(event_time)
                digest=hashlib.sha256((event_time+raw["row_json"]).encode()).hexdigest();processed_buffer.append((source,event_id,event_time,digest));done+=1;last_time=event_time;last_id=event_id
            with self.store.connect() as db:
                db.executemany("INSERT OR REPLACE INTO learner_processed_events VALUES(?,?,?,?)",processed_buffer);processed_buffer.clear()
            self.sql_counts["processed_write"]+=len(chunk)
            progress({"phase":"STREAM","message":f"{source} · 이벤트 분석","sourceProcessed":done,"sourceTotal":total})
        if current_day:
            progress({"phase":"FINALIZE_GROUPS","message":f"{source} · 행동 그룹 정리","sourceProcessed":done,"sourceTotal":total})
            self._finalize_groups(source,current_day,groups,states,findings,frequency,spread,changed_signatures,cancelled);self._save_groups(source,current_day,groups,cancelled)
        progress({"phase":"FINALIZE_FINDINGS","message":f"{source} · Finding 정리","sourceProcessed":done,"sourceTotal":total})
        self._save_findings(source,findings,frequency,spread,changed_signatures,full_source,cancelled)
        progress({"phase":"WRITE","message":f"{source} · 분석 상태 저장","sourceProcessed":done,"sourceTotal":total})
        if last_time:self._save_states(source,states,last_time,cancelled)
        with self.store.connect() as db:
            old=db.execute("SELECT event_count FROM learner_source_state WHERE source=?",(source,)).fetchone();event_count=done if full_source else (old[0] if old else 0)+done
            db.execute("INSERT OR REPLACE INTO learner_source_state VALUES(?,?,?,?,?,?)",(source,event_count,last_time or (after[0] if after else ""),last_id or (after[1] if after else ""),datetime.now(timezone.utc).isoformat(),ENGINE_VERSION))
            if last_time:db.execute("INSERT OR REPLACE INTO learner_watermarks VALUES(?,?,?,?)",(source,last_time,last_id,datetime.now(timezone.utc).isoformat()))
        return done
