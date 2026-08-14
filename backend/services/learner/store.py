import hashlib
import json
import sqlite3
from pathlib import Path

SCHEMA_VERSION = "4"


class ClosingConnection(sqlite3.Connection):
    """A sqlite context manager that also releases the OS file handle."""

    def __exit__(self, exc_type, exc, traceback):
        try:
            return super().__exit__(exc_type, exc, traceback)
        finally:
            self.close()


class LearnerStore:
    def __init__(self, root: Path, path: Path | None = None):
        self.path = path or root / "cache/index/learner_cache.db"
        self.initialize()

    def connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.path, timeout=30, factory=ClosingConnection)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=30000")
        db.execute("PRAGMA journal_mode=WAL")
        return db

    def initialize(self):
        needs_backfill = False
        with self.connect() as db:
            db.executescript("""
CREATE TABLE IF NOT EXISTS learner_runs(run_id TEXT PRIMARY KEY,mode TEXT,source TEXT,history_start TEXT,history_end TEXT,target_start TEXT,target_end TEXT,status TEXT,started_at TEXT,finished_at TEXT,processed_events INTEGER DEFAULT 0,last_error TEXT,schema_version TEXT);
CREATE TABLE IF NOT EXISTS behavior_stats(source TEXT,scope_type TEXT,scope_key TEXT,behavior_type TEXT,behavior_key TEXT,count_1d INTEGER,count_7d INTEGER,count_30d INTEGER,count_90d INTEGER,count_180d INTEGER,count_all INTEGER,first_seen TEXT,last_seen TEXT,updated_at TEXT,PRIMARY KEY(source,scope_type,scope_key,behavior_type,behavior_key));
CREATE TABLE IF NOT EXISTS learner_findings(finding_id TEXT PRIMARY KEY,source TEXT,event_id TEXT,finding_type TEXT,title TEXT,summary TEXT,person_key TEXT,endpoint_key TEXT,user_name TEXT,user_id TEXT,email TEXT,hostname TEXT,department TEXT,observed_json TEXT,reasons_json TEXT,baseline_json TEXT,related_event_ids_json TEXT,created_at TEXT,gate_visible INTEGER DEFAULT 0,gate_json TEXT);
CREATE TABLE IF NOT EXISTS processed_behaviors(source TEXT,event_id TEXT,event_time TEXT,scope_type TEXT,scope_key TEXT,behavior_type TEXT,behavior_key TEXT,PRIMARY KEY(source,event_id,scope_type,scope_key,behavior_type,behavior_key));
CREATE TABLE IF NOT EXISTS learner_processed_events(source TEXT,event_id TEXT,event_time TEXT,row_hash TEXT,PRIMARY KEY(source,event_id));
CREATE TABLE IF NOT EXISTS learner_watermarks(source TEXT PRIMARY KEY,last_event_time TEXT,last_event_id TEXT,updated_at TEXT);
CREATE TABLE IF NOT EXISTS learner_analysis_state(source TEXT,scope_type TEXT,scope_key TEXT,behavior_type TEXT,behavior_key TEXT,total_count INTEGER,first_seen TEXT,last_seen TEXT,daily_json TEXT,PRIMARY KEY(source,scope_type,scope_key,behavior_type,behavior_key));
CREATE TABLE IF NOT EXISTS learner_group_state(source TEXT,event_day TEXT,behavior_type TEXT,behavior_key TEXT,event_count INTEGER,users_json TEXT,devices_json TEXT,departments_json TEXT,related_json TEXT,representative_json TEXT,PRIMARY KEY(source,event_day,behavior_type,behavior_key));
CREATE TABLE IF NOT EXISTS learner_finding_signatures(source TEXT,behavior_type TEXT,behavior_key TEXT,finding_id TEXT,PRIMARY KEY(source,behavior_type,behavior_key,finding_id));
CREATE TABLE IF NOT EXISTS learner_source_state(source TEXT PRIMARY KEY,event_count INTEGER,last_event_time TEXT,last_event_id TEXT,updated_at TEXT,engine_version TEXT);
CREATE TABLE IF NOT EXISTS learner_operational_findings(
 operational_id TEXT PRIMARY KEY,source TEXT NOT NULL,primary_event_id TEXT,created_at TEXT,
 gate_visible INTEGER NOT NULL DEFAULT 0,gate_category TEXT,title TEXT,summary TEXT,
 person_key TEXT,endpoint_key TEXT,user_name TEXT,user_id TEXT,email TEXT,hostname TEXT,department TEXT,
 representative_type TEXT,has_new_behavior INTEGER DEFAULT 0,has_frequency_spike INTEGER DEFAULT 0,has_similar_group INTEGER DEFAULT 0,
 observed_json TEXT,baseline_json TEXT,reasons_json TEXT,evidence_json TEXT,gate_reasons_json TEXT,
 behaviors_json TEXT,related_events_json TEXT,original_finding_ids_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_finding_source_time ON learner_findings(source,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_finding_type_time ON learner_findings(finding_type,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_finding_source_event ON learner_findings(source,event_id);
CREATE INDEX IF NOT EXISTS idx_behavior_scope ON behavior_stats(scope_type,scope_key,source);
CREATE INDEX IF NOT EXISTS idx_processed_signature ON processed_behaviors(source,scope_type,scope_key,behavior_type,behavior_key,event_time);
CREATE INDEX IF NOT EXISTS idx_operational_gate_time ON learner_operational_findings(gate_visible,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_operational_source_gate_time ON learner_operational_findings(source,gate_visible,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_operational_source_time ON learner_operational_findings(source,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_operational_new_time ON learner_operational_findings(has_new_behavior,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_operational_frequency_time ON learner_operational_findings(has_frequency_spike,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_operational_similar_time ON learner_operational_findings(has_similar_group,created_at DESC);
""")
            columns = {row[1] for row in db.execute("PRAGMA table_info(learner_findings)")}
            if "gate_visible" not in columns:
                db.execute("ALTER TABLE learner_findings ADD COLUMN gate_visible INTEGER DEFAULT 0")
            if "gate_json" not in columns:
                db.execute("ALTER TABLE learner_findings ADD COLUMN gate_json TEXT")
            db.execute("CREATE INDEX IF NOT EXISTS idx_finding_gate_time ON learner_findings(gate_visible,created_at DESC)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_learner_signature_lookup ON learner_finding_signatures(source,behavior_type,behavior_key)")
            raw = db.execute("SELECT EXISTS(SELECT 1 FROM learner_findings)").fetchone()[0]
            materialized = db.execute("SELECT EXISTS(SELECT 1 FROM learner_operational_findings)").fetchone()[0]
            needs_backfill = bool(raw and not materialized)
        if needs_backfill:
            self.rebuild_operational()

    def findings(self, source="", finding_type="", start="", end="", limit=30, offset=0, visible_only=True):
        query = "SELECT * FROM learner_findings WHERE 1=1"
        params = []
        if visible_only:
            query += " AND gate_visible=1"
        for clause, value in (("source=?", source), ("finding_type=?", finding_type), ("created_at>=?", start), ("created_at<?", end)):
            if value:
                query += " AND " + clause
                params.append(value)
        count_query = query.replace("SELECT *", "SELECT COUNT(*)", 1)
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        with self.connect() as db:
            total = db.execute(count_query, params).fetchone()[0]
            rows = db.execute(query, [*params, limit, offset]).fetchall()
        return {"items": [self.decode(row) for row in rows], "total": total}

    @staticmethod
    def _operational_id(source, primary):
        return "operational-" + hashlib.sha256(f"{source}:{primary}".encode()).hexdigest()[:24]

    @classmethod
    def _materialize_group(cls, rows):
        decoded = [cls.decode(row) for row in rows]
        visible_items = [item for item in decoded if item.get("gate_visible")]
        display_items = visible_items or decoded
        representative = display_items[0]
        primary = representative.get("event_id") or representative["finding_id"]
        behaviors, related, families, gate_reasons = [], [], [], []
        behavior_seen, related_seen, family_seen, reason_seen = set(), set(), set(), set()
        for item in decoded:
            observed = item.get("observed") or {}
            for value in observed.get("newBehaviors") or [observed]:
                pair = (str(value.get("behaviorType", "")), str(value.get("value", "")))
                if all(pair) and pair not in behavior_seen:
                    behavior_seen.add(pair)
                    behaviors.append({"type": pair[0], "value": pair[1]})
            for event_id in item.get("related_event_ids") or []:
                if event_id not in related_seen:
                    related_seen.add(event_id)
                    related.append(event_id)
        # Review cards only describe evidence which actually passed the gate.
        for item in display_items:
            gate = item.get("gate") or {}
            for family in gate.get("evidenceFamilies") or []:
                if family not in family_seen:
                    family_seen.add(family)
                    families.append(family)
            for reason in gate.get("reasons") or []:
                if reason not in reason_seen:
                    reason_seen.add(reason)
                    gate_reasons.append(reason)
        types = {item["finding_type"] for item in decoded}
        identity = ("event:" if representative.get("event_id") else "finding:") + primary
        return (
            cls._operational_id(representative["source"], identity), representative["source"], representative.get("event_id"),
            max((item.get("created_at") or "" for item in decoded)), int(bool(visible_items)),
            "REVIEW_REQUIRED" if visible_items else "ANALYSIS_ONLY", representative.get("title"), representative.get("summary"),
            representative.get("person_key"), representative.get("endpoint_key"), representative.get("user_name"),
            representative.get("user_id"), representative.get("email"), representative.get("hostname"), representative.get("department"),
            representative.get("finding_type"), int("NEW_BEHAVIOR" in types), int("FREQUENCY_SPIKE" in types), int("SIMILAR_GROUP" in types),
            json.dumps(representative.get("observed") or {}, ensure_ascii=False), json.dumps(representative.get("baseline") or {}, ensure_ascii=False),
            json.dumps(representative.get("reasons") or [], ensure_ascii=False), json.dumps(families, ensure_ascii=False),
            json.dumps(gate_reasons, ensure_ascii=False), json.dumps(behaviors, ensure_ascii=False), json.dumps(related, ensure_ascii=False),
            json.dumps([item["finding_id"] for item in decoded]),
        )

    def rebuild_operational(self, source="", event_ids=None):
        """Materialize UI rows outside the request path; optionally refresh affected events."""
        where, params = " WHERE 1=1", []
        with self.connect() as db:
            if source:
                where += " AND source=?"
                params.append(source)
            if event_ids is not None:
                ids = sorted({event_id for event_id in event_ids if event_id})
                if not ids:
                    return 0
                db.execute("CREATE TEMP TABLE operational_events(event_id TEXT PRIMARY KEY)")
                db.executemany("INSERT INTO operational_events VALUES(?)", [(value,) for value in ids])
                where += " AND event_id IN (SELECT event_id FROM operational_events)"
                if source:
                    db.execute("DELETE FROM learner_operational_findings WHERE source=? AND primary_event_id IN (SELECT event_id FROM operational_events)", (source,))
            elif source:
                db.execute("DELETE FROM learner_operational_findings WHERE source=?", (source,))
            else:
                db.execute("DELETE FROM learner_operational_findings")
            rows = db.execute(
                "SELECT * FROM learner_findings" + where +
                " ORDER BY source,CASE WHEN event_id IS NULL OR event_id='' THEN 'finding:'||finding_id ELSE 'event:'||event_id END,created_at DESC", params
            )
            output, group, key = [], [], None
            for row in rows:
                row_key = (row["source"], ("event:" + row["event_id"]) if row["event_id"] else ("finding:" + row["finding_id"]))
                if key is not None and row_key != key:
                    output.append(self._materialize_group(group)); group = []
                key = row_key; group.append(row)
                if len(output) >= 1000:
                    db.executemany("INSERT OR REPLACE INTO learner_operational_findings VALUES(" + ",".join("?" * 27) + ")", output); output.clear()
            if group:
                output.append(self._materialize_group(group))
            if output:
                db.executemany("INSERT OR REPLACE INTO learner_operational_findings VALUES(" + ",".join("?" * 27) + ")", output)
            return db.execute("SELECT changes()").fetchone()[0]

    def operational_findings(self, source="", finding_type="", start="", end="", limit=30, offset=0, visible_only=True):
        query = "SELECT * FROM learner_operational_findings WHERE 1=1"
        params = []
        if visible_only:
            query += " AND gate_visible=1"
        if source:
            query += " AND source=?"; params.append(source)
        type_column = {"NEW_BEHAVIOR": "has_new_behavior", "FREQUENCY_SPIKE": "has_frequency_spike", "SIMILAR_GROUP": "has_similar_group"}.get(finding_type)
        if finding_type:
            if type_column:
                query += f" AND {type_column}=1"
            else:
                query += " AND representative_type=?"; params.append(finding_type)
        for clause, value in (("created_at>=?", start), ("created_at<?", end)):
            if value:
                query += " AND " + clause; params.append(value)
        count_query = query.replace("SELECT *", "SELECT COUNT(*)", 1)
        with self.connect() as db:
            total = db.execute(count_query, params).fetchone()[0]
            rows = db.execute(query + " ORDER BY created_at DESC LIMIT ? OFFSET ?", [*params, limit, offset]).fetchall()
        return {"items": [self.decode_operational(row) for row in rows], "total": total}

    @classmethod
    def decode_operational(cls, row):
        item = dict(row)
        mapping = {"observed_json": "observed", "baseline_json": "baseline", "reasons_json": "reasons", "evidence_json": "evidenceFamilies", "gate_reasons_json": "gateReasons", "behaviors_json": "behaviors", "related_events_json": "relatedEvents", "original_finding_ids_json": "originalFindingIds"}
        for raw, target in mapping.items():
            item[target] = json.loads(item.pop(raw) or ("{}" if target in {"observed", "baseline"} else "[]"))
        item.update(finding_id=item.pop("operational_id"), finding_type=item.pop("representative_type"), event_id=item.get("primary_event_id"), primaryEventId=item.get("primary_event_id") or item["finding_id"], related_event_ids=item["relatedEvents"])
        item["originalFindingTypes"] = [name for name, flag in (("NEW_BEHAVIOR", item["has_new_behavior"]), ("FREQUENCY_SPIKE", item["has_frequency_spike"]), ("SIMILAR_GROUP", item["has_similar_group"])) if flag]
        item["gate"] = {"visible": bool(item["gate_visible"]), "category": item["gate_category"], "evidenceFamilies": item["evidenceFamilies"], "reasons": item["gateReasons"]}
        return item

    def operational_finding(self, finding_id):
        with self.connect() as db:
            row = db.execute("SELECT * FROM learner_operational_findings WHERE operational_id=?", (finding_id,)).fetchone()
            if not row:
                return None
            item = self.decode_operational(row)
            if row["primary_event_id"]:
                originals = db.execute("SELECT * FROM learner_findings WHERE source=? AND event_id=? ORDER BY created_at DESC", (row["source"], row["primary_event_id"])).fetchall()
            else:
                raw_id = item["originalFindingIds"][0]
                originals = db.execute("SELECT * FROM learner_findings WHERE finding_id=?", (raw_id,)).fetchall()
        item["originalFindings"] = [self.decode(value) for value in originals]
        return item

    def finding_rows(self, source="", finding_type="", start="", end="", limit=200):
        return self.findings(source, finding_type, start, end, limit, 0, False)["items"]

    def summary(self, start="", end=""):
        where, params = " WHERE 1=1", []
        for clause, value in (("created_at>=?", start), ("created_at<?", end)):
            if value:
                where += " AND " + clause; params.append(value)
        with self.connect() as db:
            operational = db.execute("SELECT COUNT(*) total,SUM(gate_visible) review FROM learner_operational_findings" + where, params).fetchone()
            behavior = db.execute("SELECT SUM(finding_type='NEW_BEHAVIOR') new_behavior,SUM(finding_type='FREQUENCY_SPIKE') frequency_spike FROM learner_findings" + where, params).fetchone()
            daily = db.execute("SELECT substr(created_at,1,10) day,COUNT(*) count FROM learner_operational_findings" + where + " GROUP BY day ORDER BY day DESC LIMIT 14", params).fetchall()
            sources = db.execute("SELECT source,COUNT(*) count FROM learner_operational_findings" + where + " GROUP BY source ORDER BY count DESC", params).fetchall()
        return {"review": operational["review"] or 0, "total": operational["total"] or 0, "newBehavior": behavior["new_behavior"] or 0, "frequencySpike": behavior["frequency_spike"] or 0, "daily": [dict(item) for item in reversed(daily)], "sources": [dict(item) for item in sources]}

    def finding(self, fid):
        operational = self.operational_finding(fid)
        if operational:
            return operational
        with self.connect() as db:
            row = db.execute("SELECT * FROM learner_findings WHERE finding_id=?", (fid,)).fetchone()
        return self.decode(row) if row else None

    @staticmethod
    def decode(row):
        item = dict(row)
        for key in ("observed_json", "reasons_json", "baseline_json", "related_event_ids_json", "gate_json"):
            item[key.removesuffix("_json")] = json.loads(item.pop(key) or ("[]" if key in {"reasons_json", "related_event_ids_json"} else "{}"))
        return item
