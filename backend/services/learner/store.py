import json,sqlite3
from pathlib import Path
SCHEMA_VERSION="2"
class LearnerStore:
 def __init__(self,root:Path): self.path=root/"cache/index/learner_cache.db";self.initialize()
 def connect(self):
  self.path.parent.mkdir(parents=True,exist_ok=True);db=sqlite3.connect(self.path,timeout=30);db.row_factory=sqlite3.Row;db.execute("PRAGMA busy_timeout=30000");db.execute("PRAGMA journal_mode=WAL");return db
 def initialize(self):
  with self.connect() as d:
   d.executescript('''CREATE TABLE IF NOT EXISTS learner_runs(run_id TEXT PRIMARY KEY,mode TEXT,source TEXT,history_start TEXT,history_end TEXT,target_start TEXT,target_end TEXT,status TEXT,started_at TEXT,finished_at TEXT,processed_events INTEGER DEFAULT 0,last_error TEXT,schema_version TEXT);
CREATE TABLE IF NOT EXISTS behavior_stats(source TEXT,scope_type TEXT,scope_key TEXT,behavior_type TEXT,behavior_key TEXT,count_1d INTEGER,count_7d INTEGER,count_30d INTEGER,count_90d INTEGER,count_180d INTEGER,count_all INTEGER,first_seen TEXT,last_seen TEXT,updated_at TEXT,PRIMARY KEY(source,scope_type,scope_key,behavior_type,behavior_key));
CREATE TABLE IF NOT EXISTS learner_findings(finding_id TEXT PRIMARY KEY,source TEXT,event_id TEXT,finding_type TEXT,title TEXT,summary TEXT,person_key TEXT,endpoint_key TEXT,user_name TEXT,user_id TEXT,email TEXT,hostname TEXT,department TEXT,observed_json TEXT,reasons_json TEXT,baseline_json TEXT,related_event_ids_json TEXT,created_at TEXT,gate_visible INTEGER DEFAULT 0,gate_json TEXT);
CREATE TABLE IF NOT EXISTS processed_behaviors(source TEXT,event_id TEXT,event_time TEXT,scope_type TEXT,scope_key TEXT,behavior_type TEXT,behavior_key TEXT,PRIMARY KEY(source,event_id,scope_type,scope_key,behavior_type,behavior_key));
CREATE TABLE IF NOT EXISTS learner_processed_events(source TEXT,event_id TEXT,event_time TEXT,row_hash TEXT,PRIMARY KEY(source,event_id));
CREATE TABLE IF NOT EXISTS learner_watermarks(source TEXT PRIMARY KEY,last_event_time TEXT,last_event_id TEXT,updated_at TEXT);
CREATE INDEX IF NOT EXISTS idx_finding_source_time ON learner_findings(source,created_at DESC);CREATE INDEX IF NOT EXISTS idx_finding_type_time ON learner_findings(finding_type,created_at DESC);CREATE INDEX IF NOT EXISTS idx_behavior_scope ON behavior_stats(scope_type,scope_key,source);CREATE INDEX IF NOT EXISTS idx_processed_signature ON processed_behaviors(source,scope_type,scope_key,behavior_type,behavior_key,event_time);''')
   columns={row[1] for row in d.execute("PRAGMA table_info(learner_findings)")}
   if "gate_visible" not in columns:d.execute("ALTER TABLE learner_findings ADD COLUMN gate_visible INTEGER DEFAULT 0")
   if "gate_json" not in columns:d.execute("ALTER TABLE learner_findings ADD COLUMN gate_json TEXT")
   d.execute("CREATE INDEX IF NOT EXISTS idx_finding_gate_time ON learner_findings(gate_visible,created_at DESC)")
 def findings(self,source="",finding_type="",start="",end="",limit=30,offset=0,visible_only=True):
  q="SELECT * FROM learner_findings WHERE 1=1";p=[]
  if visible_only:q+=" AND gate_visible=1"
  for clause,value in (("source=?",source),("finding_type=?",finding_type),("created_at>=?",start),("created_at<?",end)):
   if value:q+=" AND "+clause;p.append(value)
  count_q=q.replace("SELECT *","SELECT COUNT(*)",1)
  q+=" ORDER BY created_at DESC LIMIT ? OFFSET ?";page_params=[*p,limit,offset]
  with self.connect() as d: total=d.execute(count_q,p).fetchone()[0];rows=d.execute(q,page_params).fetchall()
  return {"items":[self.decode(row) for row in rows],"total":total}
 def finding_rows(self,source="",finding_type="",start="",end="",limit=200):
  return self.findings(source,finding_type,start,end,limit,0,False)["items"]
 def summary(self,start="",end=""):
  where=" WHERE 1=1";params=[]
  for clause,value in (("created_at>=?",start),("created_at<?",end)):
   if value:where+=" AND "+clause;params.append(value)
  with self.connect() as d:
   row=d.execute("SELECT COUNT(*) total, SUM(CASE WHEN gate_visible=1 THEN 1 ELSE 0 END) review, SUM(CASE WHEN finding_type='NEW_BEHAVIOR' THEN 1 ELSE 0 END) new_behavior, SUM(CASE WHEN finding_type='FREQUENCY_SPIKE' THEN 1 ELSE 0 END) frequency_spike FROM learner_findings"+where,params).fetchone()
   daily=d.execute("SELECT substr(created_at,1,10) day, COUNT(*) count FROM learner_findings"+where+" GROUP BY day ORDER BY day DESC LIMIT 14",params).fetchall()
   source=d.execute("SELECT source, COUNT(*) count FROM learner_findings"+where+" GROUP BY source ORDER BY count DESC",params).fetchall()
  return {"review":row["review"] or 0,"total":row["total"] or 0,"newBehavior":row["new_behavior"] or 0,"frequencySpike":row["frequency_spike"] or 0,"daily":[dict(item) for item in reversed(daily)],"sources":[dict(item) for item in source]}
 def finding(self,fid):
  with self.connect() as d:r=d.execute("SELECT * FROM learner_findings WHERE finding_id=?",(fid,)).fetchone()
  return self.decode(r) if r else None
 @staticmethod
 def decode(r):
  x=dict(r)
  for k in ("observed_json","reasons_json","baseline_json","related_event_ids_json","gate_json"):x[k.removesuffix("_json")]=json.loads(x.pop(k) or ("[]" if k in {"reasons_json","related_event_ids_json"} else "{}"))
  return x
