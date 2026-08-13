import json,sqlite3
from pathlib import Path
SCHEMA_VERSION="1"
class LearnerStore:
 def __init__(self,root:Path): self.path=root/"cache/index/learner_cache.db";self.initialize()
 def connect(self):
  self.path.parent.mkdir(parents=True,exist_ok=True);db=sqlite3.connect(self.path,timeout=30);db.row_factory=sqlite3.Row;db.execute("PRAGMA busy_timeout=30000");db.execute("PRAGMA journal_mode=WAL");return db
 def initialize(self):
  with self.connect() as d:
   d.executescript('''CREATE TABLE IF NOT EXISTS learner_runs(run_id TEXT PRIMARY KEY,mode TEXT,source TEXT,history_start TEXT,history_end TEXT,target_start TEXT,target_end TEXT,status TEXT,started_at TEXT,finished_at TEXT,processed_events INTEGER DEFAULT 0,last_error TEXT,schema_version TEXT);
CREATE TABLE IF NOT EXISTS behavior_stats(source TEXT,scope_type TEXT,scope_key TEXT,behavior_type TEXT,behavior_key TEXT,count_1d INTEGER,count_7d INTEGER,count_30d INTEGER,count_90d INTEGER,count_180d INTEGER,count_all INTEGER,first_seen TEXT,last_seen TEXT,updated_at TEXT,PRIMARY KEY(source,scope_type,scope_key,behavior_type,behavior_key));
CREATE TABLE IF NOT EXISTS learner_findings(finding_id TEXT PRIMARY KEY,source TEXT,event_id TEXT,finding_type TEXT,title TEXT,summary TEXT,person_key TEXT,endpoint_key TEXT,user_name TEXT,user_id TEXT,email TEXT,hostname TEXT,department TEXT,observed_json TEXT,reasons_json TEXT,baseline_json TEXT,related_event_ids_json TEXT,created_at TEXT);
CREATE TABLE IF NOT EXISTS processed_behaviors(source TEXT,event_id TEXT,event_time TEXT,scope_type TEXT,scope_key TEXT,behavior_type TEXT,behavior_key TEXT,PRIMARY KEY(source,event_id,scope_type,scope_key,behavior_type,behavior_key));
CREATE TABLE IF NOT EXISTS learner_processed_events(source TEXT,event_id TEXT,event_time TEXT,row_hash TEXT,PRIMARY KEY(source,event_id));
CREATE TABLE IF NOT EXISTS learner_watermarks(source TEXT PRIMARY KEY,last_event_time TEXT,last_event_id TEXT,updated_at TEXT);
CREATE INDEX IF NOT EXISTS idx_finding_source_time ON learner_findings(source,created_at DESC);CREATE INDEX IF NOT EXISTS idx_finding_type_time ON learner_findings(finding_type,created_at DESC);CREATE INDEX IF NOT EXISTS idx_behavior_scope ON behavior_stats(scope_type,scope_key,source);CREATE INDEX IF NOT EXISTS idx_processed_signature ON processed_behaviors(source,scope_type,scope_key,behavior_type,behavior_key,event_time);''')
 def findings(self,source="",finding_type="",start="",end="",limit=200):
  q="SELECT * FROM learner_findings WHERE 1=1";p=[]
  for clause,value in (("source=?",source),("finding_type=?",finding_type),("created_at>=?",start),("created_at<?",end)):
   if value:q+=" AND "+clause;p.append(value)
  q+=" ORDER BY created_at DESC LIMIT ?";p.append(limit)
  with self.connect() as d: rows=d.execute(q,p).fetchall()
  return [self.decode(row) for row in rows]
 def finding(self,fid):
  with self.connect() as d:r=d.execute("SELECT * FROM learner_findings WHERE finding_id=?",(fid,)).fetchone()
  return self.decode(r) if r else None
 @staticmethod
 def decode(r):
  x=dict(r)
  for k in ("observed_json","reasons_json","baseline_json","related_event_ids_json"):x[k.removesuffix("_json")]=json.loads(x.pop(k) or ("[]" if k in {"reasons_json","related_event_ids_json"} else "{}"))
  return x
