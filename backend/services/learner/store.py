import hashlib,json,sqlite3
from pathlib import Path
SCHEMA_VERSION="3"
class LearnerStore:
 def __init__(self,root:Path,path:Path|None=None): self.path=path or root/"cache/index/learner_cache.db";self.initialize()
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
CREATE TABLE IF NOT EXISTS learner_analysis_state(source TEXT,scope_type TEXT,scope_key TEXT,behavior_type TEXT,behavior_key TEXT,total_count INTEGER,first_seen TEXT,last_seen TEXT,daily_json TEXT,PRIMARY KEY(source,scope_type,scope_key,behavior_type,behavior_key));
CREATE TABLE IF NOT EXISTS learner_group_state(source TEXT,event_day TEXT,behavior_type TEXT,behavior_key TEXT,event_count INTEGER,users_json TEXT,devices_json TEXT,departments_json TEXT,related_json TEXT,representative_json TEXT,PRIMARY KEY(source,event_day,behavior_type,behavior_key));
CREATE TABLE IF NOT EXISTS learner_finding_signatures(source TEXT,behavior_type TEXT,behavior_key TEXT,finding_id TEXT,PRIMARY KEY(source,behavior_type,behavior_key,finding_id));
CREATE TABLE IF NOT EXISTS learner_source_state(source TEXT PRIMARY KEY,event_count INTEGER,last_event_time TEXT,last_event_id TEXT,updated_at TEXT,engine_version TEXT);
CREATE INDEX IF NOT EXISTS idx_finding_source_time ON learner_findings(source,created_at DESC);CREATE INDEX IF NOT EXISTS idx_finding_type_time ON learner_findings(finding_type,created_at DESC);CREATE INDEX IF NOT EXISTS idx_behavior_scope ON behavior_stats(scope_type,scope_key,source);CREATE INDEX IF NOT EXISTS idx_processed_signature ON processed_behaviors(source,scope_type,scope_key,behavior_type,behavior_key,event_time);''')
   columns={row[1] for row in d.execute("PRAGMA table_info(learner_findings)")}
   if "gate_visible" not in columns:d.execute("ALTER TABLE learner_findings ADD COLUMN gate_visible INTEGER DEFAULT 0")
   if "gate_json" not in columns:d.execute("ALTER TABLE learner_findings ADD COLUMN gate_json TEXT")
   d.execute("CREATE INDEX IF NOT EXISTS idx_finding_gate_time ON learner_findings(gate_visible,created_at DESC)")
   d.execute("CREATE INDEX IF NOT EXISTS idx_learner_signature_lookup ON learner_finding_signatures(source,behavior_type,behavior_key)")
 def findings(self,source="",finding_type="",start="",end="",limit=30,offset=0,visible_only=True):
  q="SELECT * FROM learner_findings WHERE 1=1";p=[]
  if visible_only:q+=" AND gate_visible=1"
  for clause,value in (("source=?",source),("finding_type=?",finding_type),("created_at>=?",start),("created_at<?",end)):
   if value:q+=" AND "+clause;p.append(value)
  count_q=q.replace("SELECT *","SELECT COUNT(*)",1)
  q+=" ORDER BY created_at DESC LIMIT ? OFFSET ?";page_params=[*p,limit,offset]
  with self.connect() as d: total=d.execute(count_q,p).fetchone()[0];rows=d.execute(q,page_params).fetchall()
  return {"items":[self.decode(row) for row in rows],"total":total}
 def operational_findings(self,source="",finding_type="",start="",end="",limit=30,offset=0,visible_only=True):
  """Page by source + primary event and batch-load its behavior findings."""
  group_key="CASE WHEN event_id IS NULL OR event_id='' THEN finding_id ELSE event_id END"
  where=" WHERE 1=1";params=[]
  if visible_only:where+=" AND gate_visible=1"
  for clause,value in (("source=?",source),("finding_type=?",finding_type),("created_at>=?",start),("created_at<?",end)):
   if value:where+=" AND "+clause;params.append(value)
  grouped=f" FROM learner_findings{where} GROUP BY source,{group_key}"
  with self.connect() as d:
   total=d.execute("SELECT COUNT(*) FROM (SELECT 1"+grouped+")",params).fetchone()[0]
   keys=d.execute(f"SELECT source,{group_key} operational_key,MAX(created_at) sort_time"+grouped+" ORDER BY sort_time DESC LIMIT ? OFFSET ?",[*params,limit,offset]).fetchall()
   if not keys:return {"items":[],"total":total}
   key_where=" OR ".join(f"(source=? AND {group_key}=?)" for _ in keys);key_params=[value for row in keys for value in (row["source"],row["operational_key"])]
   rows=d.execute(f"SELECT * FROM learner_findings WHERE {key_where} ORDER BY created_at DESC",key_params).fetchall()
  buckets={}
  for row in rows:buckets.setdefault((row["source"],row["event_id"] or row["finding_id"]),[]).append(row)
  return {"items":[self._operational(buckets[(row["source"],row["operational_key"])],finding_type,visible_only) for row in keys],"total":total}
 @classmethod
 def _operational(cls,rows,preferred_type="",visible_only=False):
  decoded=[cls.decode(row) for row in rows]
  candidates=[item for item in decoded if (not preferred_type or item["finding_type"]==preferred_type) and (not visible_only or item.get("gate_visible"))] or decoded
  representative=candidates[0].copy();behaviors=[];seen_behaviors=set();related=[];seen_related=set();gate_reasons=[];seen_reasons=set();families=[];finding_ids=[];finding_types=[]
  for item in decoded:
   finding_ids.append(item["finding_id"])
   if item["finding_type"] not in finding_types:finding_types.append(item["finding_type"])
   observed=item.get("observed") or {};values=observed.get("newBehaviors") or [observed]
   for value in values:
    pair=(str(value.get("behaviorType", "")),str(value.get("value", "")))
    if all(pair) and pair not in seen_behaviors:seen_behaviors.add(pair);behaviors.append({"type":pair[0],"value":pair[1]})
   for event_id in item.get("related_event_ids") or []:
    if event_id not in seen_related:seen_related.add(event_id);related.append(event_id)
   gate=item.get("gate") or {}
   for family in gate.get("evidenceFamilies") or []:
    if family not in families:families.append(family)
   for reason in gate.get("reasons") or []:
    if reason not in seen_reasons:seen_reasons.add(reason);gate_reasons.append(reason)
  visible=any(bool(item.get("gate_visible")) for item in decoded);primary=representative.get("event_id") or representative["finding_id"]
  originals=[{"findingId":item["finding_id"],"findingType":item["finding_type"],"observed":item.get("observed"),"baseline":item.get("baseline"),"gate":item.get("gate"),"reasons":item.get("reasons"),"relatedEvents":item.get("related_event_ids")} for item in decoded]
  representative.update(finding_id="operational-"+hashlib.sha256(f'{representative["source"]}:{primary}'.encode()).hexdigest()[:24],primaryEventId=primary,originalFindingIds=finding_ids,originalFindingTypes=finding_types,originalFindings=originals,behaviors=behaviors,evidenceFamilies=families,gateReasons=gate_reasons,relatedEvents=related,related_event_ids=related,gate_visible=int(visible),gate={"visible":visible,"category":"REVIEW_REQUIRED" if visible else "ANALYSIS_ONLY","evidenceFamilies":families,"reasons":gate_reasons})
  return representative
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
