import hashlib,json,sqlite3,uuid
from collections import defaultdict
from datetime import datetime,timedelta,timezone
from pathlib import Path
from .common import SOURCES,WINDOWS
from .store import LearnerStore,SCHEMA_VERSION
from .adapters import ADAPTERS
BEHAVIOR_LABELS={"process":"프로세스 실행","parent_process":"상위 프로세스","parent_child":"프로세스 실행 조합","command_line":"명령줄 실행","file_path":"파일 접근","detection_rule":"탐지 규칙","sender":"메일 발신자","sender_domain":"발신 도메인","sender_ip":"발신 IP","recipient":"메일 수신자","subject":"메일 제목","url":"URL","url_domain":"접속 도메인","attachment_extension":"첨부파일 형식","receiver":"메일 수신자","receiver_domain":"수신 도메인","mail_size":"메일 크기","hour":"발송 시간대","user":"사용자 활동","device":"장비 활동","event_type":"이벤트 유형","destination":"전송 대상","destination_domain":"대상 도메인","destination_type":"대상 유형","file_extension":"파일 형식","file_size":"파일 크기","destination_ip":"목적지 IP","destination_port":"목적지 포트","protocol":"통신 프로토콜","application":"애플리케이션","source_zone":"출발지 구역","destination_zone":"목적지 구역"}
class LearnerCancelled(Exception): pass
class LearnerService:
 def __init__(self,root:Path): self.root=root;self.events=root/"cache/index/events_index.db";self.store=LearnerStore(root)
 def _rows(self,sources,target_start="",target_end="",after=None):
  if not self.events.exists(): raise RuntimeError("events_index.db가 없습니다. 먼저 인덱싱을 실행하세요.")
  uri=f"{self.events.resolve().as_uri()}?mode=ro";db=sqlite3.connect(uri,uri=True);db.row_factory=sqlite3.Row;db.execute("PRAGMA query_only=ON");db.execute("PRAGMA busy_timeout=30000")
  q=f"SELECT kind,record_id,event_time,row_json FROM event_list_rows WHERE kind IN ({','.join('?'*len(sources))})";p=list(sources)
  if after:q+=" AND (event_time>? OR (event_time=? AND record_id>?))";p += [after[0],after[0],after[1]]
  q+=" ORDER BY event_time,record_id";rows=db.execute(q,p).fetchall();db.close();return rows
 def run(self,mode="incremental",sources=None,target_start="",target_end="",progress=lambda x:None,cancelled=lambda:False):
  sources=[s for s in (sources or SOURCES) if s in SOURCES];run_id=str(uuid.uuid4());now=datetime.now(timezone.utc).isoformat();
  with self.store.connect() as d:
   if mode=="full": d.execute("DELETE FROM behavior_stats");d.execute("DELETE FROM learner_findings");d.execute("DELETE FROM processed_behaviors");d.execute("DELETE FROM learner_watermarks");d.execute("DELETE FROM learner_processed_events")
   d.execute("INSERT INTO learner_runs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(run_id,mode,",".join(sources),None,None,target_start or None,target_end or None,"running",now,None,0,None,SCHEMA_VERSION))
  try:
   processed=0
   source_totals={source:len(self._rows([source])) for source in sources}
   total_events=sum(source_totals.values())
   progress({"message":"분석 준비 완료","currentSource":None,"sourceProcessed":0,"sourceTotal":0,"totalProcessed":0,"totalEvents":total_events,"progressPercent":0.0})
   for source in sources:
    if cancelled(): raise LearnerCancelled("분석 중단 요청")
    after=None
    if mode!="full":
     with self.store.connect() as d:
      w=d.execute("SELECT last_event_time,last_event_id FROM learner_watermarks WHERE source=?",(source,)).fetchone();after=tuple(w) if w else None
    all_rows=self._rows([source])
    rows=all_rows
    if mode!="full":
     current={r["record_id"]:hashlib.sha256((r["event_time"]+r["row_json"]).encode()).hexdigest() for r in all_rows}
     with self.store.connect() as d: known={r[0]:r[1] for r in d.execute("SELECT event_id,row_hash FROM learner_processed_events WHERE source=?",(source,))}
     changed=any(event_id in known and known[event_id]!=digest for event_id,digest in current.items()) or any(event_id not in current for event_id in known)
     if changed:
      progress({"message":f"{source} · 재인덱싱/삭제 감지 · Source 통계 재구성","currentSource":source,"sourceProcessed":0,"sourceTotal":len(all_rows),"totalProcessed":processed,"totalEvents":total_events,"progressPercent":round(processed*100/total_events,1) if total_events else 100.0})
      with self.store.connect() as d:
       d.execute("DELETE FROM behavior_stats WHERE source=?",(source,));d.execute("DELETE FROM learner_findings WHERE source=?",(source,));d.execute("DELETE FROM processed_behaviors WHERE source=?",(source,));d.execute("DELETE FROM learner_processed_events WHERE source=?",(source,))
     else: rows=[r for r in all_rows if r["record_id"] not in known]
    progress({"message":f"{source} · {len(rows):,}개 이벤트 분석","currentSource":source,"sourceProcessed":0,"sourceTotal":len(rows),"totalProcessed":processed,"totalEvents":total_events,"progressPercent":round(processed*100/total_events,1) if total_events else 100.0})
    def source_progress(done):
     overall=processed+done
     progress({"message":f"{source} 분석 중","currentSource":source,"sourceProcessed":done,"sourceTotal":len(rows),"totalProcessed":overall,"totalEvents":total_events,"progressPercent":round(overall*100/total_events,1) if total_events else 100.0})
    self._process_source(source,rows,target_start,target_end,source_progress,cancelled)
    with self.store.connect() as d:
     for r in rows:d.execute("INSERT OR REPLACE INTO learner_processed_events VALUES(?,?,?,?)",(source,r["record_id"],r["event_time"],hashlib.sha256((r["event_time"]+r["row_json"]).encode()).hexdigest()))
    processed+=len(rows)
    if rows:
     last=rows[-1]
     with self.store.connect() as d:d.execute("INSERT OR REPLACE INTO learner_watermarks VALUES(?,?,?,?)",(source,last["event_time"],last["record_id"],datetime.now(timezone.utc).isoformat()))
   self._refresh_stats(sources)
   with self.store.connect() as d:
    bounds=d.execute("SELECT MIN(event_time),MAX(event_time) FROM processed_behaviors").fetchone();d.execute("UPDATE learner_runs SET history_start=?,history_end=?,status='completed',finished_at=?,processed_events=? WHERE run_id=?",(bounds[0],bounds[1],datetime.now(timezone.utc).isoformat(),processed,run_id))
   return {"runId":run_id,"processedEvents":processed,"findings":len(self.store.findings(limit=100000))}
  except LearnerCancelled:
   with self.store.connect() as d:d.execute("UPDATE learner_runs SET status='cancelled',finished_at=?,last_error=? WHERE run_id=?",(datetime.now(timezone.utc).isoformat(),"사용자 요청으로 중단됨",run_id))
   raise
  except Exception as e:
   with self.store.connect() as d:d.execute("UPDATE learner_runs SET status='failed',finished_at=?,last_error=? WHERE run_id=?",(datetime.now(timezone.utc).isoformat(),f"{type(e).__name__}: {e}",run_id))
   raise
 def _process_source(self,source,rows,target_start,target_end,progress=lambda _done:None,cancelled=lambda:False):
  groups=defaultdict(list)
  with self.store.connect() as d:
   for row_number,raw in enumerate(rows,1):
    if row_number==1 or row_number%100==0:
     if cancelled(): raise LearnerCancelled("분석 중단 요청")
    if row_number%500==0: progress(row_number)
    row=json.loads(raw["row_json"]); event_time=raw["event_time"];event_id=raw["record_id"]
    bs=ADAPTERS[source](event_id,event_time,row)
    in_target=(not target_start or event_time>=target_start) and (not target_end or event_time<target_end+"T99")
    new_behaviors=[]
    for b in bs:
     histories={}
     for st,sk in b.scopes():
      past=d.execute("SELECT event_time,event_id FROM processed_behaviors WHERE source=? AND scope_type=? AND scope_key=? AND behavior_type=? AND behavior_key=? AND event_time<? ORDER BY event_time",(source,st,sk,b.behavior_type,b.behavior_key,event_time)).fetchall();histories[st]=[x[0] for x in past]
      d.execute("INSERT OR IGNORE INTO processed_behaviors VALUES(?,?,?,?,?,?,?)",(source,event_id,event_time,st,sk,b.behavior_type,b.behavior_key))
     if in_target and not histories.get("device") and not histories.get("user") and not histories.get("global"):
      new_behaviors.append((b,histories))
     groups[(event_time[:10],b.behavior_type,b.behavior_key)].append(b)
    if new_behaviors:
     primary=new_behaviors[0][0]
     reasons=[f"{BEHAVIOR_LABELS.get(b.behavior_type,b.behavior_type)} '{b.observed.get('value','')}'이(가) 전체 과거 이력에서 처음 확인되었습니다." for b,_history in new_behaviors]
     behavior_baselines=[{"behaviorType":b.behavior_type,"behaviorKey":b.behavior_key,"counts":{scope:len(values) for scope,values in history.items()}} for b,history in new_behaviors]
     first_counts=behavior_baselines[0]["counts"]
     self._finding(d,primary,"NEW_BEHAVIOR","새로운 행동",f"하나의 이벤트에서 새로운 행동 {len(new_behaviors):,}개가 확인되었습니다.",reasons,{**first_counts,"behaviors":behavior_baselines},[event_id],observed={"event":row,"newBehaviors":[b.observed for b,_history in new_behaviors]})
   progress(len(rows))
   if cancelled(): raise LearnerCancelled("분석 중단 요청")
   for (_,bt,bk),items in groups.items():
    if len(items)>=10:
     b=items[0];self._finding(d,b,"SIMILAR_GROUP","비슷한 이벤트",f"동일한 {BEHAVIOR_LABELS.get(bt,bt)}이(가) {len(items):,}건 확인되었습니다.",[f"같은 분석일에 정규화된 행동 값이 {len(items):,}건 일치했습니다."],{"groupCount":len(items)},[x.event_id for x in items[:100]])
   # Explainable spike: at least 10 today and >=3x prior seven-day daily average.
   for (day,bt,bk),items in groups.items():
    if len(items)<10:continue
    b=items[0];start=(datetime.fromisoformat(day)-timedelta(days=7)).isoformat()
    prior=d.execute("SELECT COUNT(DISTINCT event_id) FROM processed_behaviors WHERE source=? AND behavior_type=? AND behavior_key=? AND event_time>=? AND event_time<?",(source,bt,bk,start,day)).fetchone()[0]
    avg=prior/7
    if avg>0 and len(items)>=max(10,avg*3):self._finding(d,b,"FREQUENCY_SPIKE","최근 활동 증가",f"하루 {len(items):,}건으로 최근 7일 평균보다 크게 증가했습니다.",[f"최근 1일 {len(items):,}건",f"이전 7일 일평균 {avg:.1f}건","최소 10건 및 3배 증가 기준을 충족했습니다."],{"count1d":len(items),"prior7d":prior,"priorDailyAverage":avg},[x.event_id for x in items[:100]])
 def _finding(self,d,b,kind,title,summary,reasons,baseline,related,observed=None):
  signature=f"{kind}:{b.source}:{b.event_id}" if kind=="NEW_BEHAVIOR" else f"{kind}:{b.source}:{b.event_id}:{b.behavior_type}:{b.behavior_key}"
  fid=hashlib.sha256(signature.encode()).hexdigest()[:32]
  d.execute("INSERT OR REPLACE INTO learner_findings VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(fid,b.source,b.event_id,kind,title,summary,b.person_key,b.endpoint_key,b.user_name,b.user_id,b.email,b.hostname,b.department,json.dumps(observed if observed is not None else b.observed,ensure_ascii=False),json.dumps(reasons,ensure_ascii=False),json.dumps(baseline,ensure_ascii=False),json.dumps(related),b.event_time))
 def _refresh_stats(self,sources):
  updated=datetime.now(timezone.utc).isoformat()
  with self.store.connect() as d:
   for source in sources:
    anchor_raw=d.execute("SELECT MAX(event_time) FROM processed_behaviors WHERE source=?",(source,)).fetchone()[0]
    if not anchor_raw: continue
    anchor=datetime.fromisoformat(anchor_raw.replace("Z","+00:00"))
    rows=d.execute("SELECT scope_type,scope_key,behavior_type,behavior_key,MIN(event_time),MAX(event_time),COUNT(DISTINCT event_id) FROM processed_behaviors WHERE source=? GROUP BY 1,2,3,4",(source,)).fetchall()
    for r in rows:
     counts=[]
     for days in WINDOWS:
      cutoff=(anchor-timedelta(days=days)).isoformat();counts.append(d.execute("SELECT COUNT(DISTINCT event_id) FROM processed_behaviors WHERE source=? AND scope_type=? AND scope_key=? AND behavior_type=? AND behavior_key=? AND event_time>=?",(source,*r[:4],cutoff)).fetchone()[0])
     d.execute("INSERT OR REPLACE INTO behavior_stats VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(source,*r[:4],*counts,r[6],r[4],r[5],updated))
 def history(self,source,scope_type,scope_key,behavior_type,behavior_key):
  with self.store.connect() as d:r=d.execute("SELECT * FROM behavior_stats WHERE source=? AND scope_type=? AND scope_key=? AND behavior_type=? AND behavior_key=?",(source,scope_type,scope_key,behavior_type,behavior_key)).fetchone()
  return dict(r) if r else None
