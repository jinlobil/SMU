import argparse,json,logging,os,signal,sqlite3,threading,traceback,uuid
from datetime import datetime,timezone
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs,urlparse
from backend.services.learner import LearnerService
from system_monitor.collector import acquire_singleton,atomic_json
from system_monitor.logging_utils import configure_agent_logging
class LearnerAgent:
 def __init__(self,root):
  self.root=root;self.directory=root/"runtime/learner";self.database=self.directory/"jobs.db";self.status_path=self.directory/"learner_status.json";self.stop=threading.Event();self.wake=threading.Event();self.current_job_id=None;self.started_at=datetime.now().astimezone().isoformat(timespec="seconds");self.last_error=None;self.directory.mkdir(parents=True,exist_ok=True);self._init()
 def _db(self):d=sqlite3.connect(self.database,timeout=30);d.row_factory=sqlite3.Row;d.execute("PRAGMA busy_timeout=30000");return d
 def _init(self):
  with self._db() as d:d.execute("CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,status TEXT,message TEXT,payload TEXT,result TEXT,error TEXT,created_at TEXT,started_at TEXT,finished_at TEXT)");d.execute("UPDATE jobs SET status='queued',message='Learner 재시작 후 작업 복구 중' WHERE status='running'")
 def now(self):return datetime.now(timezone.utc).isoformat()
 def snapshot(self):return {"status":"running","pid":os.getpid(),"startedAt":self.started_at,"lastHeartbeatAt":datetime.now().astimezone().isoformat(timespec="seconds"),"currentJobId":self.current_job_id,"lastError":self.last_error}
 def heartbeat_loop(self):
  while not self.stop.is_set():atomic_json(self.status_path,self.snapshot());self.stop.wait(2)
 def submit(self,payload):
  jid=str(uuid.uuid4());now=self.now()
  with self._db() as d:d.execute("INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?)",(jid,"queued","대기 중",json.dumps(payload),None,None,now,None,None));r=d.execute("SELECT * FROM jobs WHERE id=?",(jid,)).fetchone()
  self.wake.set();return self.public(r)
 def get(self,jid):
  with self._db() as d:r=d.execute("SELECT * FROM jobs WHERE id=?",(jid,)).fetchone()
  return self.public(r) if r else None
 def public(self,r):return {"id":r["id"],"status":r["status"],"message":r["message"],"result":json.loads(r["result"]) if r["result"] else None,"error":json.loads(r["error"]) if r["error"] else None,"createdAt":r["created_at"],"startedAt":r["started_at"],"finishedAt":r["finished_at"]}
 def update(self,jid,**kw):
  vals=[json.dumps(v,ensure_ascii=False) if k in {"result","error"} and v is not None else v for k,v in kw.items()]
  with self._db() as d:d.execute(f"UPDATE jobs SET {','.join(k+'=?' for k in kw)} WHERE id=?",(*vals,jid))
 def worker_loop(self):
  while not self.stop.is_set():
   with self._db() as d:r=d.execute("SELECT * FROM jobs WHERE status='queued' ORDER BY created_at LIMIT 1").fetchone()
   if not r:self.wake.wait(1);self.wake.clear();continue
   jid=r["id"];payload=json.loads(r["payload"]);self.current_job_id=jid;self.update(jid,status="running",message="행동 이력 분석 시작",started_at=self.now())
   try:
    result=LearnerService(self.root).run(payload.get("mode","incremental"),payload.get("sources"),payload.get("targetStart",""),payload.get("targetEnd",""),lambda m:self.update(jid,message=m));self.update(jid,status="completed",message="분석 완료",result=result,finished_at=self.now())
   except Exception as e:self.last_error=f"{type(e).__name__}: {e}";self.update(jid,status="failed",message="분석 실패",error={"message":self.last_error,"traceback":traceback.format_exc()},finished_at=self.now())
   finally:self.current_job_id=None
def handler_for(agent):
 class H(BaseHTTPRequestHandler):
  def sendj(self,status,p):b=json.dumps(p,ensure_ascii=False).encode();self.send_response(status);self.send_header("Content-Type","application/json; charset=utf-8");self.send_header("Content-Length",str(len(b)));self.end_headers();self.wfile.write(b)
  def do_GET(self):
   if self.path=="/health":self.sendj(200,agent.snapshot())
   elif self.path.startswith("/jobs/"):
    j=agent.get(self.path.removeprefix("/jobs/"));self.sendj(200,j) if j else self.sendj(404,{"error":"job not found"})
   else:self.sendj(404,{"error":"not found"})
  def do_POST(self):
   u=urlparse(self.path)
   if u.path=="/jobs":
    q=parse_qs(u.query);sources=(q.get("sources") or [""])[0].split(",") if q.get("sources") else None;self.sendj(202,agent.submit({"mode":(q.get("mode")or["incremental"])[0],"sources":sources,"targetStart":(q.get("start")or[""])[0],"targetEnd":(q.get("end")or[""])[0]}))
   elif u.path=="/shutdown":self.sendj(202,{"accepted":True});agent.stop.set()
   else:self.sendj(404,{"error":"not found"})
  def log_message(self,*_):pass
 return H
def main():
 p=argparse.ArgumentParser();p.add_argument("--root",type=Path,required=True);p.add_argument("--port",type=int,default=8770);a=p.parse_args();configure_agent_logging(a.root/"runtime/logs/learner.log",60);lock=acquire_singleton(a.root/"runtime/learner/learner.lock");
 if lock is None:return 0
 agent=LearnerAgent(a.root);signal.signal(signal.SIGTERM,lambda *_:agent.stop.set());signal.signal(signal.SIGINT,lambda *_:agent.stop.set());threading.Thread(target=agent.heartbeat_loop,daemon=True).start();threading.Thread(target=agent.worker_loop,daemon=True).start();server=ThreadingHTTPServer(("127.0.0.1",a.port),handler_for(agent));server.timeout=1
 while not agent.stop.is_set():server.handle_request()
 server.server_close();lock.close();return 0
if __name__=="__main__":raise SystemExit(main())
