"""Reproducible Learner v1/v2 scaling benchmark (no production data required)."""
import argparse,json,sqlite3,tempfile,time,tracemalloc
from collections import Counter
from datetime import datetime,timedelta
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

from backend.services.learner.service import LearnerService

ORIGINAL_CONNECT=sqlite3.connect
COUNTS=Counter()
class CountingConnection(sqlite3.Connection):
    def execute(self,sql,*args,**kwargs):
        COUNTS[sql.lstrip().split(None,1)[0].upper()]+=1
        if "processed_behaviors" in sql and sql.lstrip().upper().startswith("SELECT"):COUNTS["HISTORICAL_SELECT"]+=1
        if "COUNT(DISTINCT event_id)" in sql and "behavior_type" in sql and "scope_type" not in sql:COUNTS["FREQUENCY_SELECT"]+=1
        return super().execute(sql,*args,**kwargs)
    def executemany(self,sql,*args,**kwargs):
        COUNTS[sql.lstrip().split(None,1)[0].upper()]+=1
        return super().executemany(sql,*args,**kwargs)

def measured_connect(*args,**kwargs):
    kwargs.setdefault("factory",CountingConnection)
    return ORIGINAL_CONNECT(*args,**kwargs)

def fixture(root,n):
    path=root/"cache/index/events_index.db";path.parent.mkdir(parents=True,exist_ok=True);base=datetime(2026,1,1)
    keys=max(100,n//5);batch=[]
    with ORIGINAL_CONNECT(path) as db:
        db.execute("CREATE TABLE event_list_rows(kind TEXT,record_id TEXT,event_time TEXT,row_json TEXT,source_file TEXT)")
        db.execute("CREATE INDEX idx_web_event_list_kind_time ON event_list_rows(kind,event_time DESC)")
        for i in range(n):
            # 2% high-frequency, remaining rows exercise first-seen and scoped state.
            rule=f"hot-{i%10}" if i%50==0 else f"rule-{i%keys}"
            event_time=(base+timedelta(minutes=i)).isoformat();row={"rule":rule,"userId":f"u-{i%500}","endpointId":f"pc-{i%1000}","dept":f"d-{i%20}"}
            batch.append(("detections",f"e-{i:07d}",event_time,json.dumps(row),""))
            if len(batch)==2000:db.executemany("INSERT INTO event_list_rows VALUES(?,?,?,?,?)",batch);batch.clear()
        if batch:db.executemany("INSERT INTO event_list_rows VALUES(?,?,?,?,?)",batch)

def run(engine,n):
    with tempfile.TemporaryDirectory(prefix=f"learner-{engine}-{n}-") as directory:
        root=Path(directory);fixture(root,n);COUNTS.clear();sqlite3.connect=measured_connect;tracemalloc.start();started=time.perf_counter()
        try:
            service=LearnerService(root);result=service.run_v1("full",["detections"]) if engine=="v1" else service.run("full",["detections"])
        finally:
            elapsed=time.perf_counter()-started;_,peak=tracemalloc.get_traced_memory();tracemalloc.stop();sqlite3.connect=ORIGINAL_CONNECT
        db=root/"cache/index/learner_cache.db";wal=Path(str(db)+"-wal")
        return {"engine":engine,"events":n,"seconds":round(elapsed,3),"peakMiB":round(peak/1048576,2),"dbMiB":round(db.stat().st_size/1048576,2),"walMiB":round(wal.stat().st_size/1048576,2) if wal.exists() else 0,"sql":dict(COUNTS),"engineSql":result.get("sqlCounts",{})}

def main():
    parser=argparse.ArgumentParser();parser.add_argument("--sizes",nargs="+",type=int,default=[10_000,50_000,100_000]);parser.add_argument("--engines",nargs="+",choices=("v1","v2"),default=["v1","v2"]);args=parser.parse_args();results=[]
    for size in args.sizes:
        for engine in args.engines:
            result=run(engine,size);results.append(result);print(json.dumps(result,ensure_ascii=False),flush=True)
    print(json.dumps({"results":results},ensure_ascii=False,indent=2))
if __name__=="__main__":main()
