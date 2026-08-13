import json,sqlite3,threading,time
from pathlib import Path
from backend.services.learner.service import LearnerService,LearnerCancelled
from backend.services.learner.store import LearnerStore
from backend.services.learner.adapters import ADAPTERS
from system_monitor.learner import LearnerAgent,handler_for
from system_monitor.watchdog import HardwareWatchdog

def events_db(root,rows):
 p=root/"cache/index/events_index.db";p.parent.mkdir(parents=True,exist_ok=True)
 with sqlite3.connect(p) as d:
  d.execute("CREATE TABLE event_list_rows(kind TEXT,record_id TEXT,event_time TEXT,row_json TEXT,source_file TEXT)")
  d.executemany("INSERT INTO event_list_rows VALUES(?,?,?,?,?)",[(k,i,t,json.dumps(r),"") for k,i,t,r in rows])

def test_schema_full_incremental_windows_and_idempotence(tmp_path:Path):
 rows=[("firewall",f"e{i}",f"2026-01-{i:02d}T10:00:00",{"destinationIp":"8.8.8.8","hostname":"PC1","userId":"u1","dept":"IT"}) for i in range(1,10)]
 events_db(tmp_path,rows);service=LearnerService(tmp_path);result=service.run("full",["firewall"])
 assert result["processedEvents"]==9
 with LearnerStore(tmp_path).connect() as d:
  names={x[0] for x in d.execute("SELECT name FROM sqlite_master WHERE type='table'")};assert {"learner_runs","behavior_stats","learner_findings"}<=names
  stat=d.execute("SELECT * FROM behavior_stats WHERE source='firewall' AND scope_type='global' AND behavior_type='destination_ip'").fetchone();assert stat["count_all"]==9;assert stat["count_1d"]==2;assert stat["count_7d"]==8;assert stat["count_30d"]==9;assert stat["count_90d"]==9;assert stat["count_180d"]==9;assert stat["first_seen"].startswith("2026-01-01");assert stat["last_seen"].startswith("2026-01-09")
 assert service.run("incremental",["firewall"])["processedEvents"]==0
 with sqlite3.connect(tmp_path/"cache/index/events_index.db") as d:d.execute("INSERT INTO event_list_rows VALUES(?,?,?,?,?)",("firewall","e10","2026-01-10T10:00:00",json.dumps({"destinationIp":"8.8.8.8"}),""))
 assert service.run("incremental",["firewall"])["processedEvents"]==1

def test_historical_baseline_never_uses_future_and_reasons_exist(tmp_path):
 events_db(tmp_path,[("dlp","old","2026-01-01T00:00:00",{"destination":"usb","username":"a"}),("dlp","future","2026-02-01T00:00:00",{"destination":"usb","username":"a"})]);LearnerService(tmp_path).run("full",["dlp"])
 findings=LearnerStore(tmp_path).finding_rows(source="dlp",finding_type="NEW_BEHAVIOR")
 old=next(x for x in findings if x["event_id"]=="old");assert old["baseline"]["global"]==0;assert old["reasons"]
 assert not any(x["event_id"]=="future" for x in findings)

def test_similar_group_and_frequency_spike(tmp_path):
 rows=[]
 for i in range(7):rows.append(("detections",f"p{i}",f"2026-01-{i+1:02d}T00:00:00",{"rule":"R"}))
 for i in range(21):rows.append(("detections",f"n{i}",f"2026-01-08T{i%24:02d}:00:00",{"rule":"R"}))
 events_db(tmp_path,rows);LearnerService(tmp_path).run("full",["detections"]);types={x["finding_type"] for x in LearnerStore(tmp_path).finding_rows(source="detections")};assert {"SIMILAR_GROUP","FREQUENCY_SPIKE"}<=types

def test_all_source_adapters_keep_unmapped_events():
 rows={"detections":{"rule":"r"},"xdr":{"from":"a@x.test"},"inbound":{"senderIp":"1.2.3.4"},"outbound":{"receiver":"b@y.test"},"dlp":{"destination":"usb"},"firewall":{"destinationIp":"8.8.8.8"}}
 for source,row in rows.items():
  output=ADAPTERS[source]("id","2026-01-01T00:00:00",row);assert output;assert output[0].event_id=="id"

def test_learner_health_job_and_watchdog_surface(tmp_path,monkeypatch):
 agent=LearnerAgent(tmp_path);assert agent.snapshot()["status"]=="running";job=agent.submit({"mode":"full"});assert agent.get(job["id"])["status"]=="queued"
 watchdog=HardwareWatchdog(tmp_path);monkeypatch.setattr(watchdog,"read_learner",lambda:{"status":"running","pid":1});assert watchdog.ensure_learner()["status"]=="running";assert "learner" in watchdog.snapshot()


def test_fastapi_and_frontend_expose_learner_contract():
    app=Path("backend/app.py").read_text(encoding="utf-8");ui=Path("frontend/src/pages/MachineLearningPage.tsx").read_text(encoding="utf-8")
    for route in ("/api/learner/jobs","/api/learner/findings","/api/learner/history"): assert route in app
    for label in ("새로운 행동","활동 증가","비슷한 이벤트","왜 표시됐나요?"): assert label in ui


def test_learner_main_uses_keyword_only_logging_retention():
    source=Path("system_monitor/learner.py").read_text(encoding="utf-8")
    assert 'configure_agent_logging(a.root/"runtime/logs/learner.log", retention_days=60)' in source
    assert 'configure_agent_logging(a.root/"runtime/logs/learner.log",60)' not in source


def test_new_behaviors_are_merged_into_one_primary_event_finding(tmp_path):
    row={"from":"external@outside.test","senderIp":"203.0.113.7","to":"internal@corp.test","user":"내부 사용자","userId":"internal","dept":"보안팀","subject":"새 메일"}
    events_db(tmp_path,[("inbound","mail-1","2026-03-01T09:00:00",row)])
    LearnerService(tmp_path).run("full",["inbound"])
    findings=LearnerStore(tmp_path).finding_rows(source="inbound",finding_type="NEW_BEHAVIOR")
    assert len(findings)==1
    finding=findings[0]
    assert finding["event_id"]=="mail-1"
    assert len(finding["reasons"])==5
    assert len(finding["observed"]["newBehaviors"])==5
    assert finding["user_name"]=="내부 사용자"
    assert finding["user_id"]=="internal"
    assert finding["email"]=="internal@corp.test"
    assert "external@outside.test" in json.dumps(finding["observed"],ensure_ascii=False)


def test_email_xdr_identity_prefers_internal_recipient_over_external_sender():
    row={"from":"attacker@outside.test","to":"employee@corp.test","user":"사내 사용자","userId":"employee","dept":"재무팀","subject":"검증"}
    output=ADAPTERS["xdr"]("xdr-1","2026-03-01T10:00:00",row)
    assert output
    assert all(item.user_name=="사내 사용자" for item in output)
    assert all(item.user_id=="employee" for item in output)
    assert all(item.email=="employee@corp.test" for item in output)
    sender=next(item for item in output if item.behavior_type=="sender")
    assert sender.behavior_key=="attacker@outside.test"
    assert "attacker@outside.test" not in {sender.person_key,sender.email,sender.user_id}


def test_learner_rejects_all_submissions_while_job_is_active(tmp_path):
    agent=LearnerAgent(tmp_path)
    first=agent.submit({"mode":"full","sources":["inbound"]})
    assert first["status"]=="queued"
    for mode in ("full","incremental"):
        rejected=agent.submit({"mode":mode})
        assert rejected=={"busy":True,"currentJobId":first["id"],"status":"queued"}
    with agent._db() as db:
        assert db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]==1
        db.execute("UPDATE jobs SET status='running' WHERE id=?",(first["id"],))
    assert agent.submit({"mode":"incremental"})["status"]=="running"


def test_learner_fast_double_submit_creates_only_one_job(tmp_path):
    agent=LearnerAgent(tmp_path);results=[]
    threads=[threading.Thread(target=lambda:results.append(agent.submit({"mode":"full"}))) for _ in range(2)]
    for thread in threads:thread.start()
    for thread in threads:thread.join()
    assert sum("id" in result for result in results)==1
    assert sum(result.get("busy",False) for result in results)==1


def test_existing_duplicate_queued_job_is_cancelled_on_startup(tmp_path):
    agent=LearnerAgent(tmp_path);first=agent.submit({"mode":"full"})
    with agent._db() as db:
        db.execute("INSERT INTO jobs(id,status,message,payload,created_at) VALUES(?,?,?,?,?)",("duplicate","queued","대기 중",json.dumps({"mode":"full"}),agent.now()))
    recovered=LearnerAgent(tmp_path)
    assert recovered.get(first["id"])["status"]=="queued"
    assert recovered.get("duplicate")["status"]=="cancelled"
    assert recovered.get("duplicate")["message"]=="중복 요청으로 취소됨"


def test_job_cancel_keeps_pid_releases_current_job_and_allows_next(tmp_path,monkeypatch):
    from backend.services.learner.store import LearnerStore
    import system_monitor.learner as learner_module
    store=LearnerStore(tmp_path)
    with store.connect() as db:
        db.execute("INSERT INTO learner_findings(finding_id,source,event_id,finding_type,title,summary,reasons_json,baseline_json,related_event_ids_json,observed_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",("existing","inbound","e","NEW_BEHAVIOR","기존","기존","[]","{}","[]","{}","2026-01-01"))
    class SlowFull:
        def __init__(self,root):self.store=LearnerStore(root)
        def run(self,*args):
            progress,cancelled=args[-2:]
            with self.store.connect() as db:db.execute("DELETE FROM learner_findings")
            progress({"message":"inbound 분석 중","currentSource":"inbound","sourceProcessed":500,"sourceTotal":1000,"totalProcessed":500,"totalEvents":1000,"progressPercent":50.0})
            while not cancelled():time.sleep(.01)
            raise LearnerCancelled("cancel")
    monkeypatch.setattr(learner_module,"LearnerService",SlowFull)
    agent=LearnerAgent(tmp_path);pid=agent.snapshot()["pid"];job=agent.submit({"mode":"full"})
    worker=threading.Thread(target=agent.worker_loop,daemon=True);worker.start()
    deadline=time.time()+2
    while agent.current_job_id is None and time.time()<deadline:time.sleep(.01)
    while agent.get(job["id"])["progressPercent"]<50 and time.time()<deadline:time.sleep(.01)
    assert agent.get(job["id"])["progressPercent"]==50.0
    assert agent.cancel(job["id"])["status"]=="cancelling"
    assert agent.cancel(job["id"])["status"]=="cancelling"
    deadline=time.time()+2
    while agent.current_job_id is not None and time.time()<deadline:time.sleep(.01)
    assert agent.get(job["id"])["status"]=="cancelled"
    assert agent.cancel(job["id"])["conflict"] is True
    assert agent.snapshot()["pid"]==pid and agent.snapshot()["currentJobId"] is None
    assert LearnerStore(tmp_path).finding("existing") is not None
    following=agent.submit({"mode":"incremental"});assert following["status"]=="queued"
    agent.stop.set();agent.wake.set();worker.join(1)


def test_frontend_disables_analysis_buttons_and_exposes_graceful_cancel():
    ui=Path("frontend/src/pages/MachineLearningPage.tsx").read_text(encoding="utf-8")
    assert "disabled={busy}" in ui
    assert 'global-job-progress scheduler-progress indexing learner-job-progress' in ui
    assert 'className="config-card learner-toolbar"' in ui
    for action in ('primary-action','secondary-action','danger-action'): assert f'className="{action}"' in ui
    assert "분석 중단" in ui and "/cancel" in ui
    for field in ("sourceProcessed","sourceTotal","totalProcessed","totalEvents","progressPercent"):assert field in ui


def test_learner_findings_are_server_paginated(tmp_path):
    store=LearnerStore(tmp_path)
    with store.connect() as db:
        for index in range(65):
            db.execute("INSERT INTO learner_findings(finding_id,source,event_id,finding_type,title,summary,observed_json,reasons_json,baseline_json,related_event_ids_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",(f"f{index}","inbound",f"e{index}","NEW_BEHAVIOR","새로운 행동","요약","{}","[]","{}","[]",f"2026-01-{index%28+1:02d}T00:00:{index:02d}"))
    first=store.findings(source="inbound",limit=30,offset=0);third=store.findings(source="inbound",limit=30,offset=60)
    assert first["total"]==65 and len(first["items"])==30
    assert third["total"]==65 and len(third["items"])==5


def test_machine_learning_render_boundaries_and_progress_math():
    ui=Path("frontend/src/pages/MachineLearningPage.tsx").read_text(encoding="utf-8")
    assert "const LearnerJobStatus=memo" in ui
    assert "const FindingList=memo" in ui and "const FindingCard=memo" in ui
    assert "processed/total*100:0" in ui
    assert "pageSize:String(PAGE_SIZE)" in ui and "const PAGE_SIZE=30" in ui
    assert "setInterval(()=>void poll(),1500)" in ui
    # Finding data is fetched only by the list effect, never by progress polling.
    assert ui.count("/api/learner/findings?")==1
    assert "onResultsReady()" in ui and "['completed','cancelled'].includes(current)" in ui


def test_machine_learning_uses_shared_action_tokens_without_learner_colors():
    css=Path("frontend/src/styles.css").read_text(encoding="utf-8")
    learner_css=css[css.index(".learner-toolbar-controls"):]
    assert "--learner" not in learner_css
    assert ".primary-action" in css and ".secondary-action" in css and ".danger-action" in css
