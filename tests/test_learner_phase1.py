import json,sqlite3
from pathlib import Path
from backend.services.learner.service import LearnerService
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
 findings=LearnerStore(tmp_path).findings(source="dlp",finding_type="NEW_BEHAVIOR")
 old=next(x for x in findings if x["event_id"]=="old");assert old["baseline"]["global"]==0;assert old["reasons"]
 assert not any(x["event_id"]=="future" for x in findings)

def test_similar_group_and_frequency_spike(tmp_path):
 rows=[]
 for i in range(7):rows.append(("detections",f"p{i}",f"2026-01-{i+1:02d}T00:00:00",{"rule":"R"}))
 for i in range(21):rows.append(("detections",f"n{i}",f"2026-01-08T{i%24:02d}:00:00",{"rule":"R"}))
 events_db(tmp_path,rows);LearnerService(tmp_path).run("full",["detections"]);types={x["finding_type"] for x in LearnerStore(tmp_path).findings(source="detections")};assert {"SIMILAR_GROUP","FREQUENCY_SPIKE"}<=types

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
    findings=LearnerStore(tmp_path).findings(source="inbound",finding_type="NEW_BEHAVIOR")
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
