import json
import sqlite3
from pathlib import Path

import pytest

from backend.services.learner.service import LearnerCancelled, LearnerService
from backend.services.learner.store import LearnerStore


def event_db(root: Path, rows):
    path=root/"cache/index/events_index.db";path.parent.mkdir(parents=True,exist_ok=True)
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE event_list_rows(kind TEXT,record_id TEXT,event_time TEXT,row_json TEXT,source_file TEXT)")
        db.execute("CREATE INDEX idx_web_event_list_kind_time ON event_list_rows(kind,event_time DESC)")
        db.executemany("INSERT INTO event_list_rows VALUES(?,?,?,?,?)",[(s,i,t,json.dumps(row),"") for s,i,t,row in rows])


def semantic_findings(root):
    items=LearnerStore(root).finding_rows(source="detections",limit=10000)
    result=[]
    for item in items:
        observed=item["observed"];values=observed.get("newBehaviors") or [observed]
        signatures=tuple(sorted((v.get("behaviorType"),v.get("value")) for v in values if v.get("behaviorType")))
        baseline={key:item["baseline"].get(key) for key in ("groupCount","eventCount","distinctUsers","distinctDevices","spread","count1d","prior7d") if key in item["baseline"]}
        result.append((item["finding_type"],signatures,baseline,tuple(item["related_event_ids"])))
    return sorted(result,key=str)


def test_v2_matches_v1_finding_semantics(tmp_path):
    rows=[]
    for day in range(1,8):rows.append(("detections",f"old-{day}",f"2026-01-{day:02d}T09:00:00",{"rule":"R","userId":"old","endpointId":"old-pc"}))
    for index in range(21):rows.append(("detections",f"new-{index}",f"2026-01-08T10:{index:02d}:00",{"rule":"R","userId":f"u-{index%5}","endpointId":f"pc-{index%6}"}))
    v1=tmp_path/"v1";v2=tmp_path/"v2";event_db(v1,rows);event_db(v2,rows)
    LearnerService(v1).run_v1("full",["detections"]);LearnerService(v2).run("full",["detections"])
    assert semantic_findings(v2)==semantic_findings(v1)


def test_v2_no_time_leak_and_future_does_not_change_first_event(tmp_path):
    first=("detections","first","2026-01-01T09:00:00",{"rule":"A","userId":"u","endpointId":"pc"})
    one=tmp_path/"one";two=tmp_path/"two";event_db(one,[first]);event_db(two,[first,("detections","second","2026-01-01T10:00:00",first[3])])
    LearnerService(one).run("full",["detections"]);LearnerService(two).run("full",["detections"])
    left=LearnerStore(one).finding_rows(finding_type="NEW_BEHAVIOR")[0];right=LearnerStore(two).finding_rows(finding_type="NEW_BEHAVIOR")[0]
    assert left["event_id"]==right["event_id"]=="first"
    assert left["baseline"]==right["baseline"]
    with LearnerStore(two).connect() as db:
        state=db.execute("SELECT total_count FROM learner_analysis_state WHERE source='detections' AND scope_type='global' AND behavior_type='detection_rule' AND behavior_key='a'").fetchone()
    assert state[0]==2


def test_v2_incremental_uses_persistent_state_and_only_new_events(tmp_path):
    event_db(tmp_path,[("detections","first","2026-01-01T09:00:00",{"rule":"A","userId":"u"})]);service=LearnerService(tmp_path)
    service.run("full",["detections"])
    with sqlite3.connect(tmp_path/"cache/index/events_index.db") as db:db.execute("INSERT INTO event_list_rows VALUES(?,?,?,?,?)",("detections","second","2026-01-02T09:00:00",json.dumps({"rule":"A","userId":"u"}),""))
    result=service.run("incremental",["detections"])
    assert result["processedEvents"]==1 and result["engineVersion"]=="2"
    with LearnerStore(tmp_path).connect() as db:
        assert db.execute("SELECT total_count FROM learner_analysis_state WHERE source='detections' AND scope_type='global' AND behavior_key='a'").fetchone()[0]==2
        assert db.execute("SELECT COUNT(*) FROM learner_processed_events WHERE source='detections'").fetchone()[0]==2


def test_v2_cancel_discards_staging_and_preserves_active_results(tmp_path):
    rows=[("detections",f"e-{i}",f"2026-01-{i//1440+1:02d}T{i//60%24:02d}:{i%60:02d}:00",{"rule":f"R-{i%100}","userId":f"u-{i%20}"}) for i in range(5000)]
    event_db(tmp_path,rows);store=LearnerStore(tmp_path)
    with store.connect() as db:db.execute("INSERT INTO learner_findings(finding_id,source,event_id,finding_type,title) VALUES('existing','detections','old','NEW_BEHAVIOR','기존 결과')")
    stop={"value":False}
    def progress(value):
        if value.get("sourceProcessed",0)>=2000:stop["value"]=True
    with pytest.raises(LearnerCancelled):LearnerService(tmp_path).run("full",["detections"],progress=progress,cancelled=lambda:stop["value"])
    assert LearnerStore(tmp_path).finding("existing") is not None
    assert not list((tmp_path/"runtime/learner").glob("*.staging.db*"))


def test_v2_reports_real_engine_phases(tmp_path):
    event_db(tmp_path,[("detections",f"e-{i}",f"2026-01-01T00:{i:02d}:00",{"rule":"R"}) for i in range(10)])
    phases=[];LearnerService(tmp_path).run("full",["detections"],progress=lambda value:phases.append(value.get("phase")))
    assert {"PREPARE","STREAM","FINALIZE_GROUPS","FINALIZE_FINDINGS","WRITE","ACTIVATE"}<=set(phases)


def test_v2_select_count_is_not_event_or_group_proportional(tmp_path):
    event_db(tmp_path,[("detections",f"e-{i}",f"2026-01-{i//1440+1:02d}T{i//60%24:02d}:{i%60:02d}:00",{"rule":f"R-{i%50}"}) for i in range(2000)])
    result=LearnerService(tmp_path).run("full",["detections"])
    assert result["sqlCounts"]["input_select"]==3
    assert "historical_select" not in result["sqlCounts"]
    assert "frequency_select" not in result["sqlCounts"]
