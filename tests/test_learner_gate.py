import json
from backend.services.learner.gate import FREQUENCY,NOVELTY_RARITY,SPREAD,evaluate
from backend.services.learner.store import LearnerStore


def finding(kind="NEW_BEHAVIOR",global_prior=0,behavior="destination",value="example.test",group=0):
    observed={"behaviorType":behavior,"value":value}
    if kind=="NEW_BEHAVIOR":observed={"newBehaviors":[observed]}
    return {"finding_type":kind,"observed_json":json.dumps(observed),"baseline_json":json.dumps({"behaviors":[{"counts":{"user":0,"device":0,"department":0,"global":global_prior}}],"groupCount":group})}


def test_novelty_family_alone_is_analysis_only():
    gate=evaluate(finding())
    assert gate["visible"] is False and gate["category"]=="ANALYSIS_ONLY"
    assert gate["evidenceFamilies"]==[NOVELTY_RARITY]


def test_multiple_first_seen_scopes_remain_one_novelty_family():
    gate=evaluate(finding(global_prior=0))
    assert gate["visible"] is False and len(gate["evidenceFamilies"])==1


def test_global_first_plus_frequency_is_visible():
    gate=evaluate(finding(),{("destination","example.test")},set())
    assert gate["visible"] and gate["evidenceFamilies"]==[NOVELTY_RARITY,FREQUENCY]


def test_global_first_plus_similar_group_is_visible():
    gate=evaluate(finding(),set(),{("destination","example.test")})
    assert gate["visible"] and gate["evidenceFamilies"]==[NOVELTY_RARITY,SPREAD]


def test_global_rare_device_first_plus_frequency_is_visible():
    gate=evaluate(finding(global_prior=5),{("destination","example.test")},set())
    assert gate["visible"] and gate["evidence"]["globalRare"] is True


def test_high_global_prior_user_first_is_hidden():
    gate=evaluate(finding(global_prior=82000))
    assert not gate["visible"] and not gate["evidence"]["globalRare"]


def test_gate_persists_reasons_and_hidden_query_remains_available(tmp_path):
    store=LearnerStore(tmp_path);gate=evaluate(finding())
    with store.connect() as db:
        db.execute("INSERT INTO learner_findings(finding_id,source,event_id,finding_type,title,summary,observed_json,reasons_json,baseline_json,related_event_ids_json,created_at,gate_visible,gate_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",("hidden","dlp","e1","NEW_BEHAVIOR","새로운 행동","요약","{}","[]","{}","[]","2026-01-01",0,json.dumps(gate,ensure_ascii=False)))
    assert store.findings(source="dlp",visible_only=True)["total"]==0
    all_results=store.findings(source="dlp",visible_only=False)
    assert all_results["total"]==1 and all_results["items"][0]["gate"]["reasons"]


def _event_db(root, rows):
    import sqlite3
    path=root/"cache/index/events_index.db";path.parent.mkdir(parents=True,exist_ok=True)
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE event_list_rows(kind TEXT,record_id TEXT,event_time TEXT,row_json TEXT,source_file TEXT)")
        db.executemany("INSERT INTO event_list_rows VALUES(?,?,?,?,?)",[(source,event_id,time,json.dumps(row),"") for source,event_id,time,row in rows])


def test_similar_group_promotes_new_behavior_without_changing_stats(tmp_path):
    from backend.services.learner.service import LearnerService
    rows=[("detections",f"e{i}",f"2026-01-01T00:{i:02d}:00",{"rule":"Rare Rule"}) for i in range(10)]
    _event_db(tmp_path,rows);service=LearnerService(tmp_path);service.run("full",["detections"])
    store=LearnerStore(tmp_path);review=store.findings(source="detections",visible_only=True)
    assert review["total"]==0
    similar=next(item for item in store.finding_rows(source="detections") if item["finding_type"]=="SIMILAR_GROUP")
    assert similar["baseline"]["spread"] is False
    assert similar["baseline"]["eventCount"]==10
    with store.connect() as db:
        stat=db.execute("SELECT count_all FROM behavior_stats WHERE source='detections' AND scope_type='global' AND behavior_type='detection_rule'").fetchone()
    assert stat[0]==10


def test_incremental_run_reapplies_gate_to_preserved_findings(tmp_path):
    import sqlite3
    from backend.services.learner.service import LearnerService
    _event_db(tmp_path,[("detections","first","2026-01-01T00:00:00",{"rule":"R"})])
    service=LearnerService(tmp_path);service.run("full",["detections"]);store=LearnerStore(tmp_path)
    assert store.findings(source="detections",visible_only=True)["total"]==0
    with sqlite3.connect(tmp_path/"cache/index/events_index.db") as db:
        db.executemany("INSERT INTO event_list_rows VALUES(?,?,?,?,?)",[("detections",f"next{i}",f"2026-01-02T00:{i:02d}:00",json.dumps({"rule":"R","userId":f"user-{i}"}),"") for i in range(10)])
    service.run("incremental",["detections"])
    new=next(item for item in store.findings(source="detections",visible_only=True)["items"] if item["finding_type"]=="NEW_BEHAVIOR")
    assert new["gate"]["visible"] is True


def test_frequency_and_entity_spread_are_independent_families():
    frequency=evaluate(finding(kind="FREQUENCY_SPIKE",group=100))
    assert frequency["evidenceFamilies"]==[FREQUENCY]
    assert frequency["category"]=="ANALYSIS_ONLY"
    spread_finding=finding(kind="SIMILAR_GROUP",group=20)
    spread_finding["baseline_json"]=json.dumps({"groupCount":20,"eventCount":20,"distinctUsers":5,"distinctDevices":1,"spread":True,"entitySpreadCount":5})
    spread=evaluate(spread_finding)
    assert spread["evidenceFamilies"]==[SPREAD]
    assert spread["evidence"]["distinctUsers"]==5
    combined=evaluate(spread_finding,{("destination","example.test")},set())
    assert combined["evidenceFamilies"]==[FREQUENCY,SPREAD]
    assert combined["category"]=="REVIEW_REQUIRED"


def test_wehago_style_same_entity_repetition_is_frequency_only():
    runtime=finding(kind="SIMILAR_GROUP",behavior="process",value="WehagoUpdater.exe",group=10)
    runtime["baseline_json"]=json.dumps({"groupCount":10,"eventCount":10,"distinctUsers":1,"distinctDevices":1,"distinctDepartments":1,"spread":False,"entitySpreadCount":1})
    gate=evaluate(runtime,{("process","wehagoupdater.exe")},set())
    assert gate["evidenceFamilies"]==[FREQUENCY]
    assert gate["evidence"]["spread"] is False
    assert gate["category"]=="ANALYSIS_ONLY" and gate["visible"] is False


def test_legacy_similar_group_gate_is_preserved_without_identity_backfill(tmp_path):
    from backend.services.learner.gate import apply_gate
    store=LearnerStore(tmp_path);legacy={"visible":True,"category":"REVIEW_REQUIRED","evidenceFamilies":["FREQUENCY","SPREAD"],"reasons":["legacy"]}
    with store.connect() as db:
        db.execute("INSERT INTO learner_findings(finding_id,source,event_id,finding_type,observed_json,reasons_json,baseline_json,related_event_ids_json,gate_visible,gate_json) VALUES(?,?,?,?,?,?,?,?,?,?)",("legacy","detections","event","SIMILAR_GROUP",json.dumps({"behaviorType":"process","value":"tool.exe"}),"[]",json.dumps({"groupCount":20}),"[]",1,json.dumps(legacy)))
        apply_gate(db,"detections")
    preserved=store.finding("legacy")
    assert preserved["gate_visible"]==1 and preserved["gate"]==legacy
