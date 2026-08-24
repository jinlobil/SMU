import json
import sqlite3

from backend.services.learner.store import LearnerStore


def insert_finding(db, fid, event_id, visible, reason, kind="NEW_BEHAVIOR", source="detections", created="2026-08-13T10:00:00"):
    gate = {"visible": visible, "category": "REVIEW_REQUIRED" if visible else "ANALYSIS_ONLY", "evidenceFamilies": ["FREQUENCY"] if visible else ["NOVELTY_RARITY"], "reasons": [reason]}
    db.execute(
        "INSERT INTO learner_findings(finding_id,source,event_id,finding_type,title,summary,observed_json,reasons_json,baseline_json,related_event_ids_json,created_at,gate_visible,gate_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (fid, source, event_id, kind, kind, "summary", json.dumps({"behaviorType": "process", "value": fid}), "[]", "{}", json.dumps([fid, "shared"]), created, int(visible), json.dumps(gate, ensure_ascii=False)),
    )


def test_connection_context_closes_the_file_handle(tmp_path):
    store = LearnerStore(tmp_path)
    connection = store.connect()
    with connection as db:
        db.execute("SELECT 1")
    try:
        connection.execute("SELECT 1")
    except sqlite3.ProgrammingError as error:
        assert "closed" in str(error)
    else:
        raise AssertionError("connection was committed but not closed")


def test_review_materialization_excludes_hidden_reasons_but_detail_keeps_raw(tmp_path):
    store = LearnerStore(tmp_path)
    with store.connect() as db:
        insert_finding(db, "visible", "same", True, "확인해야 하는 이유", "FREQUENCY_SPIKE")
        insert_finding(db, "hidden-a", "same", False, "기본 화면에서는 숨깁니다.")
        insert_finding(db, "hidden-b", "same", False, "기본 화면에서는 숨깁니다.", "SIMILAR_GROUP")
        insert_finding(db, "hidden-only", "hidden-event", False, "숨김 전용")
    store.rebuild_operational("detections")
    review = store.operational_findings(visible_only=True)
    assert review["total"] == 1
    assert review["items"][0]["gateReasons"] == ["확인해야 하는 이유"]
    assert "숨깁니다" not in json.dumps(review["items"][0], ensure_ascii=False)
    all_items = store.operational_findings(visible_only=False)
    assert all_items["total"] == 2
    detail = store.operational_finding(review["items"][0]["finding_id"])
    assert {item["finding_id"] for item in detail["originalFindings"]} == {"visible", "hidden-a", "hidden-b"}


def test_operational_pagination_filters_and_missing_event_ids(tmp_path):
    store = LearnerStore(tmp_path)
    with store.connect() as db:
        for index in range(31):
            insert_finding(db, f"f-{index}", f"event-{index}", True, "visible", "NEW_BEHAVIOR" if index % 2 else "FREQUENCY_SPIKE", created=f"2026-08-13T10:00:{index:02d}")
        insert_finding(db, "no-event-a", None, False, "hidden")
        insert_finding(db, "no-event-b", None, False, "hidden")
    store.rebuild_operational()
    first = store.operational_findings(limit=30, visible_only=True)
    second = store.operational_findings(limit=30, offset=30, visible_only=True)
    assert first["total"] == 31 and len(first["items"]) == 30 and len(second["items"]) == 1
    assert store.operational_findings(finding_type="FREQUENCY_SPIKE", visible_only=True)["total"] == 16
    assert store.operational_findings(visible_only=False)["total"] == 33


def test_operational_hot_query_uses_materialized_index_without_temp_grouping(tmp_path):
    store = LearnerStore(tmp_path)
    with store.connect() as db:
        for index in range(100):
            insert_finding(db, f"f-{index}", f"event-{index}", True, "visible")
    store.rebuild_operational()
    with store.connect() as db:
        before = [row[3] for row in db.execute("EXPLAIN QUERY PLAN SELECT source,CASE WHEN event_id IS NULL OR event_id='' THEN finding_id ELSE event_id END key,MAX(created_at) FROM learner_findings WHERE gate_visible=1 GROUP BY source,key ORDER BY MAX(created_at) DESC LIMIT 30")]
        after = [row[3] for row in db.execute("EXPLAIN QUERY PLAN SELECT * FROM learner_operational_findings WHERE gate_visible=1 ORDER BY created_at DESC LIMIT 30")]
    assert any("TEMP B-TREE" in step for step in before)
    assert not any("TEMP B-TREE" in step or "learner_findings" in step for step in after)
    assert any("idx_operational_gate_time" in step for step in after)
