"""Explainable Phase 1 visibility gate for persisted Learner findings."""
import json

GLOBAL_RARE_MAX_PRIOR_COUNT = 5
NOVELTY_RARITY = "NOVELTY_RARITY"
FREQUENCY = "FREQUENCY"
SPREAD = "SPREAD"


def behavior_signatures(finding):
    observed=json.loads(finding["observed_json"] or "{}")
    values=observed.get("newBehaviors") or [observed]
    return {(str(item.get("behaviorType", "")),str(item.get("value", "")).lower()) for item in values if item.get("behaviorType") and item.get("value")}


def evaluate(finding, frequency_signatures=frozenset(), spread_signatures=frozenset()):
    kind=finding["finding_type"]
    signatures=behavior_signatures(finding)
    baseline=json.loads(finding["baseline_json"] or "{}")
    families=[];reasons=[];evidence={}
    if kind=="NEW_BEHAVIOR":
        families.append(NOVELTY_RARITY)
        behavior_counts=[item.get("counts",{}) for item in baseline.get("behaviors",[])] or [baseline]
        global_prior=min((int(item.get("global",0) or 0) for item in behavior_counts),default=0)
        evidence.update(globalPriorCount=global_prior,globalFirst=global_prior==0,globalRare=global_prior<=GLOBAL_RARE_MAX_PRIOR_COUNT)
        reasons.append("회사 전체에서 처음 확인된 행동입니다." if global_prior==0 else "회사 전체에서 거의 확인되지 않은 행동입니다.")
    if kind=="FREQUENCY_SPIKE" or signatures & frequency_signatures:
        families.append(FREQUENCY);evidence["frequencySpike"]=True
        reasons.append("최근 짧은 시간 동안 발생 빈도가 크게 증가했습니다.")
    actual_spread=bool(baseline.get("spread"))
    if kind=="SIMILAR_GROUP":
        evidence.update(similarGroup=True,eventCount=int(baseline.get("eventCount",baseline.get("groupCount",0)) or 0),distinctUsers=int(baseline.get("distinctUsers",0) or 0),distinctDevices=int(baseline.get("distinctDevices",0) or 0),distinctDepartments=int(baseline.get("distinctDepartments",0) or 0),spread=actual_spread,entitySpreadCount=int(baseline.get("entitySpreadCount",0) or 0))
    if actual_spread or signatures & spread_signatures:
        families.append(SPREAD);evidence["spread"]=True
        reasons.append("같은 행동이 서로 다른 사용자 또는 장비에서 확인되었습니다.")
    families=list(dict.fromkeys(families));visible=len(families)>=2
    if not visible:
        reasons=["새로운 행동의 근거는 보존하지만, 서로 다른 유형의 추가 변화가 확인되지 않아 기본 화면에서는 숨깁니다."]
    return {"visible":visible,"category":"REVIEW_REQUIRED" if visible else "ANALYSIS_ONLY","evidenceFamilies":families,"reasons":reasons,"evidence":evidence}


REVIEW_TITLES={
 ("detections","NEW_BEHAVIOR"):"확인이 필요한 새로운 실행 패턴",
 ("firewall","NEW_BEHAVIOR"):"외부 통신 패턴이 달라졌습니다",
 ("xdr","NEW_BEHAVIOR"):"새로운 메일 활동이 반복되었습니다",
 ("inbound","NEW_BEHAVIOR"):"새로운 수신 메일 활동이 반복되었습니다",
 ("outbound","FREQUENCY_SPIKE"):"평소보다 메일 발송 활동이 증가했습니다",
 ("dlp","FREQUENCY_SPIKE"):"평소보다 파일 전송 활동이 증가했습니다",
}

def apply_gate(connection, source):
    rows=connection.execute("SELECT * FROM learner_findings WHERE source=?",(source,)).fetchall()
    frequency=set();spread=set();legacy_spread=set()
    for row in rows:
        if row["finding_type"]=="FREQUENCY_SPIKE":frequency.update(behavior_signatures(row))
        elif row["finding_type"]=="SIMILAR_GROUP":
            baseline=json.loads(row["baseline_json"] or "{}")
            if "spread" not in baseline:legacy_spread.update(behavior_signatures(row))
            elif baseline.get("spread"):spread.update(behavior_signatures(row))
    for row in rows:
        # The old schema has no entity identity per related event. Keep its gate
        # unchanged until a normal full run can calculate Spread v2 safely.
        if behavior_signatures(row) & legacy_spread:continue
        gate=evaluate(row,frequency,spread)
        title=REVIEW_TITLES.get((source,row["finding_type"]),row["title"]) if gate["visible"] else row["title"]
        connection.execute("UPDATE learner_findings SET gate_visible=?,gate_json=?,title=? WHERE finding_id=?",(int(gate["visible"]),json.dumps(gate,ensure_ascii=False),title,row["finding_id"]))
