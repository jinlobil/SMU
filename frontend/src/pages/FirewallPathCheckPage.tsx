import { useState } from "react";

type Status = "PASS" | "BLOCK" | "WARNING" | "UNKNOWN" | "NOT_REACHED";
type Summary = {
  status: Status; source?: string; destination?: string; service?: string;
  primaryReason: string; blockedAt?: string | null; matchedRule?: string;
  ingressZone?: string; egressZone?: string; action?: string; warnings?: string[];
};
type Step = {
  type: string; label: string; status: Status; reason: string; firewall?: string;
  ingressZone?: string; egressZone?: string; matchedRule?: { rule: string; action?: string; sourceObject?: string; destinationObject?: string; service?: string } | null;
  action?: string; rule?: string; evidence?: Record<string, string | null>;
  translation?: { original: string; translated: string; originalPort?: number; translatedPort?: number };
  route?: { routeType?: string; network?: string; interface?: string; zone?: string; gateway?: string } | null;
  gateway?: { Name?: string; "Gateway IP"?: string; Type?: string; Weight?: string } | null;
  awsSg?: { direction?: string; state?: string; reason?: string; matches?: { description?: string; ruleId?: string; protocol?: string; fromPort?: number; toPort?: number }[] };
};
type Progress = { nodes: { id: string; title: string; status: Status; reason: string }[]; links: { from: string; to: string; active: boolean; status: Status }[] };
type Case = { pathContext?: string; target?: string; source?: string; destination?: string; summary: Summary; analysisPath: Step[]; progress?: Progress; serviceResults?: ServiceCase[]; networkResults?: Case[] };
type ServiceCase = Case & { protocol: string; fromPort: number | null; toPort: number | null; protocolNumber?: number; protocolNumbers?: number[] };
type Group = { label: string; status: Status; reason: string; site?: string; zone?: string; results: Case[]; publication?: { publishedVia: string; rule: string } };
type LegacyStep = { kind: string; label: string; firewall?: string; state: string; reason?: string; policy?: { state: string; matchedRule?: Step["matchedRule"] }; routing?: { destination: Step["route"] } };
type Result = Case & { mode?: string; groups?: Group[]; resolvedResults?: Case[]; checkedAt?: string; steps?: LegacyStep[]; source?: string; destination?: string };
const labels: Record<Status, string> = { PASS: "허용", BLOCK: "차단", WARNING: "주의", UNKNOWN: "판정 불가", NOT_REACHED: "도달하지 않음" };
const tone = (status: Status) => status === "PASS" ? "success" : status === "BLOCK" ? "fail" : "exists";
const legacyPolicy: Record<string, string> = { no_matching_rule: "매칭 정책 없음 · 기본 Drop", service_varies: "서비스별 결과 상이" };

function Badge({ status }: { status: Status }) {
  return <span className={`result-pill ${tone(status)}`} data-status={status}>{labels[status]} · {status}</span>;
}
function PathProgress({ progress, context }: { progress: Progress; context?: string }) {
  return <nav className="panel path-progress" aria-label="패킷 이동 경로">{context && <p>{context}</p>}<ol>{progress.nodes.map((node, index) => <li key={node.id} data-status={node.status} data-link-active={index === 0 || progress.links[index - 1]?.active ? "true" : "false"}>
    <span className="path-progress-dot" aria-hidden="true">{node.status === "BLOCK" ? "✕" : node.status === "NOT_REACHED" ? "○" : "●"}</span>
    <b>{node.title}</b><small>{labels[node.status]}</small>
  </li>)}</ol></nav>;
}
function StepCard({ step }: { step: Step }) {
  const evidence = step.evidence || (step.awsSg ? { Direction: step.awsSg.direction || step.label, Rule: step.awsSg.matches?.map(item => item.description || item.ruleId).filter(Boolean).join("; ") || "-" } : {});
  return <li className="path-vertical-step" data-status={step.status}><article className="panel">
    <header><h3>{step.label}</h3><Badge status={step.status} /></header>
    {step.status === "NOT_REACHED" ? <p>앞 단계에서 차단되어 이 단계에 도달하지 않았습니다.</p> : <>
      {step.type === "firewall" && <div className="path-facts"><span>Zone <b>{step.ingressZone || "-"} → {step.egressZone || "-"}</b></span><span>Matched Rule <b>{step.matchedRule?.rule || (step.status === "BLOCK" ? "기본 Drop / 일치 Rule 없음" : "단일 적용 Rule 없음")}</b></span><span>Action <b>{step.action || "-"}</b></span></div>}
      {step.translation && <p>{step.translation.original} → <b>{step.translation.translated}</b>{step.rule && <> · Rule: {step.rule}</>}</p>}
      {step.route && ["route", "return_route"].includes(step.type) && <div className="path-facts"><span>{step.route.routeType || "Static"} <b>{step.route.network}</b></span><span>Interface <b>{step.route.interface || "-"}</b> / Zone <b>{step.route.zone || "-"}</b></span>{step.route.gateway && <span>Gateway <b>{step.route.gateway}</b></span>}</div>}
      {step.gateway && <p>{step.gateway["Gateway IP"]} · {step.gateway.Type} · Weight {step.gateway.Weight || "-"} · 설정 기준</p>}
      {(!step.translation || step.status !== "PASS") && <p>{step.reason}</p>}
      {Object.keys(evidence).length > 0 && <details><summary>판정 근거 보기</summary><dl className="path-evidence">{Object.entries(evidence).filter(([, value]) => value).map(([key, value]) => <div key={key}><dt>{key}</dt><dd>{value}</dd></div>)}</dl></details>}
    </>}
  </article></li>;
}
// Only old API responses need this compatibility adapter. New responses own all transitions.
function legacyView(steps: LegacyStep[], source: string, destination: string): Case {
  let blocked = false;
  const path: Step[] = steps.map(item => {
    const state = item.policy?.state || item.state;
    const status: Status = blocked ? "NOT_REACHED" : ["deny", "no_matching_rule", "FAIL"].includes(state) ? "BLOCK" : ["allow", "PASS"].includes(state) ? "PASS" : "UNKNOWN";
    if (status === "BLOCK") blocked = true;
    return { type: item.kind, label: item.label, status, reason: item.reason || legacyPolicy[state] || state, matchedRule: item.policy?.matchedRule, action: item.policy?.matchedRule?.action, route: item.routing?.destination };
  });
  const nodes = [{ id: "source", title: "Source", status: "PASS" as Status, reason: source }, ...path.map((item, i) => ({ id: `legacy-${i}`, title: item.label, status: item.status, reason: item.reason })), { id: "destination", title: "Destination", status: (blocked ? "NOT_REACHED" : "UNKNOWN") as Status, reason: destination }];
  return { summary: { status: blocked ? "BLOCK" : "UNKNOWN", source, destination, primaryReason: path.find(step => step.status === "BLOCK")?.reason || "레거시 API 분석 결과" }, analysisPath: path, progress: { nodes, links: nodes.slice(1).map((node, i) => ({ from: nodes[i].id, to: node.id, active: node.status !== "NOT_REACHED", status: node.status })) } };
}
const serviceLabel = (item: ServiceCase) => item.protocol === "IP" ? `IP / ${item.protocolNumbers?.join(", ") || item.protocolNumber}` : `${item.protocol} / ${item.fromPort === null ? "전체" : item.fromPort === item.toPort ? item.fromPort : `${item.fromPort}–${item.toPort}`}`;

export function FirewallPathCheckPage() {
  const [source, setSource] = useState("101.1.0.50");
  const [destination, setDestination] = useState("100.1.2.10");
  const [protocol, setProtocol] = useState("TCP");
  const [port, setPort] = useState("389");
  const [protocolNumber, setProtocolNumber] = useState("");
  const [result, setResult] = useState<Result | null>(null);
  const [selected, setSelected] = useState<Case | null>(null);
  const [network, setNetwork] = useState<Case | null>(null);
  const [service, setService] = useState<ServiceCase | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const usesPort = protocol === "TCP" || protocol === "UDP";
  const usesProtocolNumber = protocol === "IP";
  const run = async (refresh = false) => {
    setLoading(true); setError(""); setResult(null); setSelected(null); setNetwork(null); setService(null);
    try {
      if (!source.trim() && !destination.trim()) throw new Error("Source 또는 Destination을 입력하세요");
      const response = await fetch("/api/firewall/path-check", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ source, destination, protocol, port: usesPort && port.trim() ? Number(port) : null, protocolNumber: protocol === "IP" && protocolNumber.trim() ? Number(protocolNumber) : null, refresh }) });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload?.error?.message || "Path Check 실패");
      setResult(payload.data);
    } catch (reason) { setError(String(reason)); } finally { setLoading(false); }
  };
  const oneSided = result?.mode === "SOURCE_REACHABILITY" || result?.mode === "DESTINATION_EXPOSURE";
  const rootView = result?.analysisPath ? result : result ? legacyView(result.steps || [], source, destination) : null;
  const scope = selected || rootView;
  const parent = network || scope;
  const view = service || parent;
  const summary = service?.summary || network?.summary || selected?.summary || result?.summary || rootView?.summary;
  const choose = (item: Case) => { setSelected(item); setNetwork(null); setService(null); };
  return <><header className="topbar"><div><p className="breadcrumb">Response / Firewall Path Check</p><h1>Firewall Path Analysis</h1></div>{result?.checkedAt && <small>마지막 확인 {new Date(result.checkedAt).toLocaleString()}</small>}</header>
    <section className="panel path-check-form"><div className="integration-form-pair"><label>Source IP / CIDR / FQDN<input value={source} onChange={event => setSource(event.target.value)} /></label><label>Destination IP / CIDR / FQDN<input value={destination} onChange={event => setDestination(event.target.value)} /></label></div><div className="integration-form-pair"><label>Protocol<select value={protocol} onChange={event => { const value = event.target.value; setProtocol(value); if (!["TCP", "UDP"].includes(value)) setPort(""); if (value !== "IP") setProtocolNumber(""); }}><option value="ANY">ANY</option><option value="TCP">TCP</option><option value="UDP">UDP</option><option value="ICMP">ICMP</option><option value="ICMPV6">ICMPv6</option><option value="IP">IP</option></select></label><label>{usesProtocolNumber ? "Protocol Number (Optional)" : "Destination Port (Optional)"}<input type="number" min={usesProtocolNumber ? 0 : 1} max={usesProtocolNumber ? 255 : 65535} value={usesProtocolNumber ? protocolNumber : port} onChange={event => usesProtocolNumber ? setProtocolNumber(event.target.value) : setPort(event.target.value)} placeholder={usesPort || usesProtocolNumber ? "ANY" : "Port 미사용"} disabled={!usesPort && !usesProtocolNumber} /></label></div><div className="firewall-buttons"><button className="primary-action" disabled={loading} onClick={() => run(false)}>{loading ? "확인 중..." : "Path Check"}</button>{result && <button disabled={loading} onClick={() => run(true)}>최신 정보 다시 조회</button>}</div>{error && <div className="error-banner">{error}</div>}</section>
    {result && summary && <>
      <section className="panel path-summary" aria-label="분석 결론"><div><b>{result.mode || "PATH"}</b><Badge status={summary.status} /><strong>{summary.source || source || "후보 Source"} → {summary.destination || destination || "후보 Destination"}</strong><span>{summary.service || `${protocol} / ${port || "ANY"}`}</span></div><div><b>{summary.blockedAt ? `${summary.blockedAt}에서 차단` : "판정 결과"}</b><strong>{summary.primaryReason}</strong>{summary.matchedRule && <span>Matched Rule: {summary.matchedRule} · Action: {summary.action}</span>}{summary.ingressZone && <span>{summary.ingressZone} → {summary.egressZone}</span>}</div><div><b>Configuration 기준 분석</b>{summary.warnings?.slice(0, 3).map((warning, i) => <small key={i}>{warning}</small>)}</div></section>
      {oneSided && <section className="panel path-scope-list"><h2>{result.mode === "SOURCE_REACHABILITY" ? "접근 가능한 대상" : "접근 가능한 출발지"}</h2>{!result.groups?.length && <p>수집된 정책에서 대응하는 접근 범위를 찾지 못했습니다.</p>}{result.groups?.map((group, i) => <div className="path-scope" key={i}><b>{group.label}</b><Badge status={group.status} /><small>{group.site} {group.zone} · {group.reason}</small>{group.publication && <small>Published: {group.publication.publishedVia} · NAT: {group.publication.rule}</small>}{group.results.length === 1 ? <button onClick={() => choose(group.results[0])} aria-pressed={selected === group.results[0]}>경로 보기: {group.results[0].target}</button> : <label>분석할 Network<select aria-label="분석할 Network" value={group.results.findIndex(item => item === selected)} onChange={event => { const item = group.results[Number(event.target.value)]; if (item) choose(item); }}><option value={-1}>Network 선택 ({group.results.length})</option>{group.results.map((item, j) => <option value={j} key={j}>{item.target} · {labels[item.summary.status]}</option>)}</select></label>}</div>)}</section>}
      {result.resolvedResults && <section className="panel path-scope-list"><h2>Resolved IP별 결과 ({result.resolvedResults.length})</h2>{result.resolvedResults.map((item, i) => <button key={i} onClick={() => choose(item)} aria-pressed={selected === item}>{item.source} → {item.destination} · {labels[item.summary.status]}</button>)}</section>}
      {(!oneSided || selected) && view && <section className="path-selected-result" key={`${selected?.target || "root"}-${service ? serviceLabel(service) : "all"}`}>
        {scope?.networkResults?.length ? <section className="panel path-service-results"><h2>Network별 판정</h2><label>Network 범위<select aria-label="Network 범위" value={network ? scope.networkResults.indexOf(network) : -1} onChange={event => { setNetwork(scope.networkResults?.[Number(event.target.value)] || null); setService(null); }}><option value={-1}>전체 범위 요약</option>{scope.networkResults.map((item, i) => <option key={i} value={i}>{item.target} · {labels[item.summary.status]}</option>)}</select></label></section> : null}
        {view.progress && <PathProgress progress={view.progress} context={view.pathContext} />}
        {(parent?.serviceResults?.length || 0) > 1 ? <section className="panel path-service-results"><h2>서비스별 판정</h2><label>서비스 범위<select aria-label="서비스 범위" value={service ? parent!.serviceResults!.indexOf(service) : -1} onChange={event => setService(parent!.serviceResults?.[Number(event.target.value)] || null)}><option value={-1}>전체 범위 요약</option>{parent!.serviceResults!.map((item, i) => <option key={i} value={i}>{serviceLabel(item)} · {labels[item.summary.status]}</option>)}</select></label></section> : null}
        <ol className="path-diagram path-vertical" aria-label="패킷 단계별 판정"><li className="path-vertical-step" data-status="PASS"><article className="panel"><h3>Source</h3><p>{view.summary.source || source}</p></article></li>{view.analysisPath.map((step, i) => <StepCard step={step} key={i} />)}<li className="path-vertical-step" data-status={view.progress?.nodes.at(-1)?.status || "UNKNOWN"}><article className="panel"><h3>Destination</h3><Badge status={view.progress?.nodes.at(-1)?.status || "UNKNOWN"} /><p>{view.progress?.nodes.at(-1)?.reason || view.summary.destination || destination}</p></article></li></ol>
      </section>}
    </>}
  </>;
}
