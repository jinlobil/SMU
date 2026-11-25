import { useState, type ReactNode } from "react";

type Site = { input: string; network: string; site: string; category: string };
type Candidate = {
  rule: string; status: string; action: string; service: string; serviceResolved: string;
  serviceProtocols: string[]; servicePorts: string[]; serviceProtocolNumbers: string[];
  sourceZone: string; destinationZone: string; sourceObject: string; sourceResolved: string;
  destinationObject: string; destinationResolved: string; source_wildcard: boolean;
  destination_wildcard: boolean; anyService: boolean; fullMatch: boolean;
};
type FirewallResult = {
  firewall: string; available: boolean; checkedAt?: string; error?: string;
  policy: { state: string; orderReliable?: boolean; matchedRule?: Candidate | null; matches?: Candidate[]; broadQuery?: boolean };
  routing: { destination: Record<string, string> | null; return: Record<string, string> | null; error?: string };
};
type SGRule = { groupId: string; groupName: string; ruleId: string; protocol: string; fromPort: number | string; toPort: number | string; target: string; sourceType: string; description: string; match: string; reason: string };
type SGStep = {
  kind: "aws_sg"; label: string; direction: "Inbound" | "Outbound"; state: string; reason: string; broadQuery: boolean; queryMode?: "ip" | "fqdn";
  endpoint: { name?: string; instanceId?: string; eniId?: string; ip?: string };
  groups: { id: string; name: string }[]; matches: SGRule[]; evaluations: SGRule[];
};
type PathStep = SGStep | (FirewallResult & { kind: "firewall"; label: string; state: string });
type Result = { source: Site; destination: Site; protocol: string; port: number | null; protocolNumber: number | null; path: string[]; partialPath: boolean; firewalls: FirewallResult[]; steps: PathStep[]; awsSecurityGroups: { outbound: SGStep; inbound: SGStep; networkPath?: { mode: string; reason: string } | null }; policySummary: { state: string; label: string }; checkedAt: string };

const policyLabel: Record<string, string> = { allow: "정책상 허용", deny: "정책상 차단", matched: "정책 일치", no_matching_rule: "매칭 정책 없음 · 기본 Drop", service_varies: "서비스별 정책 상이", order_check_required: "Rule Order 확인 필요", unavailable: "조회 불가" };
const tone = (state: string) => state === "allow" ? "success" : state === "deny" || state === "no_matching_rule" ? "fail" : "exists";
const routeLabel = (route: Record<string, string> | null) => route
  ? [route.network, route.interface && `Interface: ${route.interface}`, route.gateway && `Gateway: ${route.gateway}`].filter(Boolean).join("\n")
  : "Static Route에서 미확인";
const addressValue = (value: string, wildcard: boolean) => wildcard ? "Any" : value || "-";
const sgLabel: Record<string, string> = { PASS: "PASS · 정책 허용", FAIL: "FAIL · 일치 Allow Rule 없음", "N/A": "N/A · AWS 대상 아님", UNKNOWN: "UNKNOWN · 확인 불가", MATCH: "Exact Allow", CANDIDATE: "Candidate · 조건 확인 필요", NO_MATCH: "불일치" };
const sgTone = (state: string) => state === "PASS" || state === "MATCH" ? "success" : state === "FAIL" ? "fail" : "exists";

function SecurityGroupResult({ step }: { step: SGStep }) {
  const rows = step.state === "FAIL" ? [] : step.matches.filter(rule => step.state !== "PASS" || rule.match === "MATCH");
  const resultReason = step.state === "FAIL" && step.queryMode !== "fqdn" ? "일치하는 Allow Rule 없음" : step.reason;
  return <section className="panel firewall-results path-firewall-result"><header><div><h2>{step.label}</h2><p>{resultReason}</p></div><span className={`result-pill ${sgTone(step.state)}`}>{step.queryMode === "fqdn" && step.state === "UNKNOWN" ? "확인 필요" : sgLabel[step.state]}</span></header>
    <div className="path-summary"><div><b>EC2 Name / Instance</b><strong>{step.endpoint.name || "-"}</strong><span>{step.endpoint.instanceId || "-"}</span></div><div><b>EC2 IP / ENI</b><strong>{step.endpoint.ip || "-"}</strong><span>{step.endpoint.eniId || "-"}</span></div><div><b>Attached Security Group</b><span>{step.groups.map(group => `${group.name} / ${group.id}`).join("\n") || "-"}</span></div></div>
    {rows.length ? <div className="table-wrap path-candidate-table"><table><thead><tr><th>SG Name</th><th>SG ID</th><th>Rule ID</th><th>Protocol</th><th>From Port / Type</th><th>To Port / Code</th><th>Source Type</th><th>Source</th><th>Destination Type</th><th>Destination</th><th>Rule Description</th><th>Match</th><th>확인 내용</th></tr></thead><tbody>{rows.map((rule, index) => <tr key={`${rule.groupId}-${rule.ruleId}-${index}`}><td>{rule.groupName}</td><td>{rule.groupId}</td><td>{rule.ruleId}</td><td>{rule.protocol}</td><td>{rule.fromPort}</td><td>{rule.toPort}</td><td>{step.direction === "Inbound" ? rule.sourceType : "-"}</td><td>{step.direction === "Inbound" ? rule.target : "-"}</td><td>{step.direction === "Outbound" ? rule.sourceType : "-"}</td><td>{step.direction === "Outbound" ? rule.target : "-"}</td><td>{rule.description}</td><td><span className={`result-pill ${sgTone(rule.match)}`}>{sgLabel[rule.match]}</span></td><td>{rule.reason}</td></tr>)}</tbody></table></div> : <p className="path-no-candidates">{resultReason}</p>}
    <p>새 연결의 {step.direction}만 검사합니다. Stateful SG의 응답 트래픽에 Reverse Rule을 요구하지 않습니다.</p>
  </section>;
}

function CandidateTable({ rows }: { rows: Candidate[] }) {
  if (!rows.length) return <p className="path-no-candidates">Matching Rule이 없습니다.</p>;
  return <div className="table-wrap path-candidate-table"><table><thead><tr><th>Rule Name</th><th>Status</th><th>Action</th><th>Source Zone</th><th>Source Object</th><th>Source Resolved</th><th>Destination Zone</th><th>Destination Object</th><th>Destination Resolved</th><th>Service / Group</th><th>Protocol</th><th>Port / Range</th></tr></thead><tbody>{rows.map((candidate, index) => <tr key={`${candidate.rule}-${index}`}><td>{candidate.rule || "-"}</td><td><span className={`result-pill ${candidate.status === "활성" || candidate.status.toLowerCase() === "enable" ? "success" : "exists"}`}>{candidate.status || "-"}</span></td><td><span className={`result-pill ${["allow", "accept"].includes(candidate.action.toLowerCase()) ? "success" : "fail"}`}>{candidate.action || "-"}</span></td><td>{candidate.sourceZone || "-"}</td><td>{addressValue(candidate.sourceObject, candidate.source_wildcard)}</td><td>{addressValue(candidate.sourceResolved, candidate.source_wildcard)}</td><td>{candidate.destinationZone || "-"}</td><td>{addressValue(candidate.destinationObject, candidate.destination_wildcard)}</td><td>{addressValue(candidate.destinationResolved, candidate.destination_wildcard)}</td><td>{candidate.anyService ? "Any" : candidate.service || "-"}</td><td>{candidate.serviceProtocols.map(value => value === "IP" && candidate.serviceProtocolNumbers.length ? `IP (${candidate.serviceProtocolNumbers.join(", ")})` : value).join(", ") || "-"}</td><td>{candidate.servicePorts.join(", ") || (candidate.serviceProtocolNumbers.length ? "해당 없음" : "-")}</td></tr>)}</tbody></table></div>;
}


type AnalysisStep = { type: string; label: string; status: string; reason: string; firewall?: string; reached?: boolean; ingressZone?: string; egressZone?: string; action?: string; matchedRule?: Candidate | null; route?: Record<string,string> | null; candidateRules?: Candidate[]; awsSg?: SGStep };
type Summary = { status: string; source: string; destination: string; service: string; primaryReason: string; blockedAt?: string | null; warnings?: string[] };
type AnalysisCase = { target?: string; source?: string; destination?: string; summary: Summary; analysisPath: AnalysisStep[] };
type AnalysisResult = Partial<Result> & { mode?: string; summary?: Summary; analysisPath?: AnalysisStep[]; groups?: { label: string; status: string; reason: string; zone: string; networks: string[]; fqdns: string[]; results: AnalysisCase[] }[]; resolvedResults?: AnalysisCase[]; details?: unknown };
const legacyCandidates = (item: FirewallResult) => (item.policy.matches || []).filter(candidate => item.policy.broadQuery || candidate.fullMatch);
const analysisTone = (state: string) => state === "PASS" ? "success" : state === "BLOCK" ? "fail" : "exists";

function Fold({ id, title, opened, toggle, children }: { id: string; title: ReactNode; opened: Set<string>; toggle: (id: string, open: boolean) => void; children: ReactNode }) {
  return <details style={{ minWidth: 0, maxWidth: "100%", overflowWrap: "anywhere" }} open={opened.has(id)} onToggle={event => toggle(id, event.currentTarget.open)}><summary>{title}</summary>{children}</details>;
}
function AnalysisPath({ steps, prefix, opened, toggle, source, destination }: { steps: AnalysisStep[]; prefix: string; opened: Set<string>; toggle: (id: string, open: boolean) => void; source?: string; destination?: string }) {
  return <section className="path-diagram">{source && <article className="panel"><b>Source</b><small>{source}</small></article>}{steps.map((step,index) => <div className="path-segment" key={index}><i>▶</i><article className="panel"><b>{step.label}</b><span className={`result-pill ${analysisTone(step.status)}`}>{step.status}</span>{step.reached === false && <small>Not reached due to upstream firewall/SG block</small>}{step.type === "firewall" && <><small>Ingress: {step.ingressZone || "미확인"} → Egress: {step.egressZone || "미확인"}</small><b>Matched Rule: {step.matchedRule?.rule || "-"}</b><small>Action: {step.action || "-"}</small>{step.route && <small>Route: {step.route.network} / {step.route.interface}</small>}</>}<small>{step.reason}</small><Fold id={`${prefix}-${index}`} title="세부 정책 및 경로 정보 보기" opened={opened} toggle={toggle}><>{step.candidateRules && <CandidateTable rows={step.candidateRules} />}<pre style={{ whiteSpace: "pre-wrap", minWidth: 0 }}>{JSON.stringify(step,null,2)}</pre></></Fold></article></div>)}{destination && <div className="path-segment"><i>▶</i><article className="panel"><b>Destination</b><small>{destination}</small></article></div>}</section>;
}
export function FirewallPathCheckPage() {
  const [source,setSource] = useState("101.1.0.50");
  const [destination,setDestination] = useState("100.1.2.10");
  const [protocol,setProtocol] = useState("TCP");
  const [port,setPort] = useState("389");
  const [protocolNumber,setProtocolNumber] = useState("");
  const [result,setResult] = useState<AnalysisResult | null>(null);
  const [loading,setLoading] = useState(false);
  const [error,setError] = useState("");
  const [opened,setOpened] = useState<Set<string>>(new Set());
  const toggle = (id: string, open: boolean) => setOpened(previous => {
    if (previous.has(id) === open) return previous;
    const next = new Set(previous); if (open) next.add(id); else next.delete(id); return next;
  });
  const usesPort = protocol === "TCP" || protocol === "UDP";
  const usesProtocolNumber = protocol === "IP";
  const run = async (refresh = false) => {
    setLoading(true); setError(""); setOpened(new Set()); setResult(null);
    try {
      if (!source.trim() && !destination.trim()) throw new Error("Source 또는 Destination을 입력하세요");
      const response = await fetch("/api/firewall/path-check", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ source, destination, protocol, port: usesPort && port.trim() ? Number(port) : null, protocolNumber: protocol === "IP" && protocolNumber.trim() ? Number(protocolNumber) : null, refresh }) });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload?.error?.message || "Path Check 실패");
      setResult(payload.data);
    } catch (reason) { setError(String(reason)); } finally { setLoading(false); }
  };
  const fallbackSteps: AnalysisStep[] = (result?.steps || []).map(step => step.kind === "aws_sg"
    ? { type: "aws_sg", label: step.label, status: step.state === "FAIL" ? "BLOCK" : step.state, reason: step.reason, awsSg: step }
    : { type: "firewall", firewall: step.firewall, label: step.label, status: step.policy.state === "allow" ? "PASS" : ["deny","no_matching_rule"].includes(step.policy.state) ? "BLOCK" : "UNKNOWN", reason: policyLabel[step.policy.state], action: step.policy.matchedRule?.action, matchedRule: step.policy.matchedRule, candidateRules: legacyCandidates(step), route: step.routing.destination });
  const steps = result?.analysisPath || fallbackSteps;
  const summary: Summary | null = result ? result.summary || { status: result.policySummary?.state === "FAIL" ? "BLOCK" : result.policySummary?.state || "UNKNOWN", source: result.source?.input || source, destination: result.destination?.input || destination, service: `${result.protocol || protocol} / ${result.port ?? "ANY"}`, primaryReason: result.policySummary?.label || "Configuration 확인 필요" } : null;
  const ids = ["configuration","legacy","resolved"];
  steps.forEach((_,index) => ids.push(`path-${index}`));
  result?.resolvedResults?.forEach((item,i) => item.analysisPath.forEach((_,j) => ids.push(`ip-${i}-${j}`)));
  result?.groups?.forEach((group,i) => { ids.push(`group-${i}`); group.results.forEach((item,j) => item.analysisPath.forEach((_,k) => ids.push(`group-${i}-${j}-${k}`))); });
  return <><header className="topbar"><div><p className="breadcrumb">Response / Firewall Path Check</p><h1>Firewall Path Analysis</h1></div>{result?.checkedAt && <div><small>마지막 확인</small><b>{new Date(result.checkedAt).toLocaleString()}</b></div>}</header>
    <section className="panel path-check-form"><div className="integration-form-pair"><label>Source IP / CIDR / FQDN<input value={source} onChange={event => setSource(event.target.value)} /></label><label>Destination IP / CIDR / FQDN<input value={destination} onChange={event => setDestination(event.target.value)} /></label></div><div className="integration-form-pair"><label>Protocol<select value={protocol} onChange={event => { const value = event.target.value; setProtocol(value); if (!["TCP", "UDP"].includes(value)) setPort(""); if (value !== "IP") setProtocolNumber(""); }}><option value="ANY">ANY</option><option value="TCP">TCP</option><option value="UDP">UDP</option><option value="ICMP">ICMP</option><option value="ICMPV6">ICMPv6</option><option value="IP">IP</option></select></label><label>{usesProtocolNumber ? "Protocol Number (Optional)" : "Destination Port (Optional)"}<input type="number" min={usesProtocolNumber ? 0 : 1} max={usesProtocolNumber ? 255 : 65535} value={usesProtocolNumber ? protocolNumber : port} onChange={event => usesProtocolNumber ? setProtocolNumber(event.target.value) : setPort(event.target.value)} placeholder={usesPort || usesProtocolNumber ? "ANY" : "Port 미사용"} disabled={!usesPort && !usesProtocolNumber} /></label></div><div className="firewall-buttons"><button className="primary-action" disabled={loading} onClick={() => run(false)}>{loading ? "확인 중..." : "Path Check"}</button>{result && <button disabled={loading} onClick={() => run(true)}>최신 정보 다시 조회</button>}</div>{error && <div className="error-banner">{error}</div>}</section>

    {result && summary && <>
      <section className="panel path-summary"><div><b>{result.mode || "PATH"}</b><strong className={`result-pill ${analysisTone(summary.status)}`}>{summary.status}</strong><span>{summary.source || "후보 Source"} → {summary.destination || "후보 Destination"}</span><b>{summary.service}</b></div><div><b>{summary.blockedAt ? `Blocked At: ${summary.blockedAt}` : "판정 근거"}</b><strong>{summary.primaryReason}</strong><span>Configuration 기반 분석 · 실제 연결성/장비 상태를 단정하지 않습니다.</span></div><div><b>Additional Findings</b>{summary.warnings?.slice(0,4).map((warning,index) => <span key={index}>{warning}</span>)}</div></section>
      <div className="firewall-buttons"><button onClick={() => setOpened(new Set(ids))}>모두 펼치기</button><button onClick={() => setOpened(new Set())}>모두 접기</button></div>
      {result.mode === "SOURCE_REACHABILITY" || result.mode === "DESTINATION_EXPOSURE" ? <section className="panel"><h2>{result.mode === "SOURCE_REACHABILITY" ? "접근 가능한 대상 / Reachable Destinations" : "접근 가능한 출발지 / Accessible Sources"}</h2>{!result.groups?.length && <p>확인 가능한 정책 Object가 없습니다. 미표시 범위를 허용으로 간주하지 마세요.</p>}{result.groups?.map((group,i) => <Fold key={i} id={`group-${i}`} title={<><b>{group.label}</b> <span className={`result-pill ${analysisTone(group.status)}`}>{group.status}</span> {group.zone}</>} opened={opened} toggle={toggle}><p>{group.reason}</p><p>{[...group.networks,...group.fqdns].join("; ")}</p>{group.results.map((item,j) => <div key={j}><b>{item.target} · {item.summary.status}</b><AnalysisPath steps={item.analysisPath} prefix={`group-${i}-${j}`} opened={opened} toggle={toggle} /></div>)}</Fold>)}</section>
      : <AnalysisPath steps={steps} prefix="path" opened={opened} toggle={toggle} source={summary.source} destination={summary.destination} />}
      {result.resolvedResults && <section className="panel"><Fold id="resolved" title={`Resolved IP별 결과 (${result.resolvedResults.length})`} opened={opened} toggle={toggle}>{result.resolvedResults.map((item,i) => <div key={i}><b>{item.source} → {item.destination} · {item.summary.status}</b><p>{item.summary.primaryReason}</p><AnalysisPath steps={item.analysisPath} prefix={`ip-${i}`} opened={opened} toggle={toggle} /></div>)}</Fold></section>}
      <section className="panel"><Fold id="legacy" title="기존 정책 및 AWS SG 상세" opened={opened} toggle={toggle}>{result.steps?.map((item,index) => item.kind === "aws_sg" ? <SecurityGroupResult step={item} key={index} /> : <section key={index}><h2>{item.firewall} Firewall</h2><p>Matched Rule: {item.policy.matchedRule?.rule || "-"}</p><p>{routeLabel(item.routing.destination)}</p><p>Return: {routeLabel(item.routing.return)}</p></section>)}</Fold><Fold id="configuration" title="NAT / Route / Return Route / Interface / Zone / Gateway / Resolved Objects 상세" opened={opened} toggle={toggle}><pre>{JSON.stringify(result.details || result,null,2)}</pre></Fold></section>
    </>}
  </>;
}
