import { useState } from "react";

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
  kind: "aws_sg"; label: string; direction: "Inbound" | "Outbound"; state: string; reason: string; broadQuery: boolean;
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
  const rows = step.matches.length ? step.matches : step.evaluations;
  return <section className="panel firewall-results path-firewall-result"><header><div><h2>{step.label}</h2><p>{step.reason}</p></div><span className={`result-pill ${sgTone(step.state)}`}>{sgLabel[step.state]}</span></header>
    <div className="path-summary"><div><b>EC2 Name / Instance</b><strong>{step.endpoint.name || "-"}</strong><span>{step.endpoint.instanceId || "-"}</span></div><div><b>EC2 IP / ENI</b><strong>{step.endpoint.ip || "-"}</strong><span>{step.endpoint.eniId || "-"}</span></div><div><b>Attached Security Group</b><span>{step.groups.map(group => `${group.name} / ${group.id}`).join("\n") || "-"}</span></div></div>
    {rows.length ? <div className="table-wrap path-candidate-table"><table><thead><tr><th>SG Name</th><th>SG ID</th><th>Rule ID</th><th>Protocol</th><th>From Port / Type</th><th>To Port / Code</th><th>Source Type</th><th>Source</th><th>Destination Type</th><th>Destination</th><th>Rule Description</th><th>Match</th><th>확인 내용</th></tr></thead><tbody>{rows.map((rule, index) => <tr key={`${rule.groupId}-${rule.ruleId}-${index}`}><td>{rule.groupName}</td><td>{rule.groupId}</td><td>{rule.ruleId}</td><td>{rule.protocol}</td><td>{rule.fromPort}</td><td>{rule.toPort}</td><td>{step.direction === "Inbound" ? rule.sourceType : "-"}</td><td>{step.direction === "Inbound" ? rule.target : "-"}</td><td>{step.direction === "Outbound" ? rule.sourceType : "-"}</td><td>{step.direction === "Outbound" ? rule.target : "-"}</td><td>{rule.description}</td><td><span className={`result-pill ${sgTone(rule.match)}`}>{sgLabel[rule.match]}</span></td><td>{rule.reason}</td></tr>)}</tbody></table></div> : <p className="path-no-candidates">{step.reason}</p>}
    <p>새 연결의 {step.direction}만 검사합니다. Stateful SG의 응답 트래픽에 Reverse Rule을 요구하지 않습니다.</p>
  </section>;
}

function CandidateTable({ rows }: { rows: Candidate[] }) {
  if (!rows.length) return <p className="path-no-candidates">Matching Rule이 없습니다.</p>;
  return <div className="table-wrap path-candidate-table"><table><thead><tr><th>Rule Name</th><th>Status</th><th>Action</th><th>Source Zone</th><th>Source Object</th><th>Source Resolved</th><th>Destination Zone</th><th>Destination Object</th><th>Destination Resolved</th><th>Service / Group</th><th>Protocol</th><th>Port / Range</th></tr></thead><tbody>{rows.map((candidate, index) => <tr key={`${candidate.rule}-${index}`}><td>{candidate.rule || "-"}</td><td><span className={`result-pill ${candidate.status === "활성" || candidate.status.toLowerCase() === "enable" ? "success" : "exists"}`}>{candidate.status || "-"}</span></td><td><span className={`result-pill ${["allow", "accept"].includes(candidate.action.toLowerCase()) ? "success" : "fail"}`}>{candidate.action || "-"}</span></td><td>{candidate.sourceZone || "-"}</td><td>{addressValue(candidate.sourceObject, candidate.source_wildcard)}</td><td>{addressValue(candidate.sourceResolved, candidate.source_wildcard)}</td><td>{candidate.destinationZone || "-"}</td><td>{addressValue(candidate.destinationObject, candidate.destination_wildcard)}</td><td>{addressValue(candidate.destinationResolved, candidate.destination_wildcard)}</td><td>{candidate.anyService ? "Any" : candidate.service || "-"}</td><td>{candidate.serviceProtocols.map(value => value === "IP" && candidate.serviceProtocolNumbers.length ? `IP (${candidate.serviceProtocolNumbers.join(", ")})` : value).join(", ") || "-"}</td><td>{candidate.servicePorts.join(", ") || (candidate.serviceProtocolNumbers.length ? "해당 없음" : "-")}</td></tr>)}</tbody></table></div>;
}

export function FirewallPathCheckPage() {
  const [source, setSource] = useState("101.1.0.50");
  const [destination, setDestination] = useState("100.1.2.10");
  const [protocol, setProtocol] = useState("TCP");
  const [port, setPort] = useState("389");
  const [protocolNumber, setProtocolNumber] = useState("");
  const [result, setResult] = useState<Result | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const run = async (refresh = false) => {
    setLoading(true); setError("");
    try {
      const usesPort = protocol === "TCP" || protocol === "UDP";
      const response = await fetch("/api/firewall/path-check", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ source, destination, protocol, port: usesPort && port.trim() ? Number(port) : null, protocolNumber: protocol === "IP" && protocolNumber.trim() ? Number(protocolNumber) : null, refresh }) });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload?.error?.message || "Path Check 실패");
      setResult(payload.data);
    } catch (reason) { setError(String(reason)); } finally { setLoading(false); }
  };
  const node = (name: string, subtitle: string, firewall?: FirewallResult, sg?: SGStep) => <article className="panel"><b>{name}</b><small>{subtitle}</small>{firewall && <><span className={`result-pill ${tone(firewall.policy.state)}`}>{policyLabel[firewall.policy.state] || firewall.policy.state}</span><span className={`result-pill ${firewall.routing.destination ? "success" : "exists"}`}>{firewall.routing.destination ? "Static Route 확인" : "Static Route 미확인"}</span></>}{sg && <><span className={`result-pill ${sgTone(sg.state)}`}>{sgLabel[sg.state]}</span><small>{sg.reason}</small></>}</article>;
  const allRoutesConfirmed = Boolean(result?.firewalls.length) && result!.firewalls.every(item => item.routing.destination && item.routing.return);
  const usesPort = protocol === "TCP" || protocol === "UDP";
  const usesProtocolNumber = protocol === "IP";
  const serviceSummary = result?.protocol === "IP" ? `IP / Protocol No. ${result.protocolNumber ?? "ANY"}` : result?.protocol === "TCP" || result?.protocol === "UDP" ? `${result.protocol} / ${result.port ?? "ANY"}` : result?.protocol || "ANY";
  return <><header className="topbar"><div><p className="breadcrumb">Response / Firewall Path Check</p><h1>Firewall Path Check</h1></div>{result && <div><small>마지막 확인</small><b>{new Date(result.checkedAt).toLocaleString()}</b></div>}</header>
    <section className="panel path-check-form"><div className="integration-form-pair"><label>Source IP / CIDR<input value={source} onChange={event => setSource(event.target.value)} /></label><label>Destination IP / CIDR<input value={destination} onChange={event => setDestination(event.target.value)} /></label></div><div className="integration-form-pair"><label>Protocol<select value={protocol} onChange={event => { const value = event.target.value; setProtocol(value); if (!["TCP", "UDP"].includes(value)) setPort(""); if (value !== "IP") setProtocolNumber(""); }}><option value="ANY">ANY</option><option value="TCP">TCP</option><option value="UDP">UDP</option><option value="ICMP">ICMP</option><option value="ICMPV6">ICMPv6</option><option value="IP">IP</option></select></label><label>{usesProtocolNumber ? "Protocol Number (Optional)" : "Destination Port (Optional)"}<input type="number" min={usesProtocolNumber ? 0 : 1} max={usesProtocolNumber ? 255 : 65535} value={usesProtocolNumber ? protocolNumber : port} onChange={event => usesProtocolNumber ? setProtocolNumber(event.target.value) : setPort(event.target.value)} placeholder={usesPort || usesProtocolNumber ? "ANY" : "Port 미사용"} disabled={!usesPort && !usesProtocolNumber} /></label></div><div className="firewall-buttons"><button className="primary-action" disabled={loading} onClick={() => run(false)}>{loading ? "확인 중..." : "Path Check"}</button>{result && <button disabled={loading} onClick={() => run(true)}>최신 정보 다시 조회</button>}</div>{error && <div className="error-banner">{error}</div>}</section>
    {result && <><section className="panel path-summary"><div><b>Source</b><strong>{result.source.input}</strong><span>{result.source.site} · {result.source.category || "Mapping 미확인"}</span></div><div><b>Destination</b><strong>{result.destination.input}</strong><span>{result.destination.site} · {result.destination.category || "Mapping 미확인"}</span></div><div><b>Service</b><strong>{serviceSummary}</strong><span>{result.awsSecurityGroups.networkPath?.reason || (result.partialPath ? "Path 일부만 확인 가능" : "관리 Firewall Path 확인")}</span></div></section>
      <section className="path-diagram">{node(result.source.site, result.source.input)}{result.steps.map((step, index) => <div className="path-segment" key={`${step.kind}-${index}`}><i>▶</i>{step.kind === "aws_sg" ? node(step.label, `${step.endpoint.name || "EC2 미확인"} · ${step.endpoint.eniId || "ENI 미확인"}`, undefined, step) : node(step.label, step.available ? "Configuration 확인" : "조회 불가", step)}</div>)}<div className="path-segment"><i>▶</i>{node(result.destination.site, `${result.destination.input} · ${serviceSummary}`)}</div></section>
      <section className="panel path-summary"><div><b>Policy Path</b><strong>{result.policySummary.label}</strong><span className={`result-pill ${sgTone(result.policySummary.state)}`}>{sgLabel[result.policySummary.state]}</span></div><div><b>Static Route</b><strong>{!result.firewalls.length ? "해당 없음 · Firewall 경유 단계 없음" : allRoutesConfirmed ? "Static Route 확인됨" : "Static Route에서 일치 경로 미확인"}</strong></div><div><b>판정 범위</b><strong>Configuration 기반 Path Check</strong><span>실제 패킷 연결성을 단정하지 않습니다.</span></div></section>
      <section className="panel path-summary"><div><b>Source AWS SG Outbound</b><span>{sgLabel[result.awsSecurityGroups.outbound.state]}</span></div><div><b>Destination AWS SG Inbound</b><span>{sgLabel[result.awsSecurityGroups.inbound.state]}</span></div></section>
      {result.steps.map((item, index) => item.kind === "aws_sg" ? <SecurityGroupResult step={item} key={`${item.direction}-${index}`} /> : <section className="panel firewall-results path-firewall-result" key={item.firewall}><header><div><h2>{item.firewall} Firewall</h2><p>{item.policy.broadQuery ? "Address/Zone Candidate Rule을 표시합니다." : "Protocol/Port까지 일치하는 Rule만 표시합니다."}</p></div><span className={`result-pill ${tone(item.policy.state)}`}>{policyLabel[item.policy.state] || item.policy.state}</span></header><CandidateTable rows={(item.policy.matches || []).filter(candidate => item.policy.broadQuery || candidate.fullMatch)} /><div className="table-wrap path-route-table"><table><thead><tr><th>Destination Route</th><th>Return Route</th></tr></thead><tbody><tr><td>{routeLabel(item.routing.destination)}</td><td>{routeLabel(item.routing.return)}</td></tr></tbody></table></div></section>)}
    </>}
  </>;
}
