import { useState } from "react";

type Site = { input: string; network: string; site: string; category: string };
type Candidate = {
  rule: string;
  status: string;
  action: string;
  sourceMatch: "full" | "partial" | "none";
  destinationMatch: "full" | "partial" | "none";
  protocolMatch: boolean;
  portMatch: boolean;
  serviceMatch: boolean;
  sourceZone: string;
  destinationZone: string;
  fullMatch: boolean;
  position: number | null;
};
type FirewallResult = {
  firewall: string;
  available: boolean;
  checkedAt?: string;
  error?: string;
  policy: { state: string; orderReliable?: boolean; matchedRule?: Candidate | null; matches?: Candidate[] };
  routing: { destination: Record<string, string> | null; return: Record<string, string> | null; error?: string };
};
type Result = { source: Site; destination: Site; protocol: string; port: number; path: string[]; partialPath: boolean; firewalls: FirewallResult[]; checkedAt: string };

const policyLabel: Record<string, string> = { allow: "정책 허용 확인", deny: "차단 정책 확인", matched: "정책 일치", missing: "정책 누락", partial: "Partial Match", disabled: "비활성 정책", order_check_required: "Rule Order 확인 필요", unavailable: "조회 불가" };
const tone = (state: string) => state === "allow" ? "success" : state === "deny" || state === "missing" ? "fail" : "exists";
const matchLabel = (value: string) => value === "full" ? "Full Match" : value === "partial" ? "Partial Match" : "No Match";
const routeLabel = (route: Record<string, string> | null) => route
  ? [route.network, route.interface && `Interface: ${route.interface}`, route.gateway && `Gateway: ${route.gateway}`].filter(Boolean).join("\n")
  : "Static Route에서 미확인";

function CandidateTable({ rows, protocol, port }: { rows: Candidate[]; protocol: string; port: number }) {
  if (!rows.length) return <p className="path-no-candidates">Matching Rule이 없습니다.</p>;
  return <div className="table-wrap path-candidate-table"><table><thead><tr><th>Rule Name</th><th>Status</th><th>Action</th><th>Source Match</th><th>Destination Match</th><th>Protocol</th><th>Port</th><th>Source Zone</th><th>Destination Zone</th></tr></thead><tbody>{rows.map((candidate, index) => <tr key={`${candidate.rule}-${index}`}><td>{candidate.rule || "-"}</td><td><span className={`result-pill ${candidate.status === "활성" || candidate.status.toLowerCase() === "enable" ? "success" : "exists"}`}>{candidate.status || "-"}</span></td><td><span className={`result-pill ${["allow", "accept"].includes(candidate.action.toLowerCase()) ? "success" : "fail"}`}>{candidate.action || "-"}</span></td><td>{matchLabel(candidate.sourceMatch)}</td><td>{matchLabel(candidate.destinationMatch)}</td><td>{candidate.protocolMatch ? `${protocol} Match` : "No Match"}</td><td>{candidate.portMatch ? `${port} Match` : "No Match"}</td><td>{candidate.sourceZone || "-"}</td><td>{candidate.destinationZone || "-"}</td></tr>)}</tbody></table></div>;
}

export function FirewallPathCheckPage() {
  const [source, setSource] = useState("101.1.0.50");
  const [destination, setDestination] = useState("100.1.2.10");
  const [protocol, setProtocol] = useState("TCP");
  const [port, setPort] = useState("389");
  const [result, setResult] = useState<Result | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const run = async (refresh = false) => {
    setLoading(true); setError("");
    try {
      const response = await fetch("/api/firewall/path-check", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ source, destination, protocol, port: Number(port), refresh }) });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload?.error?.message || "Path Check 실패");
      setResult(payload.data);
    } catch (reason) { setError(String(reason)); } finally { setLoading(false); }
  };
  const node = (name: string, subtitle: string, firewall?: FirewallResult) => <article className="panel"><b>{name}</b><small>{subtitle}</small>{firewall && <><span className={`result-pill ${tone(firewall.policy.state)}`}>{policyLabel[firewall.policy.state] || firewall.policy.state}</span><span className={`result-pill ${firewall.routing.destination ? "success" : "exists"}`}>{firewall.routing.destination ? "Static Route 확인" : "Static Route 미확인"}</span></>}</article>;
  const allPoliciesConfirmed = Boolean(result?.firewalls.length) && result!.firewalls.every(item => item.policy.state === "allow");
  const allRoutesConfirmed = Boolean(result?.firewalls.length) && result!.firewalls.every(item => item.routing.destination && item.routing.return);
  return <><header className="topbar"><div><p className="breadcrumb">Response / Firewall Path Check</p><h1>Firewall Path Check</h1></div>{result && <div><small>마지막 확인</small><b>{new Date(result.checkedAt).toLocaleString()}</b></div>}</header>
    <section className="panel path-check-form"><div className="integration-form-pair"><label>Source IP / CIDR<input value={source} onChange={event => setSource(event.target.value)} /></label><label>Destination IP / CIDR<input value={destination} onChange={event => setDestination(event.target.value)} /></label></div><div className="integration-form-pair"><label>Protocol<select value={protocol} onChange={event => setProtocol(event.target.value)}><option>TCP</option><option>UDP</option></select></label><label>Destination Port<input type="number" min="1" max="65535" value={port} onChange={event => setPort(event.target.value)} /></label></div><div className="firewall-buttons"><button className="primary-action" disabled={loading} onClick={() => run(false)}>{loading ? "확인 중..." : "Path Check"}</button>{result && <button disabled={loading} onClick={() => run(true)}>최신 정보 다시 조회</button>}</div>{error && <div className="error-banner">{error}</div>}</section>
    {result && <><section className="panel path-summary"><div><b>Source</b><strong>{result.source.input}</strong><span>{result.source.site} · {result.source.category || "Mapping 미확인"}</span></div><div><b>Destination</b><strong>{result.destination.input}</strong><span>{result.destination.site} · {result.destination.category || "Mapping 미확인"}</span></div><div><b>Service</b><strong>{result.protocol} / {result.port}</strong><span>{result.partialPath ? "Path 일부만 확인 가능" : "관리 Firewall Path 확인"}</span></div></section>
      <section className="path-diagram">{node(result.source.site, result.source.input)}{result.firewalls.map(item => <div className="path-segment" key={item.firewall}><i>▶</i>{node(`${item.firewall} Firewall`, item.available ? "Configuration 확인" : "조회 불가", item)}</div>)}<div className="path-segment"><i>▶</i>{node(result.destination.site, `${result.destination.input} · ${result.protocol}/${result.port}`)}</div></section>
      <section className="panel path-summary"><div><b>Policy Path</b><strong>{allPoliciesConfirmed ? "Firewall Policy 확인됨" : result.partialPath ? "Path 일부만 확인 가능" : "Firewall Policy 누락 또는 확인 필요"}</strong></div><div><b>Static Route</b><strong>{allRoutesConfirmed ? "Static Route 확인됨" : "Static Route에서 일치 경로 미확인"}</strong></div><div><b>판정 범위</b><strong>Configuration 기반 Path Check</strong><span>실제 패킷 연결성을 단정하지 않습니다.</span></div></section>
      {result.firewalls.map(item => <section className="panel firewall-results path-firewall-result" key={item.firewall}><header><div><h2>{item.firewall} Firewall</h2><p>Candidate Rule 상세를 유지한 상태에서 최종 Policy 판정을 별도로 표시합니다.</p></div><span className={`result-pill ${tone(item.policy.state)}`}>{policyLabel[item.policy.state] || item.policy.state}</span></header><CandidateTable rows={item.policy.matches || []} protocol={result.protocol} port={result.port} /><div className="table-wrap path-route-table"><table><thead><tr><th>Destination Route</th><th>Return Route</th></tr></thead><tbody><tr><td>{routeLabel(item.routing.destination)}</td><td>{routeLabel(item.routing.return)}</td></tr></tbody></table></div></section>)}
    </>}
  </>;
}
