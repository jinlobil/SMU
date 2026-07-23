import { useEffect, useState } from "react";

type Pair = [string, number];
type Dashboard = { range: { start: string; end: string }; endpoints: { pc: number; server: number; total: number }; organization: { departments: number; users: number }; totals: Record<string, number>; trend: { dates: string[]; series: Record<string, number[]> }; top: { files: Pair[]; hashes: Pair[]; hosts: Pair[]; rules: Pair[]; senders: Pair[] } };
const colors: Record<string, string> = { "Detection - XDR": "#7c3aed", "Email - XDR": "#0ea5e9", "Inbound Mail": "#16a34a", "Outbound Mail": "#ec4899", File: "#f59e0b" };

function Ranking({ title, rows }: { title: string; rows: Pair[] }) {
  return <article className="dashboard-card ranking"><h2>{title}</h2>{rows.length === 0 ? <p>집계 데이터 없음</p> : <ol>{rows.map(([name, count]) => <li key={name}><span title={name}>{name}</span><b>{count.toLocaleString()}</b></li>)}</ol>}</article>;
}

export function DashboardPage() {
  const [data, setData] = useState<Dashboard | null>(null); const [error, setError] = useState(""); const [loading, setLoading] = useState(true);
  useEffect(() => { fetch("/api/dashboard?days=7").then(async (response) => { const payload = await response.json(); if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`); setData(payload.data); }).catch((reason) => setError(String(reason))).finally(() => setLoading(false)); }, []);
  if (loading) return <div className="dashboard-state">Dashboard 데이터를 집계하는 중입니다...</div>;
  if (error || !data) return <div className="error-banner">Dashboard 조회 오류: {error}</div>;
  const maximum = Math.max(1, ...Object.values(data.trend.series).flat());
  return <><header className="topbar"><div><p className="breadcrumb">Overview / Dashboard</p><h1>Dashboard</h1></div><span className="dashboard-range">{data.range.start} ~ {data.range.end}</span></header>
    <section className="dashboard-metrics"><article><span>Endpoints</span><strong>{data.endpoints.total.toLocaleString()}</strong><small>PC {data.endpoints.pc.toLocaleString()} · Server {data.endpoints.server.toLocaleString()}</small></article><article><span>Organization</span><strong>{data.organization.departments.toLocaleString()}</strong><small>사용자 {data.organization.users.toLocaleString()}명</small></article>{Object.entries(data.totals).map(([name, count]) => <article key={name}><span>{name}</span><strong>{count.toLocaleString()}</strong><small>최근 7일 이벤트</small></article>)}</section>
    <section className="dashboard-card trend-card"><header><div><h2>Threat Trend</h2><p>최근 7일 소스별 이벤트 추이</p></div><div className="trend-legend">{Object.entries(colors).map(([name, color]) => <span key={name}><i style={{ background: color }} />{name}</span>)}</div></header><div className="trend-chart">{data.trend.dates.map((day, dayIndex) => <div className="trend-day" key={day}><div className="trend-bars">{Object.entries(data.trend.series).map(([name, values]) => <i key={name} title={`${name}: ${values[dayIndex]}건`} style={{ height: `${Math.max(2, values[dayIndex] / maximum * 100)}%`, background: colors[name] }} />)}</div><span>{day.slice(5)}</span></div>)}</div></section>
    <section className="dashboard-rankings"><Ranking title="Top File" rows={data.top.files} /><Ranking title="Top Hash" rows={data.top.hashes} /><Ranking title="Top Hostname" rows={data.top.hosts} /><Ranking title="Top Rule" rows={data.top.rules} /><Ranking title="Top Sender IP" rows={data.top.senders} /></section>
  </>;
}
