import { useCallback, useEffect, useMemo, useState } from "react";

type Metric = { average: number; minimum: number; maximum: number };
type Point = { timestamp: string; cpu: Metric; memory: Metric; memoryUsedBytes: number; memoryTotalBytes: number; samples: number };
type Current = { collector: { running: boolean; intervalSeconds: number; retentionDays: number; lastError: string | null }; sample: { timestamp: string; cpuPercent: number; memoryPercent: number; memoryUsedBytes: number; memoryTotalBytes: number } | null };
type Bucket = "second" | "minute" | "hour" | "day";

const localDate = (date = new Date()) => {
  const offset = date.getTimezoneOffset() * 60000;
  return new Date(date.getTime() - offset).toISOString().slice(0, 10);
};
const bytes = (value: number) => `${(value / 1073741824).toFixed(1)} GB`;

function smoothPath(points: [number, number][]) {
  if (points.length < 2) return points.length ? `M ${points[0][0]} ${points[0][1]}` : "";
  return points.slice(1).reduce((path, point, index) => {
    const previous = points[index], before = points[Math.max(0, index - 1)], after = points[Math.min(points.length - 1, index + 2)];
    return `${path} C ${previous[0] + (point[0] - before[0]) / 6} ${previous[1] + (point[1] - before[1]) / 6}, ${point[0] - (after[0] - previous[0]) / 6} ${point[1] - (after[1] - previous[1]) / 6}, ${point[0]} ${point[1]}`;
  }, `M ${points[0][0]} ${points[0][1]}`);
}

function MetricChart({ title, kind, points, current }: { title: string; kind: "cpu" | "memory"; points: Point[]; current: Current["sample"] }) {
  const width = 1100, height = 270, left = 48, bottom = 34;
  const values = points.map(point => point[kind]);
  const x = (index: number) => left + index * (width - left - 24) / Math.max(1, points.length - 1);
  const y = (value: number) => height - bottom - Math.max(0, Math.min(100, value)) * (height - bottom - 22) / 100;
  const averagePoints = values.map((value, index) => [x(index), y(value.average)] as [number, number]);
  const path = smoothPath(averagePoints);
  const currentValue = current ? (kind === "cpu" ? current.cpuPercent : current.memoryPercent) : null;
  const average = values.length ? values.reduce((sum, value) => sum + value.average, 0) / values.length : 0;
  const maximum = values.length ? Math.max(...values.map(value => value.maximum)) : 0;
  const minimum = values.length ? Math.min(...values.map(value => value.minimum)) : 0;
  const color = kind === "cpu" ? "var(--trend-detection)" : "var(--trend-email)";
  const labelEvery = Math.max(1, Math.ceil(points.length / 8));
  return <article className={`system-metric-card ${kind}`}>
    <header><div><h2>{title}</h2><p>평균 {average.toFixed(1)}% · 최대 {maximum.toFixed(1)}% · 최소 {minimum.toFixed(1)}%</p></div><strong>{currentValue === null ? "-" : `${currentValue.toFixed(1)}%`}</strong></header>
    {kind === "memory" && current && <p className="memory-detail">사용 {bytes(current.memoryUsedBytes)} / 전체 {bytes(current.memoryTotalBytes)}</p>}
    <div className="system-chart-area">{points.length === 0 ? <div className="system-empty">선택한 기간에 수집된 데이터가 없습니다.</div> : <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`${title} 사용률 추세`}>
      <defs><linearGradient id={`${kind}-area`} x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor={color} stopOpacity=".42"/><stop offset="1" stopColor={color} stopOpacity=".02"/></linearGradient></defs>
      {[0, 25, 50, 75, 100].map(value => <g key={value}><line x1={left} x2={width - 24} y1={y(value)} y2={y(value)} className="system-grid-line"/><text x="8" y={y(value) + 4} className="axis-label">{value}%</text></g>)}
      <path d={`${path} L ${averagePoints.at(-1)?.[0]} ${height - bottom} L ${averagePoints[0][0]} ${height - bottom} Z`} fill={`url(#${kind}-area)`} className="trend-area"/>
      <path d={path} fill="none" stroke={color} strokeWidth="3.5" strokeLinecap="round" className="trend-wave"/>
      {points.map((point, index) => <g key={point.timestamp} className="system-point"><circle cx={x(index)} cy={y(point[kind].average)} r="4" fill="var(--surface)" stroke={color} strokeWidth="3"/><title>{new Date(point.timestamp).toLocaleString("ko-KR")}\n평균 {point[kind].average}% / 최대 {point[kind].maximum}% / 최소 {point[kind].minimum}%\n{point.samples}개 샘플</title></g>)}
      {points.map((point, index) => index % labelEvery === 0 || index === points.length - 1 ? <text key={point.timestamp} x={x(index)} y={height - 8} className="axis-label" textAnchor="middle">{new Date(point.timestamp).toLocaleString("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })}</text> : null)}
    </svg>}</div>
  </article>;
}

export function SystemInfoPage() {
  const today = localDate(), initial = today;
  const [start, setStart] = useState(initial), [end, setEnd] = useState(today), [bucket, setBucket] = useState<Bucket>("minute");
  const [applied, setApplied] = useState({ start: initial, end: today, bucket: "minute" as Bucket });
  const [points, setPoints] = useState<Point[]>([]), [current, setCurrent] = useState<Current | null>(null), [error, setError] = useState("");
  const query = useMemo(() => new URLSearchParams({ start: `${applied.start}T00:00:00`, end: `${applied.end}T23:59:59`, bucket: applied.bucket }).toString(), [applied]);
  const load = useCallback(async () => {
    try {
      const [currentResponse, historyResponse] = await Promise.all([fetch("/api/system-info/current"), fetch(`/api/system-info/history?${query}`)]);
      const [currentPayload, historyPayload] = await Promise.all([currentResponse.json(), historyResponse.json()]);
      if (!currentResponse.ok || !historyResponse.ok) throw new Error(historyPayload?.error?.message || "System-Info 조회 실패");
      setCurrent(currentPayload.data); setPoints(historyPayload.data.points); setError("");
    } catch (reason) { setError(String(reason)); }
  }, [query]);
  useEffect(() => { void load(); const timer = window.setInterval(() => void load(), 5000); return () => window.clearInterval(timer); }, [load]);
  const collecting = current?.collector.running && !current.collector.lastError;
  return <><header className="topbar dash-topbar"><div><p className="breadcrumb">System / Config / System-Info</p><h1>System-Info</h1></div><div className="dashboard-range system-info-range"><span>{applied.start} ~ {applied.end}</span><input type="date" value={start} onChange={event => setStart(event.target.value)}/><b>~</b><input type="date" value={end} onChange={event => setEnd(event.target.value)}/><select aria-label="표시 단위" value={bucket} onChange={event => setBucket(event.target.value as Bucket)}><option value="second">초 단위</option><option value="minute">분 단위</option><option value="hour">시간 단위</option><option value="day">일 단위</option></select><button disabled={!start || !end} onClick={() => setApplied({ start, end, bucket })}>적용</button><i className={collecting ? "collecting" : "collector-error"}>{collecting ? `5초 수집 중 · ${current?.sample ? new Date(current.sample.timestamp).toLocaleTimeString("ko-KR") : "준비 중"}` : "수집 상태 확인"}</i></div></header><section className="system-info">
    {error && <div className="error-banner">{error}</div>}
    <MetricChart title="CPU Usage" kind="cpu" points={points} current={current?.sample || null}/>
    <MetricChart title="Memory Usage" kind="memory" points={points} current={current?.sample || null}/>
  </section></>;
}
