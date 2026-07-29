import { useCallback, useEffect, useMemo, useState } from "react";

type Metric = { average: number; minimum: number; maximum: number };
type Point = { timestamp: string; cpu: Metric; memory: Metric; memoryUsedBytes: number; memoryTotalBytes: number; samples: number };
type Current = { collector: { running: boolean; intervalSeconds: number; retentionDays: number; lastError: string | null }; sample: { timestamp: string; cpuPercent: number; memoryPercent: number; memoryUsedBytes: number; memoryTotalBytes: number } | null };
type Bucket = "auto" | "5second" | "10second" | "30second" | "minute" | "5minute" | "10minute" | "30minute" | "hour" | "6hour" | "day";
type History = { points: Point[]; bucket: Bucket; bucketSeconds: number };

const pad = (value: number) => String(value).padStart(2, "0");
const localDateTime = (date = new Date()) => `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
const bytes = (value: number) => `${(value / 1073741824).toFixed(1)} GB`;
const bucketLabels: Record<Bucket, string> = { auto: "자동", "5second": "5초", "10second": "10초", "30second": "30초", minute: "1분", "5minute": "5분", "10minute": "10분", "30minute": "30분", hour: "1시간", "6hour": "6시간", day: "1일" };
const presets = [{ label: "10분", minutes: 10 }, { label: "30분", minutes: 30 }, { label: "1시간", minutes: 60 }, { label: "6시간", minutes: 360 }, { label: "24시간", minutes: 1440 }, { label: "7일", minutes: 10080 }, { label: "30일", minutes: 43200 }];

function smoothPath(points: [number, number][]) {
  if (points.length < 2) return points.length ? `M ${points[0][0]} ${points[0][1]}` : "";
  return points.slice(1).reduce((path, point, index) => {
    const previous = points[index], before = points[Math.max(0, index - 1)], after = points[Math.min(points.length - 1, index + 2)];
    return `${path} C ${previous[0] + (point[0] - before[0]) / 6} ${previous[1] + (point[1] - before[1]) / 6}, ${point[0] - (after[0] - previous[0]) / 6} ${point[1] - (after[1] - previous[1]) / 6}, ${point[0]} ${point[1]}`;
  }, `M ${points[0][0]} ${points[0][1]}`);
}

function MetricChart({ title, kind, points, current }: { title: string; kind: "cpu" | "memory"; points: Point[]; current: Current["sample"] }) {
  const [hovered, setHovered] = useState<number | null>(null);
  const width = 1100, height = 250, left = 48, right = 24, bottom = 16;
  const values = points.map(point => point[kind]);
  const x = (index: number) => left + index * (width - left - right) / Math.max(1, points.length - 1);
  const y = (value: number) => height - bottom - Math.max(0, Math.min(100, value)) * (height - bottom - 22) / 100;
  const averagePoints = values.map((value, index) => [x(index), y(value.average)] as [number, number]);
  const path = smoothPath(averagePoints), selected = hovered === null ? null : points[hovered];
  const currentValue = current ? (kind === "cpu" ? current.cpuPercent : current.memoryPercent) : null;
  const average = values.length ? values.reduce((sum, value) => sum + value.average, 0) / values.length : 0;
  const maximum = values.length ? Math.max(...values.map(value => value.maximum)) : 0;
  const minimum = values.length ? Math.min(...values.map(value => value.minimum)) : 0;
  const color = kind === "cpu" ? "var(--trend-detection)" : "var(--trend-email)";
  const hoverX = hovered === null ? 0 : x(hovered), tooltipX = Math.min(width - 234, Math.max(8, hoverX - 110));
  const selectNearest = (event: React.MouseEvent<SVGSVGElement>) => {
    const box = event.currentTarget.getBoundingClientRect();
    const svgX = (event.clientX - box.left) / box.width * width;
    const ratio = Math.max(0, Math.min(1, (svgX - left) / (width - left - right)));
    setHovered(Math.round(ratio * Math.max(0, points.length - 1)));
  };
  return <article className={`system-metric-card ${kind}`}>
    <header><div><h2>{title}</h2><p>평균 {average.toFixed(1)}% · 최대 {maximum.toFixed(1)}% · 최소 {minimum.toFixed(1)}%</p></div><strong>{currentValue === null ? "-" : `${currentValue.toFixed(1)}%`}</strong></header>
    {kind === "memory" && current && <p className="memory-detail">사용 {bytes(current.memoryUsedBytes)} / 전체 {bytes(current.memoryTotalBytes)}</p>}
    <div className="system-chart-area">{points.length === 0 ? <div className="system-empty">선택한 기간에 수집된 데이터가 없습니다.</div> : <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`${title} 사용률 추세`} onMouseMove={selectNearest} onMouseLeave={() => setHovered(null)}>
      <defs><linearGradient id={`${kind}-area`} x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor={color} stopOpacity=".42"/><stop offset="1" stopColor={color} stopOpacity=".02"/></linearGradient></defs>
      {[0, 25, 50, 75, 100].map(value => <g key={value}><line x1={left} x2={width - right} y1={y(value)} y2={y(value)} className="system-grid-line"/><text x="8" y={y(value) + 4} className="axis-label">{value}%</text></g>)}
      {averagePoints.length > 1 && <path d={`${path} L ${averagePoints.at(-1)?.[0]} ${height - bottom} L ${averagePoints[0][0]} ${height - bottom} Z`} fill={`url(#${kind}-area)`} className="trend-area"/>}
      <path d={path} fill="none" stroke={color} strokeWidth="3.5" strokeLinecap="round" className="trend-wave"/>
      {points.length <= 150 && points.map((point, index) => <circle key={point.timestamp} cx={x(index)} cy={y(point[kind].average)} r="4" fill="var(--surface)" stroke={color} strokeWidth="3" className="system-point"/>)}
      {selected && hovered !== null && <g className="system-active-tooltip"><line x1={hoverX} x2={hoverX} y1="14" y2={height - bottom} className="hover-guide visible"/><circle cx={hoverX} cy={y(selected[kind].average)} r="6" fill="var(--surface)" stroke={color} strokeWidth="3"/><g className="day-tooltip system-tooltip visible" transform={`translate(${tooltipX},12)`}><rect width="226" height="104" rx="12"/><text x="14" y="22" className="tooltip-date">{new Date(selected.timestamp).toLocaleString("ko-KR")}</text><text x="14" y="46" className="tooltip-name">평균</text><text x="210" y="46" className="tooltip-value">{selected[kind].average.toFixed(1)}%</text><text x="14" y="65" className="tooltip-name">최대</text><text x="210" y="65" className="tooltip-value">{selected[kind].maximum.toFixed(1)}%</text><text x="14" y="84" className="tooltip-name">최소 · {selected.samples}개 샘플</text><text x="210" y="84" className="tooltip-value">{selected[kind].minimum.toFixed(1)}%</text></g></g>}
    </svg>}</div>
  </article>;
}

export function SystemInfoPage() {
  const now = useMemo(() => new Date(), []), initialStart = useMemo(() => localDateTime(new Date(now.getTime() - 60 * 60 * 1000)), [now]), initialEnd = useMemo(() => localDateTime(now), [now]);
  const [start, setStart] = useState(initialStart), [end, setEnd] = useState(initialEnd), [bucket, setBucket] = useState<Bucket>("auto");
  const [applied, setApplied] = useState({ start: initialStart, end: initialEnd, bucket: "auto" as Bucket });
  const [points, setPoints] = useState<Point[]>([]), [current, setCurrent] = useState<Current | null>(null), [resolvedBucket, setResolvedBucket] = useState<Bucket>("auto"), [error, setError] = useState("");
  const query = useMemo(() => new URLSearchParams(applied).toString(), [applied]);
  const applyPreset = (minutes: number) => { const presetEnd = new Date(), presetStart = new Date(presetEnd.getTime() - minutes * 60000); const next = { start: localDateTime(presetStart), end: localDateTime(presetEnd), bucket: "auto" as Bucket }; setStart(next.start); setEnd(next.end); setBucket("auto"); setApplied(next); };
  const load = useCallback(async () => {
    try {
      const [currentResponse, historyResponse] = await Promise.all([fetch("/api/system-info/current"), fetch(`/api/system-info/history?${query}`)]);
      const [currentPayload, historyPayload] = await Promise.all([currentResponse.json(), historyResponse.json()]);
      if (!currentResponse.ok || !historyResponse.ok) throw new Error(historyPayload?.error?.message || "System-Info 조회 실패");
      const history = historyPayload.data as History; setCurrent(currentPayload.data); setPoints(history.points); setResolvedBucket(history.bucket); setError("");
    } catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)); }
  }, [query]);
  useEffect(() => { void load(); const timer = window.setInterval(() => void load(), 5000); return () => window.clearInterval(timer); }, [load]);
  const collecting = current?.collector.running && !current.collector.lastError;
  return <><header className="topbar system-info-topbar"><div><p className="breadcrumb">System / Config / System-Info</p><h1>System-Info</h1></div><i className={collecting ? "collecting" : "collector-error"}>{collecting ? `5초 수집 중 · ${current?.sample ? new Date(current.sample.timestamp).toLocaleTimeString("ko-KR") : "준비 중"}` : "수집 상태 확인"}</i></header>
    <section className="system-time-controls"><div className="system-presets">{presets.map(preset => <button key={preset.label} onClick={() => applyPreset(preset.minutes)}>{preset.label}</button>)}</div><div className="system-custom-range"><input aria-label="시작 시간" type="datetime-local" value={start} onChange={event => setStart(event.target.value)}/><b>~</b><input aria-label="종료 시간" type="datetime-local" value={end} onChange={event => setEnd(event.target.value)}/><select aria-label="표시 단위" value={bucket} onChange={event => setBucket(event.target.value as Bucket)}>{Object.entries(bucketLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select><button disabled={!start || !end || start >= end} onClick={() => setApplied({ start, end, bucket })}>적용</button><span>표시: {bucketLabels[resolvedBucket]} · 최대 600포인트</span></div></section>
    <section className="system-info">{error && <div className="error-banner">{error}</div>}<MetricChart title="CPU Usage" kind="cpu" points={points} current={current?.sample || null}/><MetricChart title="Memory Usage" kind="memory" points={points} current={current?.sample || null}/></section>
  </>;
}
