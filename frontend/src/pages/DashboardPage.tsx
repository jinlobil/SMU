import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";

type Pair = [string, number];
type SummaryRow = [string, Pair[]];
type Range = { start: string; end: string };
type AssetsData = { range: Range; endpoints: { pc: number; server: number; total: number }; organization: { departments: number; users: number }; folderUsage: Record<string, number> };
type MixTrendData = { range: Range; comparisonRange: { day: string; month: string }; totals: Record<string, number>; comparison: Record<string, { day: number | null; month: number | null }>; trend: { dates: string[]; series: Record<string, number[]> }; cache: string };
type TopDetectionData = { range: Range; top: { files: Pair[]; hashes: Pair[]; hosts: Pair[]; rules: Pair[] }; summary: { detection: SummaryRow[] } };
type TopMailData = { range: Range; top: { senders: Pair[] }; summary: { xdr: SummaryRow[]; inbound: SummaryRow[] } };
type TopFileData = { range: Range; summary: { file: SummaryRow[] } };
type DashboardSnapshot = { assets: AssetsData | null; mixTrend: MixTrendData | null; topDetection: TopDetectionData | null; topMail: TopMailData | null; topFile: TopFileData | null };
type GroupName = keyof DashboardSnapshot;

const colors: Record<string, string> = { "Detection - XDR": "var(--trend-detection)", "Email - XDR": "var(--trend-xdr)", "Inbound Mail": "var(--trend-email)", "Outbound Mail": "var(--trend-outbound)", File: "var(--trend-file)" };
const seriesId = (name: string) => name.replaceAll(" ", "").replaceAll("-", "");
const emptySnapshot: DashboardSnapshot = { assets: null, mixTrend: null, topDetection: null, topMail: null, topFile: null };
const emptyTotals = Object.fromEntries(Object.keys(colors).map((name) => [name, 0])) as Record<string, number>;
const emptyTrend = { dates: [] as string[], series: Object.fromEntries(Object.keys(colors).map((name) => [name, []])) as Record<string, number[]> };
let dashboardSnapshot: DashboardSnapshot | null = null;
const summaryTitles: Record<string, string> = { detection: "Detection - XDR Summary", xdr: "Email - XDR Summary", inbound: "Inbound Mail Summary", file: "File Summary" };
const quickRanges = [1, 7, 15, 30];
const dateSpanDays = (rangeStart: string, rangeEnd: string) => { if (!rangeStart || !rangeEnd) return null; const startDate = new Date(`${rangeStart}T00:00:00Z`), endDate = new Date(`${rangeEnd}T00:00:00Z`); if (Number.isNaN(startDate.getTime()) || Number.isNaN(endDate.getTime())) return null; return Math.floor((endDate.getTime() - startDate.getTime()) / 86400000) + 1; };
const quickStart = (anchor: string, days: number) => { const value = new Date(`${anchor}T00:00:00Z`); value.setUTCDate(value.getUTCDate() - days + 1); return value.toISOString().slice(0, 10); };

function LoadingText({ label }: { label: string }) { return <p className="dashboard-loading-inline">{label} 불러오는 중...</p>; }
function Ranking({ title, rows, loading, onSelect }: { title: string; rows: Pair[]; loading?: boolean; onSelect?: (name: string) => void }) { return <article className="dash-card ranking"><h2>{title}</h2>{loading ? <LoadingText label={title} /> : rows.length === 0 ? <p>집계 데이터 없음</p> : <ol>{rows.map(([name, count]) => <li key={name} className={onSelect ? "clickable" : ""} onClick={() => onSelect?.(name)}><span title={name}>{name}</span><b>({count.toLocaleString()})</b></li>)}</ol>}</article>; }
function Percent({ value }: { value: number | null }) { if (value === null) return <b className="same">신규</b>; const className = value > 0 ? "up" : value < 0 ? "down" : "same"; return <b className={className}>{value > 0 ? "▲" : value < 0 ? "▼" : "-"} {value > 0 ? "+" : ""}{value.toFixed(1)}%</b>; }
function SecurityMix({ totals, loading }: { totals: Record<string, number>; loading?: boolean }) { const entries=Object.entries(totals),sum=entries.reduce((total,[,value])=>total+value,0),radius=42,circumference=2*Math.PI*radius;let offset=0;return <article className="dash-card mix-card"><h2>Security Mix</h2>{loading ? <LoadingText label="Security Mix" /> : <div className="mix-content"><svg viewBox="0 0 120 120" role="img" aria-label="조회 기간 솔루션별 이벤트 비율"><circle cx="60" cy="60" r={radius} className="mix-track"/>{entries.map(([name,value])=>{const length=sum?value/sum*circumference:0,current=offset;offset+=length;return <circle key={name} cx="60" cy="60" r={radius} className="mix-segment" stroke={colors[name]} strokeDasharray={`${length} ${circumference-length}`} strokeDashoffset={-current}><title>{name}: {value.toLocaleString()}건</title></circle>})}<text x="60" y="56">TOTAL</text><text x="60" y="70" className="mix-total">{sum.toLocaleString()}</text></svg><ul>{entries.map(([name,value])=><li key={name}><i style={{background:colors[name]}}/><span>{name}</span><b>{sum?`${(value/sum*100).toFixed(1)}%`:"0%"}</b></li>)}</ul></div>}</article>}
function Summary({ name, rows, loading }: { name: string; rows?: SummaryRow[]; loading?: boolean }) { return <article className="dash-card summary-card"><h2>{summaryTitles[name]}</h2>{loading ? <LoadingText label={summaryTitles[name] || name} /> : (rows || []).map(([label, values]) => <p key={label}><b>{label}</b> : {values.length ? `${values[0][0]} (${values[0][1].toLocaleString()})` : "None"}</p>)}</article>; }
function smoothPath(points: [number, number][]) { if (points.length < 2) return ""; return points.slice(1).reduce((path, point, index) => { const previous = points[index]; const before = points[Math.max(0, index - 1)]; const after = points[Math.min(points.length - 1, index + 2)]; const c1x = previous[0] + (point[0] - before[0]) / 6; const c1y = previous[1] + (point[1] - before[1]) / 6; const c2x = point[0] - (after[0] - previous[0]) / 6; const c2y = point[1] - (after[1] - previous[1]) / 6; return `${path} C ${c1x} ${c1y}, ${c2x} ${c2y}, ${point[0]} ${point[1]}`; }, `M ${points[0][0]} ${points[0][1]}`); }

function TrendChart({data,visible,setVisible}:{data:{trend:MixTrendData["trend"]};visible:string[];setVisible:(value:string[])=>void}) {
  const width=1400,height=250,left=22,right=22,active=Object.entries(data.trend.series).filter(([name])=>visible.includes(name));
  const maximum=Math.max(1,...active.flatMap(([,values])=>values));
  const x=(index:number)=>left+index*(width-left-right)/Math.max(1,data.trend.dates.length-1),y=(value:number)=>height-34-value/maximum*(height-70);
  const columnWidth=(width-left-right)/Math.max(1,data.trend.dates.length-1),tooltipHeight=34+active.length*18;
  return <div className="chart-area"><div className="trend-toggles">{Object.entries(colors).map(([name,color])=><label key={name}><input type="checkbox" checked={visible.includes(name)} onChange={()=>setVisible(visible.includes(name)?visible.filter(item=>item!==name):[...visible,name])}/><i style={{background:color}}/>{name}</label>)}</div><svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label="날짜별 전체 보안 솔루션 추세">
    <defs>{Object.entries(colors).map(([name,color])=><linearGradient key={name} id={`area-${seriesId(name)}`} x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor={color} stopOpacity=".34"/><stop offset="1" stopColor={color} stopOpacity="0"/></linearGradient>)}</defs>
    {[0,.25,.5,.75,1].map(part=><line key={part} x1={left} x2={width-right} y1={y(maximum*part)} y2={y(maximum*part)} className="grid-line"/>)}
    {active.map(([name,values],seriesIndex)=>{const points=values.map((value,index)=>[x(index),y(value)] as [number,number]),path=smoothPath(points),areaPath=`${path} L ${points.at(-1)?.[0]} ${height-34} L ${points[0][0]} ${height-34} Z`,clipId=`bubbles-${seriesId(name)}`;return <g key={name} className="trend-series"><defs><clipPath id={clipId}><path d={areaPath}/></clipPath></defs><path d={areaPath} fill={`url(#area-${seriesId(name)})`} className="trend-area"/><g clipPath={`url(#${clipId})`} className="trend-bubbles">{Array.from({length:20},(_,bubbleIndex)=>{const bubbleX=left+24+((bubbleIndex*137+seriesIndex*61)%(width-left-right-48)),drift=9+(bubbleIndex%4)*5,radius=.65+(bubbleIndex%3)*.35;return <circle key={bubbleIndex} r={radius} fill={colors[name]} fillOpacity={.3+(bubbleIndex%3)*.1}><animateMotion path={`M ${bubbleX} ${height-24} C ${bubbleX-drift} ${height-88}, ${bubbleX+drift} ${height-142}, ${bubbleX-drift/2} 20`} dur={`${18+(bubbleIndex%6)*2.4+seriesIndex*1.1}s`} begin={`${-(bubbleIndex*2.7+seriesIndex*1.4)}s`} repeatCount="indefinite"/></circle>})}</g><path d={path} fill="none" stroke={colors[name]} strokeWidth="3.5" strokeLinecap="round" className="trend-wave"/>{values.map((value,index)=><circle key={index} cx={x(index)} cy={y(value)} r="4" fill="var(--surface)" stroke={colors[name]} strokeWidth="3" className="trend-dot"/>)}</g>})}
    {data.trend.dates.map((day,index)=>{const tooltipX=Math.min(width-202,Math.max(8,x(index)-94));return <g key={day} className="day-hover"><rect x={x(index)-columnWidth/2} y="8" width={columnWidth} height={height-28} fill="transparent"/><line x1={x(index)} x2={x(index)} y1="18" y2={height-34} className="hover-guide"/><g className="day-tooltip" transform={`translate(${tooltipX},12)`}><rect width="194" height={tooltipHeight} rx="12"/><text x="14" y="21" className="tooltip-date">{day}</text>{active.map(([name,values],row)=><g key={name} transform={`translate(0,${32+row*18})`}><circle cx="16" cy="0" r="4" fill={colors[name]}/><text x="28" y="4" className="tooltip-name">{name}</text><text x="180" y="4" className="tooltip-value">{(values[index]??0).toLocaleString()}</text></g>)}</g></g>})}
    {data.trend.dates.map((day,index)=><text key={day} x={x(index)} y={height-8} className="axis-label">{day.slice(5)}</text>)}
  </svg></div>;
}

async function fetchGroup<T>(path: string, rangeStart = "", rangeEnd = ""): Promise<T> {
  const params = rangeStart && rangeEnd ? `?start=${rangeStart}&end=${rangeEnd}` : "";
  const response = await fetch(`${path}${params}`);
  const payload = await response.json();
  if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
  return payload.data as T;
}

export function DashboardPage({ onOpenDetection }: { onOpenDetection: (filter: { field: string; query: string; start?: string; end?: string }) => void }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const [snapshot, setSnapshot] = useState<DashboardSnapshot>(dashboardSnapshot || emptySnapshot);
  const [start, setStart] = useState(searchParams.get("from") || "");
  const [end, setEnd] = useState(searchParams.get("to") || "");
  const [errors, setErrors] = useState<string[]>([]);
  const [loading, setLoading] = useState<Record<GroupName, boolean>>({ assets: !dashboardSnapshot?.assets, mixTrend: !dashboardSnapshot?.mixTrend, topDetection: !dashboardSnapshot?.topDetection, topMail: !dashboardSnapshot?.topMail, topFile: !dashboardSnapshot?.topFile });
  const [visible, setVisible] = useState(Object.keys(colors));
  const activeRange = snapshot.mixTrend?.range || snapshot.assets?.range || snapshot.topDetection?.range || { start, end };
  const anyLoading = Object.values(loading).some(Boolean);
  const selectedDays = dateSpanDays(start, end);
  const rangeError = selectedDays !== null && (selectedDays < 1 || selectedDays > 30) ? "Dashboard는 최대 30일까지 조회할 수 있습니다." : "";
  const topRows = Math.max(snapshot.topDetection?.top.hosts.length || 0, snapshot.topDetection?.top.rules.length || 0, snapshot.topMail?.top.senders.length || 0);
  const summaries = useMemo(() => ({
    detection: snapshot.topDetection?.summary.detection,
    xdr: snapshot.topMail?.summary.xdr,
    inbound: snapshot.topMail?.summary.inbound,
    file: snapshot.topFile?.summary.file,
  }), [snapshot]);

  const updateRange = (range: Range) => {
    setStart((current) => current || range.start);
    setEnd((current) => current || range.end);
  };

  const applyQuickRange = (days: number) => {
    const anchor = end || activeRange.end || new Date().toISOString().slice(0, 10);
    setStart(quickStart(anchor, days));
    setEnd(anchor);
  };

  const load = (rangeStart = "", rangeEnd = "") => {
    const days = dateSpanDays(rangeStart, rangeEnd);
    if (days !== null && (days < 1 || days > 30)) {
      setErrors([]);
      return;
    }
    if (rangeStart && rangeEnd) setSearchParams({ from: rangeStart, to: rangeEnd }, { replace: true });
    const groups: [GroupName, string, Promise<DashboardSnapshot[GroupName]>][] = [
      ["assets", "/api/dashboard/assets", fetchGroup<AssetsData>("/api/dashboard/assets", rangeStart, rangeEnd)],
      ["mixTrend", "/api/dashboard/mix-trend", fetchGroup<MixTrendData>("/api/dashboard/mix-trend", rangeStart, rangeEnd)],
      ["topDetection", "/api/dashboard/top-detection", fetchGroup<TopDetectionData>("/api/dashboard/top-detection", rangeStart, rangeEnd)],
      ["topMail", "/api/dashboard/top-mail", fetchGroup<TopMailData>("/api/dashboard/top-mail", rangeStart, rangeEnd)],
      ["topFile", "/api/dashboard/top-file", fetchGroup<TopFileData>("/api/dashboard/top-file", rangeStart, rangeEnd)],
    ];
    setErrors([]);
    setLoading({ assets: true, mixTrend: true, topDetection: true, topMail: true, topFile: true });
    setSnapshot(emptySnapshot);
    groups.forEach(([key, label, request]) => {
      request.then((data) => {
        setSnapshot((previous) => {
          const next = { ...previous, [key]: data };
          dashboardSnapshot = next;
          return next;
        });
        if (data?.range) updateRange(data.range);
      }).catch((reason) => {
        setErrors((previous) => [...previous, `${label}: ${String(reason)}`]);
      }).finally(() => {
        setLoading((previous) => ({ ...previous, [key]: false }));
      });
    });
  };

  useEffect(() => {
    if (start && end) {
      load(start, end);
      return;
    }
    if (dashboardSnapshot?.assets && dashboardSnapshot?.mixTrend && dashboardSnapshot?.topDetection && dashboardSnapshot?.topMail && dashboardSnapshot?.topFile) {
      const range = dashboardSnapshot.mixTrend.range;
      setStart(range.start);
      setEnd(range.end);
      return;
    }
    load();
  }, []);

  return <><header className="topbar dash-topbar"><div><p className="breadcrumb">Overview / Dashboard</p><h1>Dashboard</h1></div><div className="dashboard-range"><span>{activeRange.start && activeRange.end ? `${activeRange.start} ~ ${activeRange.end}` : "조회 기간 준비 중"}</span><input type="date" value={start} onChange={(event) => setStart(event.target.value)} /><b>~</b><input type="date" value={end} onChange={(event) => setEnd(event.target.value)} /><div className="dashboard-quick-ranges">{quickRanges.map((days) => <button key={days} type="button" disabled={anyLoading} onClick={() => applyQuickRange(days)}>{days}일</button>)}</div><button disabled={anyLoading || !start || !end || Boolean(rangeError)} onClick={() => load(start, end)}>{anyLoading ? "조회 중" : "적용"}</button><i>{anyLoading ? "일부 카드 조회 중" : snapshot.mixTrend?.cache === "pre-aggregated" ? "미리 집계됨" : "인덱스 조회"}</i>{rangeError && <small className="dashboard-range-error">{rangeError}</small>}</div></header>
    {errors.length > 0 && !rangeError && <div className="error-banner">Dashboard 조회 오류: {errors.join(" / ")}</div>}
    <section className="dash-top"><div className="asset-stack"><article className="dash-card asset-card"><h2>Endpoints</h2>{loading.assets || !snapshot.assets ? <LoadingText label="Endpoints" /> : <dl><div><dt>PC</dt><dd>{snapshot.assets.endpoints.pc.toLocaleString()} 대</dd></div><div><dt>Server</dt><dd>{snapshot.assets.endpoints.server.toLocaleString()} 대</dd></div></dl>}</article><article className="dash-card asset-card"><h2>Organization</h2>{loading.assets || !snapshot.assets ? <LoadingText label="Organization" /> : <dl><div><dt>조직부서</dt><dd>{snapshot.assets.organization.departments.toLocaleString()} 개</dd></div><div><dt>사원 수</dt><dd>{snapshot.assets.organization.users.toLocaleString()} 명</dd></div></dl>}</article></div><Ranking title="Top File" rows={snapshot.topDetection?.top.files || []} loading={loading.topDetection || !snapshot.topDetection} onSelect={(query) => onOpenDetection({ field: "file", query, start: activeRange.start, end: activeRange.end })} /><Ranking title="Top Hash" rows={snapshot.topDetection?.top.hashes || []} loading={loading.topDetection || !snapshot.topDetection} onSelect={(query) => onOpenDetection({ field: "sha256", query, start: activeRange.start, end: activeRange.end })} /><SecurityMix totals={snapshot.mixTrend?.totals || emptyTotals} loading={loading.mixTrend || !snapshot.mixTrend}/></section>
    <section className="dash-card threat-card"><h2>Threat Trend</h2><div className="threat-content">{loading.mixTrend || !snapshot.mixTrend ? <LoadingText label="Threat Trend" /> : <TrendChart data={{ trend: snapshot.mixTrend.trend || emptyTrend }} visible={visible} setVisible={setVisible}/>}<aside className="comparison"><header><span/><span>전일 대비</span><span>전월 대비</span></header>{Object.entries(snapshot.mixTrend?.comparison || {}).map(([name, values]) => <div key={name}><strong>{name}</strong><Percent value={values.day} /><Percent value={values.month} /></div>)}</aside></div></section>
    <section className="dash-bottom"><article className="dash-card top-analysis"><h2>Top Analysis</h2>{loading.topDetection || loading.topMail ? <LoadingText label="Top Analysis" /> : <table><thead><tr><th>Top Hostname</th><th>Top Rule</th><th>Top Sender IP</th></tr></thead><tbody>{Array.from({ length: topRows }, (_, index) => <tr key={index}><td>{snapshot.topDetection?.top.hosts[index] ? `${snapshot.topDetection.top.hosts[index][0]} (${snapshot.topDetection.top.hosts[index][1]})` : ""}</td><td>{snapshot.topDetection?.top.rules[index] ? `${snapshot.topDetection.top.rules[index][0]} (${snapshot.topDetection.top.rules[index][1]})` : ""}</td><td>{snapshot.topMail?.top.senders[index] ? `${snapshot.topMail.top.senders[index][0]} (${snapshot.topMail.top.senders[index][1]})` : ""}</td></tr>)}</tbody></table>}</article><div className="summary-grid">{Object.entries(summaryTitles).map(([name]) => <Summary key={name} name={name} rows={summaries[name as keyof typeof summaries]} loading={(name === "file" ? loading.topFile : name === "detection" ? loading.topDetection : loading.topMail) || !summaries[name as keyof typeof summaries]} />)}</div></section>
  </>;
}
