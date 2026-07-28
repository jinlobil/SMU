import { useEffect, useState } from "react";
import { RangeRefreshButton } from "../components/RangeRefreshButton";


type Detection = { id: string; time: string; hostname: string; dept: string; username: string; privateIp: string; publicIp: string; file: string; sha256: string; rule: string; lineage: string };
type Condition = { field: string; query: string };
type DetectionResponse = { data: { items: Detection[]; pagination: { total: number; totalPages: number }; source: { files: string[] } } };
const fields = [["all", "ALL"], ["hostname", "Hostname"], ["dept", "Dept"], ["username", "Username"], ["privateIp", "Private IP"], ["publicIp", "Public IP"], ["file", "File"], ["sha256", "SHA256"], ["rule", "Rule"], ["lineage", "Lineage"], ["rawData", "RawData"]];
const columns: [keyof Detection, string][] = [["time", "Time"], ["hostname", "Hostname"], ["dept", "Dept"], ["username", "Username"], ["privateIp", "Private IP"], ["publicIp", "Public IP"], ["file", "File"], ["sha256", "SHA256"], ["rule", "Rule"], ["lineage", "Lineage"]];
const localDate = (offset = 0) => { const value = new Date(); value.setDate(value.getDate() + offset); return value.toISOString().slice(0, 10); };

export function DetectionPage() {
  const [start, setStart] = useState(localDate(-6)); const [end, setEnd] = useState(localDate());
  const [conditions, setConditions] = useState<Condition[]>([{ field: "all", query: "" }]);
  const [items, setItems] = useState<Detection[]>([]); const [total, setTotal] = useState(0); const [totalPages, setTotalPages] = useState(1); const [files, setFiles] = useState<string[]>([]);
  const [page, setPage] = useState(1); const [sort, setSort] = useState<keyof Detection>("time"); const [direction, setDirection] = useState<"asc" | "desc">("desc");
  const [loading, setLoading] = useState(true); const [error, setError] = useState(""); const [detail, setDetail] = useState<Record<string, unknown> | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    const controller = new AbortController(); const timer = window.setTimeout(() => {
      setLoading(true); setError(""); const active = conditions.filter((condition) => condition.query.trim());
      const params = new URLSearchParams({ start, end, conditions: JSON.stringify(active), page: String(page), pageSize: "50", sort, direction });
      fetch(`/api/detections?${params}`, { signal: controller.signal }).then(async (response) => { const payload = await response.json(); if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`); return payload as DetectionResponse; }).then((payload) => {
        setItems(payload.data.items); setTotal(payload.data.pagination.total); setTotalPages(payload.data.pagination.totalPages); setFiles(payload.data.source.files);
      }).catch((reason: unknown) => { if ((reason as Error).name !== "AbortError") setError(String(reason)); }).finally(() => setLoading(false));
    }, 300); return () => { window.clearTimeout(timer); controller.abort(); };
  }, [start, end, conditions, page, sort, direction, reloadKey]);

  const updateCondition = (index: number, patch: Partial<Condition>) => { setConditions((current) => current.map((condition, position) => position === index ? { ...condition, ...patch } : condition)); setPage(1); };
  const changeSort = (name: keyof Detection) => { if (sort === name) setDirection(direction === "asc" ? "desc" : "asc"); else { setSort(name); setDirection("asc"); } setPage(1); };
  const openDetail = async (row: Detection) => { try { const response = await fetch(`/api/detections/${row.id}?start=${start}&end=${end}`); const payload = await response.json(); if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`); setDetail(payload.data.raw); } catch (reason) { setError(String(reason)); } };

  return <><header className="topbar"><div><p className="breadcrumb">Detection / Detection - XDR</p><h1>Detection - XDR</h1></div><div className="range-actions"><div className="date-range"><label>시작<input type="date" value={start} onChange={(event) => { setStart(event.target.value); setPage(1); }} /></label><span>~</span><label>종료<input type="date" value={end} onChange={(event) => { setEnd(event.target.value); setPage(1); }} /></label></div><RangeRefreshButton target="detections" start={start} end={end} onComplete={() => setReloadKey((key) => key + 1)} /></div></header>
    <section className="summary-grid"><article><span>탐지 결과</span><strong>{total.toLocaleString()}</strong><small>Endpoint 센서 탐지</small></article><article><span>조회 기간</span><strong className="range-value">{start}<b>~</b>{end}</strong><small>한국 시간 기준</small></article><article><span>캐시 파일</span><strong>{files.length}</strong><small>기간 내 발견된 일별 파일</small></article></section>
    <section className="panel"><div className="detection-tools"><div><h2>AND 다중 검색</h2><p>조건을 추가하면 모든 조건에 일치하는 탐지만 표시합니다.</p></div><button onClick={() => setConditions((current) => [...current, { field: "all", query: "" }])}>+ 조건 추가</button></div>
      <div className="condition-list">{conditions.map((condition, index) => <div className="condition-row" key={index}><select value={condition.field} onChange={(event) => updateCondition(index, { field: event.target.value })}>{fields.map(([value, label]) => <option value={value} key={value}>{label}</option>)}</select><input value={condition.query} onChange={(event) => updateCondition(index, { query: event.target.value })} placeholder="검색어 입력..." />{conditions.length > 1 && <button onClick={() => setConditions((current) => current.filter((_, position) => position !== index))}>−</button>}</div>)}</div>
      {error && <div className="error-banner">조회 오류: {error}</div>}
      <div className="table-wrap detection-table"><table><thead><tr>{columns.map(([name, label]) => <th key={name}><button className="sort-button" onClick={() => changeSort(name)}>{label}<span>{sort === name ? (direction === "asc" ? "↑" : "↓") : "↕"}</span></button></th>)}</tr></thead><tbody>{loading ? <tr><td colSpan={10} className="state-cell">Detection 캐시를 조회하는 중입니다...</td></tr> : items.length === 0 ? <tr><td colSpan={10} className="state-cell">조건에 일치하는 Endpoint Detection이 없습니다.</td></tr> : items.map((row) => <tr key={row.id} onDoubleClick={() => openDetail(row)}>{columns.map(([name]) => <td key={name} className={name === "hostname" ? "entity-name" : name === "dept" ? "dept-name" : ""}>{row[name]}</td>)}</tr>)}</tbody></table></div>
      <footer className="pagination"><span>총 {total.toLocaleString()}개 · 행 더블클릭: Raw Detail</span><div><button disabled={page <= 1} onClick={() => setPage(page - 1)}>이전</button><b>{page} / {totalPages}</b><button disabled={page >= totalPages} onClick={() => setPage(page + 1)}>다음</button></div></footer>
    </section>
    {detail && <div className="modal-backdrop" onMouseDown={() => setDetail(null)}><section className="detail-modal" onMouseDown={(event) => event.stopPropagation()}><header><div><span>Detection Raw Detail</span><h2>Endpoint Detection Event</h2></div><button onClick={() => setDetail(null)}>×</button></header><pre>{JSON.stringify(detail, null, 2)}</pre></section></div>}
  </>;
}
