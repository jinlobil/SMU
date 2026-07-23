import { useEffect, useState } from "react";
import { RefreshButton } from "../components/RefreshButton";


type OrganizationRow = { deptCode: string; deptName: string; user: string };
type OrganizationResponse = { data: { items: OrganizationRow[]; pagination: { page: number; total: number; totalPages: number }; summary: { departments: number; users: number }; source: { exists: boolean } } };
const searchFields = [["all", "전체"], ["deptCode", "DeptCode"], ["deptName", "DeptName"], ["user", "User"]];

export function OrganizationPage() {
  const [items, setItems] = useState<OrganizationRow[]>([]);
  const [query, setQuery] = useState(""); const [field, setField] = useState("all"); const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0); const [totalPages, setTotalPages] = useState(1); const [departments, setDepartments] = useState(0);
  const [sourceExists, setSourceExists] = useState(true); const [sort, setSort] = useState<keyof OrganizationRow>("deptCode"); const [direction, setDirection] = useState<"asc" | "desc">("asc");
  const [loading, setLoading] = useState(true); const [error, setError] = useState("");
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    const controller = new AbortController(); const timer = window.setTimeout(() => {
      setLoading(true); setError(""); const params = new URLSearchParams({ query, field, page: String(page), pageSize: "50", sort, direction });
      fetch(`/api/organizations?${params}`, { signal: controller.signal }).then(async (response) => { const payload = await response.json(); if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`); return payload as OrganizationResponse; }).then((payload) => {
        setItems(payload.data.items); setTotal(payload.data.pagination.total); setTotalPages(payload.data.pagination.totalPages); setDepartments(payload.data.summary.departments); setSourceExists(payload.data.source.exists);
      }).catch((reason: unknown) => { if ((reason as Error).name !== "AbortError") setError(String(reason)); }).finally(() => setLoading(false));
    }, 250); return () => { window.clearTimeout(timer); controller.abort(); };
  }, [query, field, page, sort, direction, reloadKey]);

  const changeSort = (name: keyof OrganizationRow) => { if (sort === name) setDirection(direction === "asc" ? "desc" : "asc"); else { setSort(name); setDirection("asc"); } setPage(1); };
  const header = (label: string, name: keyof OrganizationRow) => <button className="sort-button" onClick={() => changeSort(name)}>{label}<span>{sort === name ? (direction === "asc" ? "↑" : "↓") : "↕"}</span></button>;

  return <><header className="topbar"><div><p className="breadcrumb">Asset / Organization</p><h1>Organization</h1></div><RefreshButton target="organizations" onComplete={() => setReloadKey((key) => key + 1)} /></header>
    <section className="summary-grid"><article><span>부서</span><strong>{departments.toLocaleString()}</strong><small>검색 결과의 고유 부서</small></article><article><span>사용자</span><strong>{total.toLocaleString()}</strong><small>검색 조건에 일치하는 사용자</small></article><article><span>데이터 소스</span><strong className={sourceExists ? "good" : "warn"}>{sourceExists ? "정상" : "없음"}</strong><small>cache/user_groups.json</small></article></section>
    <section className="panel"><div className="panel-head"><div><h2>Organization 목록</h2><p>부서 코드, 부서명, 사용자 기준으로 검색할 수 있습니다.</p></div><div className="search-box"><select value={field} onChange={(event) => { setField(event.target.value); setPage(1); }}>{searchFields.map(([value, label]) => <option value={value} key={value}>{label}</option>)}</select><input value={query} onChange={(event) => { setQuery(event.target.value); setPage(1); }} placeholder="검색어 입력..." /></div></div>
      {error && <div className="error-banner">조회 오류: {error}</div>}{!sourceExists && !error && <div className="empty-banner">아직 Organization 캐시가 없습니다. 기존 앱에서 Organization 새로고침을 한 번 실행해주세요.</div>}
      <div className="table-wrap"><table><thead><tr><th>{header("DeptCode", "deptCode")}</th><th>{header("DeptName", "deptName")}</th><th>{header("User", "user")}</th></tr></thead><tbody>{loading ? <tr><td colSpan={3} className="state-cell">데이터를 불러오는 중입니다...</td></tr> : items.length === 0 ? <tr><td colSpan={3} className="state-cell">표시할 조직 사용자가 없습니다.</td></tr> : items.map((item, index) => <tr key={`${item.deptCode}-${item.user}-${index}`}><td className="hostname">{item.deptCode}</td><td><span className="dept">{item.deptName}</span></td><td>{item.user}</td></tr>)}</tbody></table></div>
      <footer className="pagination"><span>총 {total.toLocaleString()}명</span><div><button disabled={page <= 1} onClick={() => setPage(page - 1)}>이전</button><b>{page} / {totalPages}</b><button disabled={page >= totalPages} onClick={() => setPage(page + 1)}>다음</button></div></footer>
    </section></>;
}
