import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

type Endpoint = {
  hostname: string;
  userId: string;
  user: string;
  dept: string;
  ip: string;
  lastSeen: string;
};

type EndpointResponse = {
  success: boolean;
  data: {
    items: Endpoint[];
    pagination: { page: number; pageSize: number; total: number; totalPages: number };
    source: { path: string; exists: boolean };
  };
};

const menus = ["Dashboard", "Detection", "Forensics", "Response", "Asset", "Lab", "Config"];
const searchFields = [
  ["all", "전체"], ["hostname", "Hostname"], ["userId", "User ID"],
  ["user", "User"], ["dept", "Dept"], ["ip", "IP"],
];

function reportClientError(payload: Record<string, unknown>) {
  const body = JSON.stringify(payload);
  if (navigator.sendBeacon) navigator.sendBeacon("/api/client-errors", new Blob([body], { type: "application/json" }));
  else fetch("/api/client-errors", { method: "POST", headers: { "Content-Type": "application/json" }, body, keepalive: true });
}

window.addEventListener("error", (event) => reportClientError({
  message: event.message, source: event.filename, line: event.lineno, column: event.colno, stack: event.error?.stack,
}));
window.addEventListener("unhandledrejection", (event) => reportClientError({
  message: String(event.reason), stack: event.reason?.stack,
}));

function App() {
  const [health, setHealth] = useState<"loading" | "ok" | "error">("loading");
  const [items, setItems] = useState<Endpoint[]>([]);
  const [query, setQuery] = useState("");
  const [field, setField] = useState("all");
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [sourceExists, setSourceExists] = useState(true);
  const [sort, setSort] = useState<keyof Endpoint>("hostname");
  const [direction, setDirection] = useState<"asc" | "desc">("asc");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    fetch("/api/health").then((response) => {
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      setHealth("ok");
    }).catch(() => setHealth("error"));
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      setLoading(true);
      setError("");
      const params = new URLSearchParams({ query, field, page: String(page), pageSize: "50", sort, direction });
      fetch(`/api/endpoints?${params}`, { signal: controller.signal })
        .then(async (response) => {
          const payload = await response.json();
          if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
          return payload as EndpointResponse;
        })
        .then((payload) => {
          setItems(payload.data.items);
          setTotal(payload.data.pagination.total);
          setTotalPages(payload.data.pagination.totalPages);
          setSourceExists(payload.data.source.exists);
        })
        .catch((reason: unknown) => {
          if ((reason as Error).name !== "AbortError") setError(String(reason));
        })
        .finally(() => setLoading(false));
    }, 250);
    return () => { window.clearTimeout(timer); controller.abort(); };
  }, [query, field, page, sort, direction]);

  const changeSort = (fieldName: keyof Endpoint) => {
    if (sort === fieldName) setDirection(direction === "asc" ? "desc" : "asc");
    else { setSort(fieldName); setDirection("asc"); }
    setPage(1);
  };

  const header = (label: string, fieldName: keyof Endpoint) => (
    <button className="sort-button" onClick={() => changeSort(fieldName)}>
      {label}<span>{sort === fieldName ? (direction === "asc" ? "↑" : "↓") : "↕"}</span>
    </button>
  );

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand"><span>SMU</span><strong>Monitoring</strong></div>
        <nav>{menus.map((menu) => <button className={menu === "Asset" ? "active" : ""} key={menu}>{menu}<span>›</span></button>)}</nav>
        <div className={`connection ${health}`}><i />{health === "ok" ? "백엔드 연결됨" : health === "error" ? "연결 오류" : "연결 확인 중"}</div>
      </aside>
      <main className="content">
        <header className="topbar">
          <div><p className="breadcrumb">Asset / Endpoint</p><h1>Endpoint</h1></div>
          <div className="status-pill">실시간 캐시 조회</div>
        </header>
        <section className="summary-grid">
          <article><span>조회 결과</span><strong>{total.toLocaleString()}</strong><small>검색 조건에 일치하는 엔드포인트</small></article>
          <article><span>데이터 소스</span><strong className={sourceExists ? "good" : "warn"}>{sourceExists ? "정상" : "없음"}</strong><small>cache/endpoints.json</small></article>
          <article><span>표시 중</span><strong>{items.length}</strong><small>페이지당 최대 50개</small></article>
        </section>
        <section className="panel">
          <div className="panel-head">
            <div><h2>Endpoint 목록</h2><p>Hostname, 사용자, 부서, IP 기준으로 검색할 수 있습니다.</p></div>
            <div className="search-box">
              <select value={field} onChange={(event) => { setField(event.target.value); setPage(1); }}>
                {searchFields.map(([value, label]) => <option value={value} key={value}>{label}</option>)}
              </select>
              <input value={query} onChange={(event) => { setQuery(event.target.value); setPage(1); }} placeholder="검색어 입력..." />
            </div>
          </div>
          {error && <div className="error-banner">조회 오류: {error}</div>}
          {!sourceExists && !error && <div className="empty-banner">아직 Endpoint 캐시가 없습니다. 기존 앱에서 Endpoint 새로고침을 한 번 실행해주세요.</div>}
          <div className="table-wrap">
            <table>
              <thead><tr><th>{header("Hostname", "hostname")}</th><th>{header("User ID", "userId")}</th><th>{header("User", "user")}</th><th>{header("Dept", "dept")}</th><th>{header("IP", "ip")}</th><th>{header("Last Seen (KST)", "lastSeen")}</th></tr></thead>
              <tbody>
                {loading ? <tr><td colSpan={6} className="state-cell">데이터를 불러오는 중입니다...</td></tr> :
                  items.length === 0 ? <tr><td colSpan={6} className="state-cell">표시할 Endpoint가 없습니다.</td></tr> :
                    items.map((item, index) => <tr key={`${item.hostname}-${index}`}><td className="hostname">{item.hostname}</td><td>{item.userId}</td><td>{item.user}</td><td><span className="dept">{item.dept}</span></td><td>{item.ip}</td><td>{item.lastSeen}</td></tr>)}
              </tbody>
            </table>
          </div>
          <footer className="pagination"><span>총 {total.toLocaleString()}개</span><div><button disabled={page <= 1} onClick={() => setPage(page - 1)}>이전</button><b>{page} / {totalPages}</b><button disabled={page >= totalPages} onClick={() => setPage(page + 1)}>다음</button></div></footer>
        </section>
      </main>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(<React.StrictMode><App /></React.StrictMode>);
