import { useEffect, useMemo, useState } from "react";

type Session = { session_id: string; created_at: string; query_mode: string; query_type: string; endpoint_name: string; program_name: string; result_count: number; display_columns: string[]; rows: Record<string, unknown>[] };
type QueryVariable = { name: string; description?: string; required?: boolean };
type HistoryQuery = { id: string; name: string; variables: QueryVariable[] };

export function EasyQueryPage() {
  const [mode, setMode] = useState("Live"), [type, setType] = useState("Process"), [endpoint, setEndpoint] = useState(""), [keyword, setKeyword] = useState("");
  const [queries, setQueries] = useState<HistoryQuery[]>([]), [queryId, setQueryId] = useState(""), [variableValues, setVariableValues] = useState<Record<string, string>>({});
  const [start, setStart] = useState(new Date(Date.now() - 6 * 86400000).toISOString()), [end, setEnd] = useState(new Date().toISOString());
  const [sessions, setSessions] = useState<Session[]>([]), [detail, setDetail] = useState<Session | null>(null), [running, setRunning] = useState(false), [message, setMessage] = useState(""), [error, setError] = useState("");
  const selectedQuery = useMemo(() => queries.find(query => query.id === queryId), [queries, queryId]);
  const reload = () => Promise.all([fetch("/api/easy-query/configuration").then(response => response.json()), fetch("/api/easy-query/sessions").then(response => response.json())]).then(([configuration, saved]) => { setQueries(configuration.data.historyQueries); setSessions(saved.data.sessions); }).catch(reason => setError(String(reason)));
  useEffect(() => { void reload(); }, []);

  const run = async () => {
    setRunning(true); setError("");
    try {
      const variables = Object.fromEntries(Object.entries(variableValues).filter(([, value]) => value.trim()));
      const response = await fetch("/api/jobs/easy-query", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ mode, queryType: type, endpoint, keyword, queryId, variables, start, end }) });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload?.error?.message);
      for (;;) {
        await new Promise(resolve => setTimeout(resolve, 1000));
        const job = await fetch(`/api/jobs/${payload.data.id}`).then(result => result.json()); setMessage(job.data.message);
        if (job.data.status === "completed") { await reload(); break; }
        if (job.data.status === "failed") throw new Error(job.data.error?.message);
      }
    } catch (reason) { setError(String(reason)); } finally { setRunning(false); }
  };
  const remove = async (id: string) => { await fetch(`/api/easy-query/sessions/${id}`, { method: "DELETE" }); await reload(); };
  const submitDisabled = running || (mode === "Live" ? !endpoint : !queryId || Boolean(selectedQuery?.variables?.some(variable => variable.required && !variableValues[variable.name]?.trim())));

  return <><header className="topbar"><div><p className="breadcrumb">Response / Easy Query</p><h1>Easy Query</h1></div><span className="status-pill installed">Sophos Live Discover / XDR Query</span></header>
    <section className="panel easy-query"><div className={`easy-form ${mode.toLowerCase()}`}>
      <select className="easy-mode" value={mode} onChange={event => setMode(event.target.value)}><option>Live</option><option>History</option></select>
      {mode === "Live" ? <><select className="easy-live-type" value={type} onChange={event => setType(event.target.value)}>{["Process", "Service", "Scheduled Task", "Installed Program", "Network Connection", "File Search"].map(value => <option key={value}>{value}</option>)}</select><input className="easy-live-endpoint" value={endpoint} onChange={event => setEndpoint(event.target.value)} placeholder="Endpoint Name"/><input className="easy-live-keyword" value={keyword} onChange={event => setKeyword(event.target.value)} placeholder="Keyword / File path"/></> : <>
        <select className="easy-history-query" value={queryId} onChange={event => { setQueryId(event.target.value); setVariableValues({}); }}><option value="">이력 쿼리 선택</option>{queries.map(query => <option value={query.id} key={query.id}>{query.name}</option>)}</select>
        <input className="easy-history-endpoint" value={endpoint} onChange={event => setEndpoint(event.target.value)} placeholder="Endpoint Name / ID (선택)"/>
        <div className="easy-history-dates"><label><span>시작 날짜</span><input type="date" value={start.slice(0, 10)} onChange={event => setStart(`${event.target.value}T00:00:00.000Z`)}/></label><label><span>종료 날짜</span><input type="date" value={end.slice(0, 10)} onChange={event => setEnd(`${event.target.value}T23:59:59.000Z`)}/></label></div>
        <div className="easy-history-variables">{selectedQuery?.variables?.length ? selectedQuery.variables.map(variable => <label key={variable.name}><span>{variable.description || variable.name}{variable.required ? " *" : ""}</span><input value={variableValues[variable.name] || ""} onChange={event => setVariableValues(current => ({ ...current, [variable.name]: event.target.value }))} placeholder={variable.name}/></label>) : <small>{queryId ? "이 쿼리는 별도 변수가 필요하지 않습니다." : "쿼리를 선택하면 필요한 변수가 표시됩니다."}</small>}</div>
      </>}
      <button className="easy-submit" disabled={submitDisabled} onClick={run}>{running ? message || "조회 중" : "조회"}</button>
    </div>{error && <div className="error-banner">{error}</div>}<div className="table-wrap"><table><thead><tr>{["Created At", "Mode", "Type", "Endpoint", "Keyword", "Count", "Action"].map(value => <th key={value}>{value}</th>)}</tr></thead><tbody>{sessions.length === 0 ? <tr><td colSpan={7} className="state-cell">저장된 Query 세션이 없습니다.</td></tr> : sessions.map(session => <tr key={session.session_id} onDoubleClick={() => setDetail(session)}><td>{session.created_at}</td><td>{session.query_mode}</td><td>{session.query_type}</td><td>{session.endpoint_name}</td><td>{session.program_name}</td><td>{session.result_count}</td><td><button onClick={() => remove(session.session_id)}>삭제</button></td></tr>)}</tbody></table></div></section>
    {detail && <div className="modal-backdrop" onMouseDown={() => setDetail(null)}><section className="detail-modal query-detail" onMouseDown={event => event.stopPropagation()}><header><h2>{detail.query_type} · {detail.endpoint_name}</h2><button onClick={() => setDetail(null)}>×</button></header><div className="table-wrap"><table><thead><tr>{detail.display_columns.map(column => <th key={column}>{column}</th>)}</tr></thead><tbody>{detail.rows.map((row, index) => <tr key={index}>{detail.display_columns.map(column => <td key={column}>{String(row[column] ?? "")}</td>)}</tr>)}</tbody></table></div></section></div>}
  </>;
}
