import { useEffect, useRef, useState } from "react";

type Column = { key: string; label: string; default: boolean };
type ExportSpec = { label: string; columns: Column[] };
type ReportSection = { key: string; label: string; default: boolean };
type Schema = { exports: Record<string, ExportSpec>; report: { label: string; sections: ReportSection[] } };
type Tab = "detections" | "xdr" | "inbound" | "outbound" | "dlp" | "report";

const exportJobKey = "smu.export.activeJob";
const tabOrder: Tab[] = ["detections", "xdr", "inbound", "outbound", "dlp", "report"];
const tabLabels: Record<Tab, string> = { detections: "Detection XLSX", xdr: "Email XDR XLSX", inbound: "Inbound Mail XLSX", outbound: "Outbound Mail XLSX", dlp: "DLP File XLSX", report: "Security Report PDF" };
const fallbackSchema: Schema = { exports: {}, report: { label: "Security Report PDF", sections: [] } };
const previewValues: Record<string, string> = {
  time: "2026-08-06 09:42:18", hostname: "PC-001", dept: "보안팀", username: "홍길동", privateIp: "10.10.1.25", publicIp: "203.0.113.25", file: "sample.exe", sha256: "a91f…e204", rule: "WIN-DETECTION-RULE", lineage: "System → sample.exe", _sourceFile: "2026-08-06.json",
  mailbox: "hong@example.com", userId: "hong", user: "홍길동", from: "sender@example.net", to: "hong@example.com", subject: "보안 알림 예시", senderIp: "198.51.100.17", ioc: "sample.example", iocSha256: "b72c…91af", detail: "탐지 상세 예시",
  received: "2026-08-06 09:42:18", cc: "security@example.com", reason: "Malware", date: "2026-08-06 09:42:18", mailProcess: "발송", sendResult: "성공", senderEmail: "hong@example.com", senderName: "홍길동", receiver: "user@example.net", size: "128 KB", policy: "외부메일 정책", attachment: "sample.pdf",
  event: "탐지됨", computer: "PC-001", sourceIp: "10.10.1.25", source: "Web Upload", destination: "Chrome", destinationType: "Web Browser", destinationDetail: "example.com", fileSize: "128 KB", fileHash: "c31d…80e2",
};
const today = () => new Date().toISOString().slice(0, 10);
const week = () => new Date(Date.now() - 6 * 86400000).toISOString().slice(0, 10);

export function ExportManagementPage() {
  const generation = useRef(0);
  const [schema, setSchema] = useState<Schema>(fallbackSchema);
  const [active, setActive] = useState<Tab>("detections");
  const [start, setStart] = useState(week());
  const [end, setEnd] = useState(today());
  const [selectedColumns, setSelectedColumns] = useState<Record<string, string[]>>({});
  const [selectedSections, setSelectedSections] = useState<string[]>([]);
  const [running, setRunning] = useState(false);
  const [message, setMessage] = useState("");
  const [progress, setProgress] = useState<{ type: string; message: string } | null>(null);
  const rangeInvalid = !start || !end || start > end;

  const defaultsFor = (kind: string, nextSchema = schema) => (nextSchema.exports[kind]?.columns || []).filter((column) => column.default).map((column) => column.key);
  const defaultSections = (nextSchema = schema) => nextSchema.report.sections.filter((section) => section.default).map((section) => section.key);
  const loadSchema = async () => {
    const response = await fetch("/api/config/export/schema"), payload = await response.json();
    if (!response.ok) throw new Error(payload?.error?.message || "Export schema 조회 실패");
    const next = payload.data as Schema;
    setSchema(next);
    setSelectedColumns(Object.fromEntries(Object.keys(next.exports).map((kind) => [kind, defaultsFor(kind, next)])));
    setSelectedSections(defaultSections(next));
  };
  const downloadFile = async (url: string, label: string) => {
    setProgress({ type: "DOWNLOAD", message: `${label} 다운로드 준비 중...` });
    const response = await fetch(url);
    if (!response.ok) { const payload = await response.json().catch(() => null); throw new Error(payload?.error?.message || `${label} 다운로드 실패`); }
    const blob = await response.blob(), disposition = response.headers.get("Content-Disposition") || "", match = disposition.match(/filename\*?=(?:UTF-8''|\")?([^";]+)/i), filename = decodeURIComponent((match?.[1] || label).replaceAll('"', ""));
    const anchor = document.createElement("a"), objectUrl = URL.createObjectURL(blob);
    anchor.href = objectUrl; anchor.download = filename; document.body.appendChild(anchor); anchor.click(); anchor.remove(); URL.revokeObjectURL(objectUrl);
    setProgress({ type: "COMPLETED", message: `${label} 다운로드 완료` });
    window.setTimeout(() => setProgress(null), 3000);
  };
  const followJob = async (id: string, type: string, currentGeneration: number) => {
    for (;;) {
      if (currentGeneration !== generation.current) return;
      const response = await fetch(`/api/jobs/${id}`), payload = await response.json();
      if (!response.ok) throw new Error(payload?.error?.message || "작업 상태 조회 실패");
      const current = payload.data;
      setProgress({ type, message: current.message });
      if (current.status === "completed") {
        localStorage.removeItem(exportJobKey);
        setRunning(false);
        setMessage("작업 완료");
        return current.result;
      }
      if (current.status === "failed") {
        localStorage.removeItem(exportJobKey);
        throw new Error(current.error?.message || "작업 실패");
      }
      await new Promise((resolve) => setTimeout(resolve, 800));
    }
  };
  const requestJob = async (url: string, body: unknown, type: string) => {
    const currentGeneration = ++generation.current;
    setRunning(true); setProgress({ type, message: "작업 요청 중" }); setMessage("");
    try {
      const response = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }), payload = await response.json();
      if (!response.ok) throw new Error(payload?.error?.message || "작업 요청 실패");
      localStorage.setItem(exportJobKey, JSON.stringify({ id: payload.data.id, type }));
      return await followJob(payload.data.id, type, currentGeneration);
    } catch (error) {
      setMessage(String(error)); setProgress(null); throw error;
    } finally {
      if (currentGeneration === generation.current) setRunning(false);
    }
  };
  const runExport = async () => {
    if (rangeInvalid || active === "report") return;
    const label = schema.exports[active]?.label || active;
    const result = await requestJob("/api/jobs/export", { kind: active, start, end, columns: selectedColumns[active] || [] }, "EXPORT");
    await downloadFile(`/api/config/export/file/${encodeURIComponent(result.filename)}`, label);
  };
  const runReport = async () => {
    if (rangeInvalid) return;
    const result = await requestJob("/api/jobs/report", { start, end, sections: selectedSections }, "REPORT");
    await downloadFile(`/api/config/report/${encodeURIComponent(result.filename)}`, schema.report.label);
  };
  const toggleColumn = (kind: string, key: string) => setSelectedColumns((current) => ({ ...current, [kind]: (current[kind] || []).includes(key) ? current[kind].filter((item) => item !== key) : [...(current[kind] || []), key] }));
  const toggleSection = (key: string) => setSelectedSections((current) => current.includes(key) ? current.filter((item) => item !== key) : [...current, key]);

  useEffect(() => { loadSchema().catch((error) => setMessage(String(error))); }, []);
  useEffect(() => { let saved: { id?: string; type?: string } | null = null; try { saved = JSON.parse(localStorage.getItem(exportJobKey) || "null"); } catch { localStorage.removeItem(exportJobKey); } if (saved?.id) { const currentGeneration = ++generation.current; setRunning(true); void followJob(saved.id, saved.type || "EXPORT", currentGeneration).catch((error) => { setMessage(String(error)); setProgress(null); setRunning(false); }); } return () => { generation.current += 1; }; }, []);

  const exportSpec = active !== "report" ? schema.exports[active] : null;
  const selectedCount = active === "report" ? selectedSections.length : (selectedColumns[active] || []).length;
  const previewColumns = exportSpec?.columns.filter((column) => (selectedColumns[active] || []).includes(column.key)) || [];
  const previewSections = schema.report.sections.filter((section) => selectedSections.includes(section.key));
  return <><header className="topbar"><div><p className="breadcrumb">System / Export Management</p><h1>Export Management</h1></div><span>{message}</span></header>{progress && <div className="global-job-progress scheduler-progress indexing"><b>{progress.type}</b><span>{progress.message}</span><i/></div>}<section className="export-management config-card"><div className="export-tabs">{tabOrder.map((tab) => <button key={tab} className={active === tab ? "active" : ""} onClick={() => setActive(tab)}>{tab === "report" ? schema.report.label || tabLabels.report : schema.exports[tab]?.label || tabLabels[tab]}</button>)}</div><div className="export-workspace"><aside><h2>{active === "report" ? schema.report.label : exportSpec?.label}</h2><div className="config-range"><input type="date" value={start} onChange={(event) => setStart(event.target.value)} /><b>~</b><input type="date" value={end} onChange={(event) => setEnd(event.target.value)} /></div><p><b>선택 항목</b><span>{selectedCount.toLocaleString()}개</span></p><button disabled={running || rangeInvalid || selectedCount === 0} className="primary-action" onClick={active === "report" ? runReport : runExport}>{running ? "작업 중..." : active === "report" ? "Security Report PDF 생성" : "선택 항목 XLSX 생성"}</button><button disabled={running} onClick={() => active === "report" ? setSelectedSections(defaultSections()) : setSelectedColumns((current) => ({ ...current, [active]: defaultsFor(active) }))}>기본값으로 복원</button><button disabled={running} onClick={() => active === "report" ? setSelectedSections(schema.report.sections.map((section) => section.key)) : setSelectedColumns((current) => ({ ...current, [active]: exportSpec?.columns.map((column) => column.key) || [] }))}>전체 선택</button><small>{rangeInvalid ? "조회 기간을 확인하세요." : "선택한 항목만 파일에 포함됩니다. 별도 저장은 필요하지 않습니다."}</small></aside><div className="export-content"><div className="export-fields">{active === "report" ? schema.report.sections.map((section) => <label key={section.key}><input type="checkbox" checked={selectedSections.includes(section.key)} onChange={() => toggleSection(section.key)} /><span>{section.label}</span><small>PDF 보고서 섹션</small></label>) : exportSpec?.columns.map((column) => <label key={column.key}><input type="checkbox" checked={(selectedColumns[active] || []).includes(column.key)} onChange={() => toggleColumn(active, column.key)} /><span>{column.label}</span><small>{column.key}</small></label>)}</div><div className="export-preview"><header><div><b>실시간 출력 미리보기</b><small>체크 상태가 실제 파일의 항목과 순서에 바로 반영됩니다.</small></div><span>{selectedCount}개 항목</span></header>{selectedCount === 0 ? <p className="export-preview-empty">출력할 항목을 하나 이상 선택하세요.</p> : active === "report" ? <div className="report-preview">{previewSections.map((section, index) => <article key={section.key}><small>SECTION {index + 1}</small><b>{section.label}</b><span>요약 및 분석 차트</span></article>)}</div> : <div className="export-preview-table"><table><thead><tr>{previewColumns.map((column) => <th key={column.key}>{column.label}</th>)}</tr></thead><tbody><tr>{previewColumns.map((column) => <td key={column.key}>{previewValues[column.key] || `${column.label} 예시`}</td>)}</tr></tbody></table></div>}</div></div></div></section></>;
}
