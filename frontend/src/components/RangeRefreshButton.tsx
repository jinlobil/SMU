import { useEffect, useRef, useState } from "react";

type Job = { id: string; status: "queued" | "running" | "completed" | "failed"; message: string; error?: { message: string } };

export function RangeRefreshButton({ target, start, end, onComplete }: { target: "detections" | "inbound"; start: string; end: string; onComplete: () => void }) {
  const mounted = useRef(true); const [job, setJob] = useState<Job | null>(null); const [error, setError] = useState("");
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const startJob = async () => { setError(""); try {
    let response = await fetch(`/api/jobs/refresh/${target}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ start, end }) }); let payload = await response.json(); if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`); setJob(payload.data);
    while (mounted.current) { await new Promise((resolve) => setTimeout(resolve, 1000)); response = await fetch(`/api/jobs/${payload.data.id}`); payload = await response.json(); if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`); if (!mounted.current) return; setJob(payload.data); if (payload.data.status === "completed") { onComplete(); return; } if (payload.data.status === "failed") throw new Error(payload.data.error?.message || "작업 실패"); }
  } catch (reason) { setError(String(reason)); setJob(null); } };
  const running = job?.status === "queued" || job?.status === "running";
  return <div className="refresh-area"><button className="refresh-button" disabled={running} onClick={startJob}>{running ? "기간 수집 중..." : "Sophos 기간 새로고침"}</button>{running && <span>{job?.message}</span>}{job?.status === "completed" && <span className="refresh-success">완료</span>}{error && <span className="refresh-error" title={error}>오류 발생 · 로그 확인</span>}</div>;
}
