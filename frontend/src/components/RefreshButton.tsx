import { useEffect, useRef, useState } from "react";


type Job = { id: string; status: "queued" | "running" | "completed" | "failed"; message: string; error?: { message: string } };

export function RefreshButton({ target, onComplete }: { target: "endpoints" | "organizations"; onComplete: () => void }) {
  const [job, setJob] = useState<Job | null>(null);
  const [error, setError] = useState("");
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);

  const poll = async (jobId: string) => {
    while (mounted.current) {
      await new Promise((resolve) => window.setTimeout(resolve, 1000));
      const response = await fetch(`/api/jobs/${jobId}`);
      const payload = await response.json();
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      const current = payload.data as Job;
      if (!mounted.current) return;
      setJob(current);
      if (current.status === "completed") { onComplete(); return; }
      if (current.status === "failed") throw new Error(current.error?.message || "새로고침 작업 실패");
    }
  };

  const start = async () => {
    setError("");
    try {
      const response = await fetch(`/api/jobs/refresh/${target}`, { method: "POST" });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
      setJob(payload.data as Job);
      await poll(payload.data.id);
    } catch (reason) {
      setError(String(reason));
      setJob(null);
    }
  };

  const running = job?.status === "queued" || job?.status === "running";
  return <div className="refresh-area">
    <button className="refresh-button" disabled={running} onClick={start}>{running ? "새로고침 중..." : "Sophos 새로고침"}</button>
    {running && <span>{job?.message}</span>}
    {job?.status === "completed" && <span className="refresh-success">완료</span>}
    {error && <span className="refresh-error" title={error}>오류 발생 · 로그 확인</span>}
  </div>;
}
