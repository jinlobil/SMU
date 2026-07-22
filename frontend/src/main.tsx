import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

type HealthState = "loading" | "ok" | "error";

function App() {
  const [health, setHealth] = useState<HealthState>("loading");
  const [message, setMessage] = useState("Python 백엔드 연결 확인 중");

  useEffect(() => {
    fetch("/api/health")
      .then(async (response) => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then(() => {
        setHealth("ok");
        setMessage("Python 백엔드 연결 완료");
      })
      .catch((error: unknown) => {
        setHealth("error");
        setMessage(`백엔드 연결 실패: ${String(error)}`);
      });
  }, []);

  return (
    <main className="shell">
      <header>
        <p className="eyebrow">SMU LOCAL WEB</p>
        <h1>Sophos Monitoring</h1>
        <p>기존 기능을 유지하면서 웹 화면으로 이전하는 첫 번째 실행 기반입니다.</p>
      </header>
      <section className={`status ${health}`}>
        <span className="dot" />
        <div>
          <strong>{message}</strong>
          <small>오류는 runtime/logs 디렉터리에 자동 저장됩니다.</small>
        </div>
      </section>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
