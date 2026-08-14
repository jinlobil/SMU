import React from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { App } from "./App";
import "./styles.css";


function reportClientError(payload: Record<string, unknown>) {
  const body = JSON.stringify(payload);
  if (navigator.sendBeacon) navigator.sendBeacon("/api/client-errors", new Blob([body], { type: "application/json" }));
  else fetch("/api/client-errors", { method: "POST", headers: { "Content-Type": "application/json" }, body, keepalive: true });
}

window.addEventListener("error", (event) => reportClientError({
  message: event.message, source: event.filename, line: event.lineno, column: event.colno, stack: event.error?.stack,
}));
window.addEventListener("unhandledrejection", (event) => {
  if (event.reason instanceof DOMException && event.reason.name === "AbortError") { event.preventDefault(); return; }
  reportClientError({ message: String(event.reason), stack: event.reason?.stack });
});

createRoot(document.getElementById("root")!).render(<React.StrictMode><BrowserRouter><App /></BrowserRouter></React.StrictMode>);
