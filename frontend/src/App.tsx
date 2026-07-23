import { useEffect, useState } from "react";
import { EndpointPage } from "./pages/EndpointPage";
import { OrganizationPage } from "./pages/OrganizationPage";
import { DetectionPage } from "./pages/DetectionPage";
import { EmailSecurityPage } from "./pages/EmailSecurityPage";
import { TransferPage } from "./pages/TransferPage";
import { TimelinePage } from "./pages/TimelinePage";
import { SensitivePage } from "./pages/SensitivePage";
import { DashboardPage } from "./pages/DashboardPage";
import { FirewallPage } from "./pages/FirewallPage";


type View = "dashboard" | "endpoint" | "organization" | "detectionEndpoint" | "emailXdr" | "inbound" | "outbound" | "dlp" | "timeline" | "sensitiveFiles" | "sensitiveSites" | "firewall" | "pending";
const menus = ["Dashboard", "Detection", "Forensics", "Response", "Asset", "Lab", "Config"];

export function App() {
  const [health, setHealth] = useState<"loading" | "ok" | "error">("loading");
  const [activeMenu, setActiveMenu] = useState("Asset");
  const [view, setView] = useState<View>("endpoint");

  useEffect(() => {
    fetch("/api/health").then((response) => {
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      setHealth("ok");
    }).catch(() => setHealth("error"));
  }, []);

  const selectMenu = (menu: string) => {
    setActiveMenu(menu);
    if (menu === "Dashboard") setView("dashboard");
    else if (menu === "Asset") setView("endpoint");
    else if (menu === "Detection") setView("detectionEndpoint");
    else if (menu === "Forensics") setView("timeline");
    else if (menu === "Response") setView("firewall");
    else setView("pending");
  };

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand"><span>SMU</span><strong>Monitoring</strong></div>
        <nav>{menus.map((menu) => <div key={menu}>
          <button className={menu === activeMenu ? "active" : ""} onClick={() => selectMenu(menu)}>{menu}<span>›</span></button>
          {menu === "Asset" && activeMenu === "Asset" && <div className="subnav">
            <button className={view === "endpoint" ? "selected" : ""} onClick={() => setView("endpoint")}>Endpoint</button>
            <button className={view === "organization" ? "selected" : ""} onClick={() => setView("organization")}>Organization</button>
          </div>}
          {menu === "Detection" && activeMenu === "Detection" && <div className="subnav">
            <button className={view === "detectionEndpoint" ? "selected" : ""} onClick={() => setView("detectionEndpoint")}>Detection - XDR</button>
            <button className={view === "emailXdr" ? "selected" : ""} onClick={() => setView("emailXdr")}>Email - XDR</button>
            <button className={view === "inbound" ? "selected" : ""} onClick={() => setView("inbound")}>Inbound Mail</button>
            <button className={view === "outbound" ? "selected" : ""} onClick={() => setView("outbound")}>Outbound Mail</button>
            <button className={view === "dlp" ? "selected" : ""} onClick={() => setView("dlp")}>File</button>
          </div>}
          {menu === "Forensics" && activeMenu === "Forensics" && <div className="subnav">
            <button className={view === "timeline" ? "selected" : ""} onClick={() => setView("timeline")}>Timeline</button>
            <button className={view === "sensitiveFiles" ? "selected" : ""} onClick={() => setView("sensitiveFiles")}>Sensitive Files</button><button className={view === "sensitiveSites" ? "selected" : ""} onClick={() => setView("sensitiveSites")}>Sensitive Sites</button>
          </div>}
          {menu === "Response" && activeMenu === "Response" && <div className="subnav">
            <button className={view === "firewall" ? "selected" : ""} onClick={() => setView("firewall")}>Firewall</button>
            <button onClick={() => setView("pending")}>Easy Query</button>
          </div>}
        </div>)}</nav>
        <div className={`connection ${health}`}><i />{health === "ok" ? "백엔드 연결됨" : health === "error" ? "연결 오류" : "연결 확인 중"}</div>
      </aside>
      <main className="content">
        {view === "dashboard" && <DashboardPage />}
        {view === "endpoint" && <EndpointPage />}
        {view === "organization" && <OrganizationPage />}
        {view === "detectionEndpoint" && <DetectionPage />}
        {view === "emailXdr" && <EmailSecurityPage kind="xdr" />}
        {view === "inbound" && <EmailSecurityPage kind="inbound" />}
        {view === "outbound" && <TransferPage kind="outbound" />}
        {view === "dlp" && <TransferPage kind="dlp" />}
        {view === "timeline" && <TimelinePage />}
        {view === "sensitiveFiles" && <SensitivePage kind="files" />}
        {view === "sensitiveSites" && <SensitivePage kind="sites" />}
        {view === "firewall" && <FirewallPage />}
        {view === "pending" && <section className="pending-page"><span>마이그레이션 진행 예정</span><h1>{activeMenu}</h1><p>이 화면은 아직 이전 중입니다. 현재 Dashboard, Asset, Detection, Forensics 그룹을 사용할 수 있습니다.</p></section>}
      </main>
    </div>
  );
}
