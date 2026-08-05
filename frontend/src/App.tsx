import { useEffect, useRef, useState, type CSSProperties } from "react";
import { EndpointPage } from "./pages/EndpointPage";
import { OrganizationPage } from "./pages/OrganizationPage";
import { DetectionPage } from "./pages/DetectionPage";
import { EmailSecurityPage } from "./pages/EmailSecurityPage";
import { TransferPage } from "./pages/TransferPage";
import { TimelinePage } from "./pages/TimelinePage";
import { SensitivePage } from "./pages/SensitivePage";
import { DashboardPage } from "./pages/DashboardPage";
import { FirewallPage } from "./pages/FirewallPage";
import { EasyQueryPage } from "./pages/EasyQueryPage";
import { LayoutPage } from "./pages/LayoutPage";
import { ConfigPage } from "./pages/ConfigPage";
import { SystemInfoPage } from "./pages/SystemInfoPage";
import { IntegrationManagementPage } from "./pages/IntegrationManagementPage";
import { ExceptionManagementPage } from "./pages/ExceptionManagementPage";
import { ContentManagementPage } from "./pages/ContentManagementPage";


type View = "dashboard" | "endpoint" | "organization" | "detectionEndpoint" | "emailXdr" | "inbound" | "outbound" | "dlp" | "timeline" | "sensitiveFiles" | "sensitiveSites" | "firewall" | "easyQuery" | "layout" | "config" | "dataManagement" | "integrationManagement" | "exceptionManagement" | "contentManagement" | "systemInfo";
type DetectionFilter = { field: string; query: string; start?: string; end?: string };
const menus = ["Dashboard", "Detection", "Forensics", "Response", "Asset", "Lab", "Config"];
const particles = Array.from({ length: 36 }, (_, index) => index);

export function App() {
  const [health, setHealth] = useState<"loading" | "ok" | "error">("loading");
  const [activeMenu, setActiveMenu] = useState("Dashboard");
  const [view, setView] = useState<View>("dashboard");
  const [detectionFilter, setDetectionFilter] = useState<DetectionFilter | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const sidebarCloseTimer = useRef<number | null>(null);

  const openSidebar = () => {
    if (sidebarCloseTimer.current !== null) window.clearTimeout(sidebarCloseTimer.current);
    sidebarCloseTimer.current = null;
    setSidebarOpen(true);
  };
  const scheduleSidebarClose = () => {
    if (sidebarCloseTimer.current !== null) window.clearTimeout(sidebarCloseTimer.current);
    sidebarCloseTimer.current = window.setTimeout(() => setSidebarOpen(false), 300);
  };

  useEffect(() => {
    fetch("/api/config/theme").then((response) => response.json()).then((payload) => {
      const theme = payload.data || {};
      const root = document.documentElement;
      root.style.setProperty("--accent", theme.Primary_Blue);
      root.style.setProperty("--accent-dark", theme.Primary_Blue_Dark);
      root.style.setProperty("--app-bg", theme.UI_Background);
      root.style.setProperty("--surface", theme.UI_Surface);
      root.style.setProperty("--card-border", theme.Card_Border);
      root.style.setProperty("--card-title", theme.Card_Title_Text);
      root.style.setProperty("--table-head-bg", theme.Table_Header_Background);
      root.style.setProperty("--table-head-text", theme.Table_Header_Text);
      root.style.setProperty("--table-selection-bg", theme.Table_Selection_Background);
      root.style.setProperty("--table-selection-text", theme.Table_Selection_Text);
      root.style.setProperty("--trend-detection", theme.Threat_trend_Detection);
      root.style.setProperty("--trend-xdr", theme.Threat_trend_Detection_XDR);
      root.style.setProperty("--trend-email", theme.Threat_trend_Email);
      root.style.setProperty("--trend-outbound", theme.Threat_trend_Outbound_Mail);
      root.style.setProperty("--trend-file", theme.Threat_trend_File);
      window.dispatchEvent(new CustomEvent("smu-theme", { detail: theme }));
    }).catch(() => undefined);
    fetch("/api/health").then((response) => {
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      setHealth("ok");
    }).catch(() => setHealth("error"));
  }, []);
  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === "Escape") setSidebarOpen(false); };
    window.addEventListener("keydown", closeOnEscape);
    return () => {
      window.removeEventListener("keydown", closeOnEscape);
      if (sidebarCloseTimer.current !== null) window.clearTimeout(sidebarCloseTimer.current);
    };
  }, []);

  const selectMenu = (menu: string) => {
    setActiveMenu(menu);
    if (menu === "Dashboard") setView("dashboard");
    else if (menu === "Asset") setView("endpoint");
    else if (menu === "Detection") { setDetectionFilter(null); setView("detectionEndpoint"); }
    else if (menu === "Forensics") setView("timeline");
    else if (menu === "Response") setView("firewall");
    else if (menu === "Lab") setView("layout");
    else setView("config");
  };
  const openDetection = (filter: DetectionFilter) => {
    setDetectionFilter(filter);
    setActiveMenu("Detection");
    setView("detectionEndpoint");
  };

  return (
    <div className="app">
      <div className="cyber-atmosphere" aria-hidden="true"><div className="cyber-grid"/>{particles.map((particle) => <i key={particle} style={{ "--px": `${(particle * 47) % 100}%`, "--py": `${(particle * 29) % 100}%`, "--delay": `${-(particle % 13)}s`, "--duration": `${10 + particle % 9}s` } as CSSProperties}/>)}</div>
      <div className="sidebar-title-trigger" aria-hidden="true" onMouseEnter={openSidebar}/>
      <aside className={`sidebar ${sidebarOpen ? "open" : ""}`} onMouseEnter={openSidebar} onMouseLeave={scheduleSidebarClose}>
        <div className="brand"><span>SMU</span><strong>Monitoring</strong></div>
        <nav>{menus.map((menu) => <div key={menu}>
          <button className={menu === activeMenu ? "active" : ""} onClick={() => selectMenu(menu)}>{menu}<span>›</span></button>
          {menu === "Asset" && activeMenu === "Asset" && <div className="subnav">
            <button className={view === "endpoint" ? "selected" : ""} onClick={() => setView("endpoint")}>Endpoint</button>
            <button className={view === "organization" ? "selected" : ""} onClick={() => setView("organization")}>Organization</button>
          </div>}
          {menu === "Detection" && activeMenu === "Detection" && <div className="subnav">
            <button className={view === "detectionEndpoint" ? "selected" : ""} onClick={() => { setDetectionFilter(null); setView("detectionEndpoint"); }}>Detection - XDR</button>
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
            <button className={view === "easyQuery" ? "selected" : ""} onClick={() => setView("easyQuery")}>Easy Query</button>
          </div>}
          {menu === "Lab" && activeMenu === "Lab" && <div className="subnav"><button className={view === "layout" ? "selected" : ""} onClick={() => setView("layout")}>Layout - User</button></div>}
          {menu === "Config" && activeMenu === "Config" && <div className="subnav">
            <a href="#config-general" className={view === "config" ? "selected" : ""} onClick={(event) => { event.preventDefault(); setView("config"); }}>General</a>
            <a href="#config-data-management" className={view === "dataManagement" ? "selected" : ""} onClick={(event) => { event.preventDefault(); setView("dataManagement"); }}>Data Management</a>
            <a href="#config-integration-management" className={view === "integrationManagement" ? "selected" : ""} onClick={(event) => { event.preventDefault(); setView("integrationManagement"); }}>Integration Management</a>
            <a href="#config-exception-management" className={view === "exceptionManagement" ? "selected" : ""} onClick={(event) => { event.preventDefault(); setView("exceptionManagement"); }}>Exception Management</a>
            <a href="#config-content-management" className={view === "contentManagement" ? "selected" : ""} onClick={(event) => { event.preventDefault(); setView("contentManagement"); }}>Content Management</a>
            <a href="#config-system-management" className={view === "systemInfo" ? "selected" : ""} onClick={(event) => { event.preventDefault(); setView("systemInfo"); }}>System Management</a>
          </div>}
        </div>)}</nav>
        <div className={`connection ${health}`}><span className="connection-orb"/><svg className="connection-heartbeat" viewBox="0 0 92 22" aria-hidden="true"><polyline points="0,11 15,11 21,4 27,18 34,7 40,11 55,11 61,5 67,17 73,11 92,11"/></svg><b>{health === "ok" ? "백엔드 연결됨" : health === "error" ? "연결 오류" : "연결 확인 중"}</b></div>
      </aside>
      <main className="content"><div key={view} className={`page-stage page-${view}`}>
        {view === "dashboard" && <DashboardPage onOpenDetection={openDetection} />}
        {view === "endpoint" && <EndpointPage />}
        {view === "organization" && <OrganizationPage />}
        {view === "detectionEndpoint" && <DetectionPage initialFilter={detectionFilter} />}
        {view === "emailXdr" && <EmailSecurityPage kind="xdr" />}
        {view === "inbound" && <EmailSecurityPage kind="inbound" />}
        {view === "outbound" && <TransferPage kind="outbound" />}
        {view === "dlp" && <TransferPage kind="dlp" />}
        {view === "timeline" && <TimelinePage />}
        {view === "sensitiveFiles" && <SensitivePage kind="files" />}
        {view === "sensitiveSites" && <SensitivePage kind="sites" />}
        {view === "firewall" && <FirewallPage />}
        {view === "easyQuery" && <EasyQueryPage />}
        {view === "layout" && <LayoutPage />}
        {view === "config" && <ConfigPage section="general" />}
        {view === "dataManagement" && <ConfigPage section="data" />}
        {view === "integrationManagement" && <IntegrationManagementPage />}
        {view === "exceptionManagement" && <ExceptionManagementPage />}
        {view === "contentManagement" && <ContentManagementPage />}
        {view === "systemInfo" && <SystemInfoPage />}
      </div></main>
    </div>
  );
}
