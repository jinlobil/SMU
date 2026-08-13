import { useEffect, useRef, useState, type CSSProperties } from "react";
import { Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
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
import { ExportManagementPage } from "./pages/ExportManagementPage";
import { UIManagementPage } from "./pages/UIManagementPage";
import { applyTheme } from "./theme";


type DetectionFilter = { field: string; query: string; start?: string; end?: string };
const particles = Array.from({ length: 36 }, (_, index) => index);

const menuRoutes = [
  { label: "Dashboard", route: "/dashboard" },
  { label: "Detection", route: "/detections/xdr" },
  { label: "Forensics", route: "/forensics/timeline" },
  { label: "Response", route: "/response/firewall" },
  { label: "Asset", route: "/assets/endpoints" },
  { label: "Lab", route: "/lab/layout" },
  { label: "Config", route: "/config/general" },
];
const submenus: Record<string, { label: string; route: string }[]> = {
  Asset: [{ label: "Endpoint", route: "/assets/endpoints" }, { label: "Organization", route: "/assets/organization" }],
  Detection: [
    { label: "Detection - XDR", route: "/detections/xdr" }, { label: "Email - XDR", route: "/detections/email-xdr" },
    { label: "Inbound Mail", route: "/detections/inbound" }, { label: "Outbound Mail", route: "/detections/outbound" },
    { label: "File", route: "/detections/dlp" },
  ],
  Forensics: [
    { label: "Timeline", route: "/forensics/timeline" }, { label: "Sensitive Files", route: "/forensics/sensitive-files" },
    { label: "Sensitive Sites", route: "/forensics/sensitive-sites" },
  ],
  Response: [{ label: "Firewall", route: "/response/firewall" }, { label: "Easy Query", route: "/response/easy-query" }],
  Lab: [{ label: "Layout - User", route: "/lab/layout" }],
  Config: [
    { label: "General", route: "/config/general" }, { label: "UI Management", route: "/config/ui" }, { label: "Data Management", route: "/config/data" },
    { label: "Export Management", route: "/config/export" }, { label: "Integration Management", route: "/config/integrations" },
    { label: "Exception Management", route: "/config/exceptions" }, { label: "Content Management", route: "/config/content" },
    { label: "System Management", route: "/config/system" },
  ],
};

function menuForPath(pathname: string) {
  if (pathname.startsWith("/detections/")) return "Detection";
  if (pathname.startsWith("/forensics/")) return "Forensics";
  if (pathname.startsWith("/response/")) return "Response";
  if (pathname.startsWith("/assets/")) return "Asset";
  if (pathname.startsWith("/lab/")) return "Lab";
  if (pathname.startsWith("/config/")) return "Config";
  return "Dashboard";
}

export function App() {
  const [health, setHealth] = useState<"loading" | "ok" | "error">("loading");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const sidebarCloseTimer = useRef<number | null>(null);
  const location = useLocation();
  const navigate = useNavigate();
  const activeMenu = menuForPath(location.pathname);

  const openSidebar = () => {
    if (sidebarCloseTimer.current !== null) window.clearTimeout(sidebarCloseTimer.current);
    sidebarCloseTimer.current = null;
    setSidebarOpen(true);
  };
  const scheduleSidebarClose = () => {
    if (sidebarCloseTimer.current !== null) window.clearTimeout(sidebarCloseTimer.current);
    sidebarCloseTimer.current = window.setTimeout(() => setSidebarOpen(false), 110);
  };

  useEffect(() => {
    fetch("/api/config/theme").then((response) => response.json()).then((payload) => {
      applyTheme(payload.data || {});
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

  const openDetection = (filter: DetectionFilter) => {
    const query = new URLSearchParams({ field: filter.field, q: filter.query });
    if (filter.start) query.set("from", filter.start);
    if (filter.end) query.set("to", filter.end);
    navigate(`/detections/xdr?${query}`);
  };

  return (
    <div className="app">
      <div className="cyber-atmosphere" aria-hidden="true"><div className="cyber-grid"/>{particles.map((particle) => <i key={particle} style={{ "--px": `${(particle * 47) % 100}%`, "--py": `${(particle * 29) % 100}%`, "--delay": `${-(particle % 13)}s`, "--duration": `${10 + particle % 9}s` } as CSSProperties}/>)}</div>
      <div className={`sidebar-title-trigger ${sidebarOpen ? "disabled" : ""}`} aria-hidden="true" onMouseEnter={openSidebar}/>
      <aside className={`sidebar ${sidebarOpen ? "open" : ""}`} onMouseEnter={openSidebar} onMouseLeave={scheduleSidebarClose}>
        <div className="brand"><span>SMU</span><strong>Monitoring</strong></div>
        <nav>{menuRoutes.map((menu) => <div key={menu.label}>
          <button className={menu.label === activeMenu ? "active" : ""} onClick={() => navigate(menu.route)}>{menu.label}<span>›</span></button>
          {menu.label === activeMenu && submenus[menu.label] && <div className="subnav">
            {submenus[menu.label].map((item) => <button key={item.route} className={location.pathname === item.route ? "selected" : ""} onClick={() => navigate(item.route)}>{item.label}</button>)}
          </div>}
        </div>)}</nav>
        <div className={`connection ${health}`}><span className="connection-orb"/><svg className="connection-heartbeat" viewBox="0 0 92 22" aria-hidden="true"><polyline points="0,11 15,11 21,4 27,18 34,7 40,11 55,11 61,5 67,17 73,11 92,11"/></svg><b>{health === "ok" ? "백엔드 연결됨" : health === "error" ? "연결 오류" : "연결 확인 중"}</b></div>
      </aside>
      <main className="content"><div key={location.pathname} className="page-stage">
        <Routes>
          <Route path="/dashboard" element={<DashboardPage onOpenDetection={openDetection} />} />
          <Route path="/assets/endpoints" element={<EndpointPage />} />
          <Route path="/assets/organization" element={<OrganizationPage />} />
          <Route path="/detections/xdr" element={<DetectionPage />} />
          <Route path="/detections/email-xdr" element={<EmailSecurityPage kind="xdr" />} />
          <Route path="/detections/inbound" element={<EmailSecurityPage kind="inbound" />} />
          <Route path="/detections/outbound" element={<TransferPage kind="outbound" />} />
          <Route path="/detections/dlp" element={<TransferPage kind="dlp" />} />
          <Route path="/forensics/timeline" element={<TimelinePage />} />
          <Route path="/forensics/sensitive-files" element={<SensitivePage kind="files" />} />
          <Route path="/forensics/sensitive-sites" element={<SensitivePage kind="sites" />} />
          <Route path="/response/firewall" element={<FirewallPage />} />
          <Route path="/response/easy-query" element={<EasyQueryPage />} />
          <Route path="/lab/layout" element={<LayoutPage />} />
          <Route path="/config/general" element={<ConfigPage section="general" />} />
          <Route path="/config/ui" element={<UIManagementPage />} />
          <Route path="/config/data" element={<ConfigPage section="data" />} />
          <Route path="/config/export" element={<ExportManagementPage />} />
          <Route path="/config/integrations" element={<IntegrationManagementPage />} />
          <Route path="/config/exceptions" element={<ExceptionManagementPage />} />
          <Route path="/config/content" element={<ContentManagementPage />} />
          <Route path="/config/system" element={<SystemInfoPage />} />
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </div></main>
    </div>
  );
}
