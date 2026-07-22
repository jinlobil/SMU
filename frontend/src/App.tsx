import { useEffect, useState } from "react";
import { EndpointPage } from "./pages/EndpointPage";
import { OrganizationPage } from "./pages/OrganizationPage";


type View = "endpoint" | "organization" | "pending";
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
    if (menu !== "Asset") setView("pending");
    else if (view === "pending") setView("endpoint");
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
        </div>)}</nav>
        <div className={`connection ${health}`}><i />{health === "ok" ? "백엔드 연결됨" : health === "error" ? "연결 오류" : "연결 확인 중"}</div>
      </aside>
      <main className="content">
        {view === "endpoint" && <EndpointPage />}
        {view === "organization" && <OrganizationPage />}
        {view === "pending" && <section className="pending-page"><span>마이그레이션 진행 예정</span><h1>{activeMenu}</h1><p>이 메뉴는 아직 기존 PyQt 기능을 웹으로 옮기는 중입니다. 현재 Asset의 Endpoint와 Organization을 사용할 수 있습니다.</p></section>}
      </main>
    </div>
  );
}
