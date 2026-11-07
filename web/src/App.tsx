import { useEffect, useState } from "react";
import { HashRouter, NavLink, Route, Routes } from "react-router-dom";
import { get } from "./api";
import Overview from "./pages/Overview";
import Explorer from "./pages/Explorer";
import CveDetail from "./pages/CveDetail";
import Performance from "./pages/Performance";
import Discoveries from "./pages/Discoveries";
import Workflow from "./pages/Workflow";

const NAV = [
  { to: "/", label: "Overview" },
  { to: "/explorer", label: "Vulnerability Explorer" },
  { to: "/discoveries", label: "Discoveries" },
  { to: "/model", label: "Model Performance" },
  { to: "/workflow", label: "Prioritization Workflow" },
];

function Sidebar() {
  const [status, setStatus] = useState<"checking" | "ok" | "off">("checking");
  const [rows, setRows] = useState<number>(0);

  useEffect(() => {
    get<{ status: string; rows: number; granite: boolean }>("/api/health")
      .then((h) => {
        setStatus(h.status === "ok" ? "ok" : "off");
        setRows(h.rows);
      })
      .catch(() => setStatus("off"));
  }, []);

  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark">B</div>
        <div>
          <div className="brand-name">Before the Breach</div>
          <div className="brand-sub">Predictive Vulnerability Intelligence</div>
        </div>
      </div>

      <nav className="nav">
        {NAV.map((n) => (
          <NavLink key={n.to} to={n.to} end={n.to === "/"}>
            <span className="dot" />
            {n.label}
          </NavLink>
        ))}
      </nav>

      <div className="sidebar-foot">
        <div className="side-card">
          <b>{rows.toLocaleString()}</b> CVEs scored across nine 2026 snapshot months.
          <div style={{ marginTop: 6 }}>
            Model output is a prediction of exploitation likelihood, never a confirmation.
          </div>
        </div>
        <div className={`status ${status === "off" ? "off" : ""}`}>
          <span className="led" />
          {status === "checking" ? "connecting…" : status === "ok" ? "model artefacts loaded" : "artefacts unavailable"}
        </div>
      </div>
    </aside>
  );
}

export default function App() {
  return (
    <HashRouter>
      <div className="app">
        <Sidebar />
        <main className="main">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/explorer" element={<Explorer />} />
            <Route path="/cve/:cveId" element={<CveDetail />} />
            <Route path="/discoveries" element={<Discoveries />} />
            <Route path="/model" element={<Performance />} />
            <Route path="/workflow" element={<Workflow />} />
            <Route path="*" element={<Overview />} />
          </Routes>
        </main>
      </div>
    </HashRouter>
  );
}
