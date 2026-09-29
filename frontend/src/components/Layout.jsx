import { NavLink, Outlet } from "react-router-dom";
import { RANGES } from "../theme";

const NAV = [
  ["/", "Dashboard", "▦"],
  ["/traffic", "Traffic Analytics", "∿"],
  ["/alerts", "Alert Queue", "⚑"],
  ["/incidents", "Incidents", "⧉"],
  ["/rules", "Detection Rules", "⚙"],
];

export default function Layout({ user, range, setRange, live, setLive, onLogout }) {
  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <svg viewBox="0 0 32 32" width="26" height="26" aria-hidden="true">
            <path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7z" fill="#3987e5" />
            <path d="M10 16h3l2-4 3 8 2-4h2" stroke="#fff" strokeWidth="2" fill="none" strokeLinecap="round" />
          </svg>
          <div>
            <div className="brand-name">Network IDS</div>
            <div className="brand-sub">SOC Console · Simulation</div>
          </div>
        </div>
        <nav>
          {NAV.map(([to, label, icon]) => (
            <NavLink key={to} to={to} end={to === "/"} className={({ isActive }) => (isActive ? "active" : "")}>
              <span className="nav-icon" aria-hidden="true">{icon}</span>{label}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-foot">
          Synthetic data only.<br />Defensive education project.
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <div className="topbar-left">
            <label className="range">
              <span>Time range</span>
              <select value={range} onChange={(e) => setRange(e.target.value)}>
                {RANGES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
              </select>
            </label>
            <button type="button" className={`live-toggle ${live ? "on" : ""}`} onClick={() => setLive(!live)}
              aria-pressed={live} title="Auto-refresh every 5 seconds (polling)">
              <span className="dot" /> {live ? "Live · 5s" : "Paused"}
            </button>
          </div>
          <div className="topbar-right">
            <span className="user-chip">{user.name} · <strong>{user.role}</strong></span>
            <button type="button" className="btn btn-ghost" onClick={onLogout}>Sign out</button>
          </div>
        </header>
        <main className="content">
          <Outlet context={{ range, live, user }} />
        </main>
      </div>
    </div>
  );
}
