import { useEffect, useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import { Loading } from "./components/ui";
import AlertDetailPage from "./pages/AlertDetailPage";
import AlertsPage from "./pages/AlertsPage";
import DashboardPage from "./pages/DashboardPage";
import IncidentsPage from "./pages/IncidentsPage";
import LoginPage from "./pages/LoginPage";
import RulesPage from "./pages/RulesPage";
import TrafficPage from "./pages/TrafficPage";
import { api, getApiKey, setApiKey } from "./services/api";

function readPref(key, fallback) {
  try {
    return localStorage.getItem(key) ?? fallback;
  } catch {
    return fallback;
  }
}

function writePref(key, value) {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* preferences are optional */
  }
}

export default function App() {
  const [user, setUser] = useState(null);
  const [checking, setChecking] = useState(Boolean(getApiKey()));
  const [range, setRangeState] = useState(() => readPref("ids_range", "24h"));
  const [live, setLiveState] = useState(() => readPref("ids_live", "true") === "true");

  const setRange = (v) => { setRangeState(v); writePref("ids_range", v); };
  const setLive = (v) => { setLiveState(v); writePref("ids_live", String(v)); };

  // Restore a session from sessionStorage (validated against the backend).
  useEffect(() => {
    const key = getApiKey();
    if (!key) return;
    api.whoami(key)
      .then(setUser)
      .catch(() => setApiKey(null))
      .finally(() => setChecking(false));
  }, []);

  useEffect(() => {
    const onLogout = () => setUser(null);
    window.addEventListener("ids-logout", onLogout);
    return () => window.removeEventListener("ids-logout", onLogout);
  }, []);

  const logout = () => {
    setApiKey(null);
    setUser(null);
  };

  if (checking) return <Loading />;
  if (!user) return <LoginPage onLogin={setUser} />;
  if (user.role === "sensor") {
    return (
      <LoginPage onLogin={setUser}
        notice="Sensor keys can only submit flows. Sign in with an analyst or admin key." />
    );
  }

  return (
    <Routes>
      <Route element={<Layout user={user} range={range} setRange={setRange} live={live} setLive={setLive}
        onLogout={logout} />}>
        <Route index element={<DashboardPage />} />
        <Route path="traffic" element={<TrafficPage />} />
        <Route path="alerts" element={<AlertsPage />} />
        <Route path="alerts/:alertId" element={<AlertDetailPage />} />
        <Route path="incidents" element={<IncidentsPage />} />
        <Route path="rules" element={<RulesPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
