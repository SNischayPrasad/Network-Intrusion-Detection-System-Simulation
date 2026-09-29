import { useState } from "react";
import { api, setApiKey } from "../services/api";

// Analyst sign-in with an API key (validated by the backend's /api/auth/whoami).
export default function LoginPage({ onLogin, notice }) {
  const [key, setKey] = useState("");
  const [error, setError] = useState(notice || "");
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const user = await api.whoami(key.trim());
      setApiKey(key.trim());
      onLogin(user);
    } catch (err) {
      setError(err.status === 401 ? "Invalid API key." : `Cannot reach backend: ${err.message}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login">
      <form className="login-card" onSubmit={submit}>
        <svg viewBox="0 0 32 32" width="40" height="40" aria-hidden="true">
          <path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7z" fill="#3987e5" />
          <path d="M10 16h3l2-4 3 8 2-4h2" stroke="#fff" strokeWidth="2" fill="none" strokeLinecap="round" />
        </svg>
        <h1>Network IDS · SOC Console</h1>
        <p className="muted">Analyst sign-in. Use the analyst or admin API key from your <code>.env</code> file.</p>
        <label htmlFor="apikey">API key</label>
        <input id="apikey" type="password" value={key} onChange={(e) => setKey(e.target.value)}
          autoComplete="off" required maxLength={200} autoFocus />
        {error && <div className="banner banner-error" role="alert">{error}</div>}
        <button className="btn btn-primary" type="submit" disabled={busy || !key.trim()}>
          {busy ? "Verifying…" : "Sign in"}
        </button>
        <p className="fine">Synthetic data only · for defensive cybersecurity education.</p>
      </form>
    </div>
  );
}
