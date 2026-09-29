// Small presentational components shared by the pages.
import { SEVERITY_COLORS, CLASS_COLORS } from "../theme";
import { titleCase } from "../services/format";

const SEVERITY_ICONS = { INFO: "i", LOW: "▾", MEDIUM: "■", HIGH: "▲", CRITICAL: "◆" };

// Severity is never shown by colour alone: icon + text label always accompany it.
export function SeverityBadge({ severity }) {
  const color = SEVERITY_COLORS[severity] || "#8a8983";
  return (
    <span className="badge" style={{ color, borderColor: color }}>
      <span aria-hidden="true">{SEVERITY_ICONS[severity] || "•"}</span> {severity}
    </span>
  );
}

export function StatusBadge({ status }) {
  return <span className={`status status-${String(status).toLowerCase()}`}>{titleCase(status)}</span>;
}

export function ClassBadge({ value }) {
  const color = CLASS_COLORS[value] || "#8a8983";
  return <span className="badge" style={{ color, borderColor: color }}>{titleCase(value)}</span>;
}

export function RiskBar({ score }) {
  const color = score > 80 ? SEVERITY_COLORS.CRITICAL : score > 60 ? SEVERITY_COLORS.HIGH
    : score > 40 ? SEVERITY_COLORS.MEDIUM : score > 20 ? SEVERITY_COLORS.LOW : SEVERITY_COLORS.INFO;
  return (
    <span className="riskbar" title={`Risk ${score}/100`}>
      <span className="riskbar-track"><span style={{ width: `${Math.min(100, score)}%`, background: color }} /></span>
      <span className="riskbar-num">{Math.round(score)}</span>
    </span>
  );
}

export function StatCard({ label, value, sub, tone }) {
  return (
    <div className={`stat-card ${tone ? `tone-${tone}` : ""}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  );
}

export function Card({ title, subtitle, children, actions, className = "" }) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <header className="card-head">
          <div>
            {title && <h3>{title}</h3>}
            {subtitle && <p className="card-sub">{subtitle}</p>}
          </div>
          {actions}
        </header>
      )}
      {children}
    </section>
  );
}

export function ErrorBanner({ error }) {
  if (!error) return null;
  return <div className="banner banner-error" role="alert">⚠ {error.message || String(error)}</div>;
}

export function Loading() {
  return <div className="loading">Loading…</div>;
}
