import { Fragment, useEffect, useState } from "react";
import { useOutletContext, useSearchParams } from "react-router-dom";
import AlertsTable from "../components/AlertsTable";
import { Card, ErrorBanner, RiskBar, SeverityBadge } from "../components/ui";
import { usePolling } from "../hooks/usePolling";
import { api } from "../services/api";
import { fmtNumber, fmtTime } from "../services/format";

// Correlated incidents: alerts grouped by source IP + alert type + 60 s window.
export default function IncidentsPage() {
  const { range, live } = useOutletContext();
  const [params] = useSearchParams();
  const [open, setOpen] = useState(params.get("focus"));
  const [detail, setDetail] = useState(null);
  const [detailError, setDetailError] = useState(null);
  const incidents = usePolling(() => api.incidents(range), [range], { enabled: live });

  useEffect(() => {
    if (!open) { setDetail(null); return; }
    api.incident(open).then(setDetail).catch(setDetailError);
  }, [open]);

  const rows = incidents.data?.items || [];
  const alertTotal = rows.reduce((n, r) => n + r.alert_count, 0);

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Incidents</h1>
          <p className="muted">Alerts are grouped by source IP + alert type within a 60-second window.
            {rows.length > 0 && ` Showing the ${fmtNumber(rows.length)} most recent of ${fmtNumber(incidents.data.total)} incidents;
            these ${fmtNumber(rows.length)} incidents contain ${fmtNumber(alertTotal)} alerts
            (${Math.round((1 - rows.length / alertTotal) * 100)}% fewer items to triage).`}</p>
        </div>
      </div>
      <ErrorBanner error={incidents.error || detailError} />
      <Card>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr><th>Incident</th><th>Source IP</th><th>Alert type</th><th>Alerts</th><th>Open</th>
                <th>First seen</th><th>Last seen</th><th>Max severity</th><th>Max risk</th></tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <Fragment key={r.incident_id}>
                  <tr className={`clickable ${open === r.incident_id ? "selected" : ""}`} tabIndex={0}
                    onClick={() => setOpen(open === r.incident_id ? null : r.incident_id)}
                    onKeyDown={(e) => e.key === "Enter" && setOpen(open === r.incident_id ? null : r.incident_id)}>
                    <td className="mono">{open === r.incident_id ? "▾" : "▸"} {r.incident_id}</td>
                    <td className="mono">{r.source_ip}</td>
                    <td>{r.alert_type}</td>
                    <td>{r.alert_count}</td>
                    <td>{r.open_alerts}</td>
                    <td className="mono nowrap">{fmtTime(r.first_seen, true)}</td>
                    <td className="mono nowrap">{fmtTime(r.last_seen, true)}</td>
                    <td><SeverityBadge severity={r.max_severity} /></td>
                    <td><RiskBar score={r.max_risk_score} /></td>
                  </tr>
                  {open === r.incident_id && (
                    <tr className="expand"><td colSpan={9}>
                      {detail && detail.incident_id === r.incident_id
                        ? <AlertsTable alerts={detail.alerts} compact /> : <span className="muted">Loading…</span>}
                    </td></tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
          {rows.length === 0 && <div className="chart-empty" style={{ height: 120 }}>No incidents in this range</div>}
        </div>
      </Card>
    </div>
  );
}
