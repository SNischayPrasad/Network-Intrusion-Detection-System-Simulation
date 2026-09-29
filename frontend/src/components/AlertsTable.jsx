import { useNavigate } from "react-router-dom";
import { fmtTime } from "../services/format";
import { RiskBar, SeverityBadge, StatusBadge } from "./ui";

// SOC alert queue table. Rows are keyboard-accessible links to the investigation page.
// All values are rendered as text by React (auto-escaped) — no raw HTML injection.
export default function AlertsTable({ alerts, compact = false }) {
  const navigate = useNavigate();
  if (!alerts || alerts.length === 0) {
    return <div className="chart-empty" style={{ height: 120 }}>No alerts match these filters</div>;
  }
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>Time</th>
            {!compact && <th>Alert ID</th>}
            <th>Source IP</th>
            <th>Destination IP</th>
            <th>Protocol</th>
            <th>Alert</th>
            <th>Severity</th>
            <th>Risk</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((a) => (
            <tr key={a.alert_id} tabIndex={0} className="clickable"
              onClick={() => navigate(`/alerts/${a.alert_id}`)}
              onKeyDown={(e) => e.key === "Enter" && navigate(`/alerts/${a.alert_id}`)}>
              <td className="mono nowrap">{fmtTime(a.created_at, true)}</td>
              {!compact && <td className="mono">{a.alert_id}</td>}
              <td className="mono">{a.source_ip}</td>
              <td className="mono">{a.destination_ip}:{a.destination_port}</td>
              <td>{a.protocol}</td>
              <td>{a.alert_type}</td>
              <td><SeverityBadge severity={a.severity} /></td>
              <td><RiskBar score={a.risk_score} /></td>
              <td><StatusBadge status={a.status} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
