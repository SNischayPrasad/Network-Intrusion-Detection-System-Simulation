import { SEVERITIES, STATUSES } from "../theme";
import { titleCase } from "../services/format";

// One row of filters above the alert table. Time range is global (top bar).
export default function AlertFilters({ filters, onChange, alertTypes = [] }) {
  const set = (key) => (e) => onChange({ ...filters, [key]: e.target.value || undefined, offset: 0 });
  return (
    <div className="filters" role="group" aria-label="Alert filters">
      <label>Severity
        <select value={filters.severity || ""} onChange={set("severity")}>
          <option value="">All</option>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
          <option value="HIGH,CRITICAL">High + Critical</option>
        </select>
      </label>
      <label>Protocol
        <select value={filters.protocol || ""} onChange={set("protocol")}>
          <option value="">All</option>
          {["TCP", "UDP", "ICMP"].map((p) => <option key={p} value={p}>{p}</option>)}
        </select>
      </label>
      <label>Alert type
        <select value={filters.alert_type || ""} onChange={set("alert_type")}>
          <option value="">All</option>
          {alertTypes.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
      </label>
      <label>Status
        <select value={filters.status || ""} onChange={set("status")}>
          <option value="">All</option>
          <option value="NEW,INVESTIGATING">Open (New + Investigating)</option>
          {STATUSES.map((s) => <option key={s} value={s}>{titleCase(s)}</option>)}
        </select>
      </label>
      <label>Source IP
        <input value={filters.source_ip || ""} onChange={set("source_ip")} placeholder="e.g. 203.0.113.150"
          maxLength={45} spellCheck={false} />
      </label>
    </div>
  );
}
