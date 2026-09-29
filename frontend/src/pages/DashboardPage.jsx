import { useState } from "react";
import { useNavigate, useOutletContext } from "react-router-dom";
import AlertFilters from "../components/AlertFilters";
import AlertsTable from "../components/AlertsTable";
import { ColumnChart, HBarChart, TimeSeriesChart } from "../components/Charts";
import { Card, ErrorBanner, StatCard } from "../components/ui";
import { usePolling } from "../hooks/usePolling";
import { api } from "../services/api";
import { fmtNumber, fmtTime, titleCase } from "../services/format";
import { CLASS_COLORS, SERIES, SEVERITY_COLORS } from "../theme";

export default function DashboardPage() {
  const { range, live } = useOutletContext();
  const navigate = useNavigate();
  const [filters, setFilters] = useState({});
  const opts = { enabled: live };

  const stats = usePolling(() => api.stats(range), [range], opts);
  const traffic = usePolling(() => api.traffic(range), [range], opts);
  const analytics = usePolling(() => api.alertAnalytics(range), [range], opts);
  const recent = usePolling(() => api.alerts({ ...filters, range, limit: 12 }),
    [range, JSON.stringify(filters)], opts);

  const s = stats.data;
  const t = traffic.data;
  const a = analytics.data;
  const pct = (n) => (s && s.total_flows ? `${((n / s.total_flows) * 100).toFixed(1)}% of flows` : "");

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Security Overview</h1>
          <p className="muted">Hybrid detection: signature rules + statistical anomaly
            {s?.ml_enabled ? " + machine learning" : " (ML disabled)"}.
            {stats.lastUpdated && ` Updated ${fmtTime(stats.lastUpdated.toISOString())}.`}</p>
        </div>
      </div>
      <ErrorBanner error={stats.error || traffic.error || analytics.error} />

      <div className="stat-grid">
        <StatCard label="Total network flows" value={fmtNumber(s?.total_flows)}
          sub={s?.last_flow_at ? `last ${fmtTime(s.last_flow_at)}` : ""} />
        <StatCard label="Normal traffic" value={fmtNumber(s?.normal_flows)} sub={pct(s?.normal_flows)} tone="good" />
        <StatCard label="Suspicious traffic" value={fmtNumber(s?.suspicious_flows)}
          sub={s ? `${fmtNumber(s.potential_intrusions)} potential intrusions` : ""} tone="warn" />
        <StatCard label="Open alerts" value={fmtNumber(s?.open_alerts)}
          sub={s ? `${fmtNumber(s.new_alerts)} new · ${fmtNumber(s.incidents)} incidents` : ""} tone="serious" />
        <StatCard label="Critical alerts" value={fmtNumber(s?.critical_alerts)}
          sub={s ? `${fmtNumber(s.critical_open_alerts)} still open` : ""} tone="critical" />
        <StatCard label="Average risk score" value={s ? `${s.average_risk_score}` : "—"} sub="0–100, all flows" />
      </div>

      <div className="grid-2">
        <Card title="Traffic over time" subtitle="Flows per interval, split by classification">
          <TimeSeriesChart data={t?.series} type="area" stacked bucketSeconds={t?.bucket_seconds}
            series={[{ key: "normal", name: "Normal", color: SERIES[0] },
              { key: "suspicious", name: "Suspicious", color: SERIES[1] }]} />
        </Card>
        <Card title="Normal vs suspicious" subtitle="Final classification of every flow">
          <HBarChart data={(t?.classification || []).map((c) => ({ ...c, label: titleCase(c.name) }))}
            labelKey="label" valueKey="count" valueName="Flows" height={240} labelWidth={130}
            colorFor={(r) => CLASS_COLORS[r.name]} />
        </Card>
        <Card title="Alerts by severity" subtitle="Severity derives from the final risk score">
          <ColumnChart data={a?.by_severity} labelKey="severity" valueKey="count" valueName="Alerts"
            colorFor={(r) => SEVERITY_COLORS[r.severity]} />
        </Card>
        <Card title="Top alert types" subtitle="Primary rule or detector per alert">
          <HBarChart data={a?.by_type} labelKey="alert_type" valueKey="count" valueName="Alerts"
            color={SERIES[0]} labelWidth={190}
            onBarClick={(d) => setFilters({ ...filters, alert_type: d.alert_type })} />
        </Card>
        <Card title="Protocol distribution">
          <HBarChart data={t?.protocols} labelKey="protocol" valueKey="count" valueName="Flows"
            color={SERIES[0]} labelWidth={60} />
        </Card>
        <Card title="Destination port distribution" subtitle="Top 10 destination ports">
          <HBarChart data={(t?.top_ports || []).map((p) => ({ ...p, label: `${p.port} ${p.service}` }))}
            labelKey="label" valueKey="count" valueName="Flows" color={SERIES[0]} labelWidth={130} />
        </Card>
        <Card title="Top source IPs by alerts" subtitle="Click a bar to open that source's alerts">
          <HBarChart data={a?.top_sources} labelKey="source_ip" valueKey="count" valueName="Alerts"
            color={SERIES[1]} labelWidth={120}
            onBarClick={(d) => navigate(`/alerts?source_ip=${encodeURIComponent(d.source_ip)}`)} />
        </Card>
        <Card title="Risk score distribution" subtitle="Flows per 10-point risk bucket">
          <ColumnChart data={a?.risk_distribution} labelKey="range" valueKey="count" valueName="Flows"
            color={SERIES[0]} />
        </Card>
      </div>

      <Card title="Recent alerts" subtitle="Click a row to investigate"
        actions={<button className="btn btn-ghost" type="button" onClick={() => navigate("/alerts")}>
          Open full queue →</button>}>
        <AlertFilters filters={filters} onChange={setFilters}
          alertTypes={(a?.by_type || []).map((x) => x.alert_type)} />
        <ErrorBanner error={recent.error} />
        <AlertsTable alerts={recent.data?.items} compact />
      </Card>
    </div>
  );
}
