import { useOutletContext } from "react-router-dom";
import { HBarChart, TimeSeriesChart } from "../components/Charts";
import { Card, ErrorBanner } from "../components/ui";
import { usePolling } from "../hooks/usePolling";
import { api } from "../services/api";
import { fmtBytes, fmtCompact } from "../services/format";
import { SERIES, SEVERITY_COLORS } from "../theme";

// Each chart carries a one-line "why an analyst cares" subtitle.
export default function TrafficPage() {
  const { range, live } = useOutletContext();
  const traffic = usePolling(() => api.traffic(range), [range], { enabled: live });
  const analytics = usePolling(() => api.alertAnalytics(range), [range], { enabled: live });
  const t = traffic.data;
  const a = analytics.data;
  const b = t?.bucket_seconds;
  const bucketLabel = b ? (b >= 3600 ? `${b / 3600} h` : b >= 60 ? `${b / 60} min` : `${b} s`) : "";

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Traffic Analytics</h1>
          <p className="muted">Network behaviour over time · interval = {bucketLabel || "—"}</p>
        </div>
      </div>
      <ErrorBanner error={traffic.error || analytics.error} />
      <div className="grid-2">
        <Card title="Packets per second" subtitle="Sudden spikes can indicate floods or bulk transfers">
          <TimeSeriesChart data={t?.series} bucketSeconds={b}
            series={[{ key: "packets_per_second", name: "Packets/s", color: SERIES[0] }]} />
        </Card>
        <Card title="Bytes per second" subtitle="Volume trend — watch for exfiltration-like surges (and backups)">
          <TimeSeriesChart data={t?.series} bucketSeconds={b} yFormatter={fmtBytes} valueFormatter={fmtBytes}
            series={[{ key: "bytes_per_second", name: "Bytes/s", color: SERIES[0] }]} />
        </Card>
        <Card title="Connections per minute" subtitle="High connection rates are a classic DoS / automation signal">
          <TimeSeriesChart data={t?.series} bucketSeconds={b}
            series={[{ key: "connections_per_minute", name: "Connections/min", color: SERIES[0] }]} />
        </Card>
        <Card title="Failed connections" subtitle="Bursts of failures suggest password guessing or probing">
          <TimeSeriesChart data={t?.series} type="bar" bucketSeconds={b}
            series={[{ key: "failed_connections", name: "Failed connections", color: SERIES[1] }]} />
        </Card>
        <Card title="Flows vs moving average" subtitle="5-interval moving average smooths noise to reveal trend shifts">
          <TimeSeriesChart data={t?.series} bucketSeconds={b}
            series={[{ key: "flows", name: "Flows", color: SERIES[0] },
              { key: "flows_moving_avg", name: "Moving average", color: SERIES[1], dashed: true }]} />
        </Card>
        <Card title="Risk timeline" subtitle="Average vs worst risk per interval (0–100)">
          <TimeSeriesChart data={t?.series} bucketSeconds={b} yFormatter={(v) => v}
            series={[{ key: "max_risk", name: "Max risk", color: SERIES[1] },
              { key: "avg_risk", name: "Average risk", color: SERIES[0] }]} />
        </Card>
        <Card title="Alert timeline" subtitle="Alerts per interval, stacked by severity">
          <TimeSeriesChart data={a?.timeline} type="bar" stacked bucketSeconds={b}
            series={["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((s) => (
              { key: s, name: s, color: SEVERITY_COLORS[s] }))} />
        </Card>
        <Card title="Protocol distribution" subtitle="Unexpected protocol mix can reveal tunnelling or misuse">
          <HBarChart data={t?.protocols} labelKey="protocol" valueKey="count" valueName="Flows"
            color={SERIES[0]} labelWidth={60} />
        </Card>
        <Card title="Destination port distribution" subtitle="Rare or watch-listed ports deserve a closer look"
          className="span-2">
          <HBarChart data={(t?.top_ports || []).map((p) => ({ ...p, label: `${p.port} · ${p.service}` }))}
            labelKey="label" valueKey="count" valueName="Flows" color={SERIES[0]} labelWidth={150} />
          <p className="fine">Total flows in range: {fmtCompact((t?.series || []).reduce((n, s) => n + s.flows, 0))}</p>
        </Card>
      </div>
    </div>
  );
}
