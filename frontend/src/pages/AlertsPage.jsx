import { useState } from "react";
import { useOutletContext, useSearchParams } from "react-router-dom";
import AlertFilters from "../components/AlertFilters";
import AlertsTable from "../components/AlertsTable";
import { Card, ErrorBanner } from "../components/ui";
import { usePolling } from "../hooks/usePolling";
import { api } from "../services/api";
import { fmtNumber } from "../services/format";

const PAGE = 25;

export default function AlertsPage() {
  const { range, live } = useOutletContext();
  const [params] = useSearchParams();
  const [filters, setFilters] = useState(() => ({
    source_ip: params.get("source_ip") || undefined,
    status: params.get("status") || undefined,
    offset: 0,
  }));
  const alerts = usePolling(() => api.alerts({ ...filters, range, limit: PAGE }),
    [range, JSON.stringify(filters)], { enabled: live });
  const types = usePolling(() => api.alertAnalytics(range), [range], { enabled: false });

  const total = alerts.data?.total ?? 0;
  const offset = filters.offset || 0;

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Alert Queue</h1>
          <p className="muted">Tier-1 triage: work newest / highest severity first. {fmtNumber(total)} alerts match.</p>
        </div>
      </div>
      <Card>
        <AlertFilters filters={filters} onChange={setFilters}
          alertTypes={(types.data?.by_type || []).map((x) => x.alert_type)} />
        <ErrorBanner error={alerts.error} />
        <AlertsTable alerts={alerts.data?.items} />
        <div className="pager">
          <button type="button" className="btn btn-ghost" disabled={offset === 0}
            onClick={() => setFilters({ ...filters, offset: Math.max(0, offset - PAGE) })}>← Newer</button>
          <span className="muted">{total ? `${offset + 1}–${Math.min(offset + PAGE, total)} of ${fmtNumber(total)}` : ""}</span>
          <button type="button" className="btn btn-ghost" disabled={offset + PAGE >= total}
            onClick={() => setFilters({ ...filters, offset: offset + PAGE })}>Older →</button>
        </div>
      </Card>
    </div>
  );
}
