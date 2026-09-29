import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Card, ErrorBanner, Loading, RiskBar, SeverityBadge, StatusBadge } from "../components/ui";
import { usePolling } from "../hooks/usePolling";
import { api } from "../services/api";
import { fmtBytes, fmtNumber, fmtTime, titleCase } from "../services/format";

const STATUS_LABELS = {
  INVESTIGATING: "Start investigation",
  RESOLVED: "Resolve",
  FALSE_POSITIVE: "Mark false positive",
};

function Field({ label, children, mono }) {
  return (
    <div className="field">
      <div className="field-label">{label}</div>
      <div className={`field-value ${mono ? "mono" : ""}`}>{children}</div>
    </div>
  );
}

function ScoreRow({ label, value, weight }) {
  return (
    <div className="score-row">
      <span>{label}</span>
      {value === null || value === undefined ? <span className="muted">disabled</span> : <RiskBar score={value} />}
      <span className="muted">{weight}</span>
    </div>
  );
}

export default function AlertDetailPage() {
  const { alertId } = useParams();
  const { data: alert, error, loading, refresh } = usePolling(() => api.alert(alertId), [alertId],
    { enabled: false });
  const [note, setNote] = useState("");
  const [closing, setClosing] = useState(null);     // RESOLVED | FALSE_POSITIVE awaiting a note
  const [resolution, setResolution] = useState("");
  const [actionError, setActionError] = useState(null);
  const [busy, setBusy] = useState(false);

  if (loading && !alert) return <Loading />;
  if (error && !alert) return <div className="page"><ErrorBanner error={error} /><Link to="/alerts">← Back to queue</Link></div>;

  const run = async (fn) => {
    setBusy(true);
    setActionError(null);
    try {
      await fn();
      await refresh();
    } catch (err) {
      setActionError(err);
    } finally {
      setBusy(false);
    }
  };

  const changeStatus = (status) => {
    if (status === "RESOLVED" || status === "FALSE_POSITIVE") {
      setClosing(status);
      return;
    }
    run(() => api.updateStatus(alert.alert_id, status));
  };

  const downloadReport = () => run(async () => {
    const text = await api.report(alert.alert_id);
    const url = URL.createObjectURL(new Blob([text], { type: "text/markdown" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `incident_report_${alert.alert_id}.md`;
    a.click();
    URL.revokeObjectURL(url);
  });

  const f = alert.flow;
  const feats = alert.features;
  const anomaly = alert.anomaly_details;

  return (
    <div className="page">
      <Link to="/alerts" className="back">← Alert queue</Link>
      <div className="page-head detail-head">
        <div>
          <h1 className="mono">{alert.alert_id}</h1>
          <p className="detail-title">{alert.alert_type} <span className="muted">({alert.rule_id})</span></p>
          <div className="chips">
            <SeverityBadge severity={alert.severity} />
            <StatusBadge status={alert.status} />
            <span className="muted">Risk <strong className="big-risk">{alert.risk_score}</strong>/100</span>
          </div>
        </div>
        <div className="actions">
          {alert.allowed_transitions.map((s) => (
            <button key={s} type="button" disabled={busy}
              className={`btn ${s === "INVESTIGATING" ? "btn-primary" : s === "RESOLVED" ? "btn-good" : "btn-ghost"}`}
              onClick={() => changeStatus(s)}>{STATUS_LABELS[s] || titleCase(s)}</button>
          ))}
          <button type="button" className="btn btn-ghost" onClick={downloadReport} disabled={busy}>
            Download report</button>
        </div>
      </div>

      <ErrorBanner error={actionError} />
      {closing && (
        <Card title={closing === "RESOLVED" ? "Resolve alert" : "Mark as false positive"}
          subtitle="A resolution note is required so every closure is documented.">
          <textarea value={resolution} onChange={(e) => setResolution(e.target.value)} rows={3} maxLength={2000}
            placeholder={closing === "RESOLVED" ? "What was found and what action was taken?"
              : "Why is this benign? (e.g. approved backup job, change ticket #...)"} />
          <div className="row-actions">
            <button type="button" className="btn btn-primary" disabled={busy || resolution.trim().length < 5}
              onClick={() => run(async () => {
                await api.updateStatus(alert.alert_id, closing, resolution.trim());
                setClosing(null);
                setResolution("");
              })}>Confirm</button>
            <button type="button" className="btn btn-ghost" onClick={() => setClosing(null)}>Cancel</button>
          </div>
        </Card>
      )}

      <div className="grid-3">
        <Card title="Overview">
          <div className="fields">
            <Field label="Event time" mono>{fmtTime(alert.created_at, true)}</Field>
            <Field label="Detected at" mono>{fmtTime(alert.detected_at, true)}</Field>
            <Field label="Source" mono>{alert.source_ip}:{alert.source_port}</Field>
            <Field label="Destination" mono>{alert.destination_ip}:{alert.destination_port}</Field>
            <Field label="Protocol">{alert.protocol}</Field>
            <Field label="Incident">{alert.incident
              ? <Link to={`/incidents?focus=${alert.incident.incident_id}`}>{alert.incident.incident_id} · {alert.incident.alert_count} alerts</Link>
              : "—"}</Field>
            <Field label="Assigned to">{alert.assigned_to || "unassigned"}</Field>
            <Field label="Flow ID" mono>{alert.flow_id}</Field>
          </div>
        </Card>
        <Card title="Traffic statistics">
          <div className="fields">
            <Field label="Packets">{fmtNumber(f.packet_count)}</Field>
            <Field label="Bytes">{fmtBytes(f.byte_count)}</Field>
            <Field label="Duration">{f.duration} s</Field>
            <Field label="Bytes / s">{fmtBytes(feats.bytes_per_second)}</Field>
            <Field label="Connections">{fmtNumber(f.connection_count)} ({fmtNumber(feats.connection_rate, 1)}/s)</Field>
            <Field label="Failed">{fmtNumber(f.failed_connection_count)} ({(feats.failure_ratio * 100).toFixed(0)}%)</Field>
            <Field label="SYN / RST">{fmtNumber(f.syn_count)} / {fmtNumber(f.rst_count)} (SYN ratio {feats.syn_ratio})</Field>
            <Field label="Unique dst ports (60 s)">{feats.unique_destination_ports}</Field>
          </div>
        </Card>
        <Card title="Hybrid risk breakdown" subtitle={alert.ml_score === null ? "Weights: rules 60% · anomaly 40%" : "Weights: rules 40% · anomaly 30% · ML 30%"}>
          <ScoreRow label="Signature" value={alert.signature_score} />
          <ScoreRow label="Anomaly" value={alert.anomaly_score} />
          <ScoreRow label="ML" value={alert.ml_score} />
          <div className="score-final">Final risk <RiskBar score={alert.risk_score} /></div>
          <p className="fine">Thresholds are project assumptions and must be calibrated in a real SOC.</p>
        </Card>
      </div>

      <div className="grid-2">
        <Card title="Why this alert fired">
          <p className="reason">{alert.reason}</p>
          <p className="muted">{alert.description}</p>
          {alert.matched_rules.length > 0 && (
            <table className="table small">
              <thead><tr><th>Rule</th><th>Severity</th><th>Evidence</th></tr></thead>
              <tbody>
                {alert.matched_rules.map((m) => (
                  <tr key={m.rule_id}><td className="nowrap">{m.rule_id} {m.name}</td>
                    <td><SeverityBadge severity={m.severity} /></td><td>{m.evidence}</td></tr>
                ))}
              </tbody>
            </table>
          )}
          {alert.mitre_hint && (
            <p className="mitre"><strong>Candidate ATT&CK mapping (unconfirmed):</strong> {alert.mitre_hint}</p>
          )}
          <p className="fine">A detection means “investigate”, not “proven malicious”.</p>
        </Card>
        <Card title="Anomaly analysis" subtitle={`Anomaly score ${anomaly.score}/100 vs. learned normal baseline`}>
          <table className="table small">
            <thead><tr><th>Metric</th><th>Value</th><th>Z-score</th><th>IQR outlier</th><th>Contribution</th></tr></thead>
            <tbody>
              {Object.entries(anomaly.details).map(([m, d]) => (
                <tr key={m} className={d.metric_score > 0 ? "hl" : ""}>
                  <td>{titleCase(m)}</td><td className="mono">{fmtNumber(d.value, 2)}</td>
                  <td className="mono">{d.z_score}</td><td>{d.iqr_outlier ? "yes" : "no"}</td>
                  <td><RiskBar score={d.metric_score} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      </div>

      <div className="grid-2">
        <Card title="Recommended investigation steps" subtitle="Defensive checks — only on systems you are authorised to access">
          <ol className="steps">{alert.recommended_steps.map((s) => <li key={s}>{s}</li>)}</ol>
        </Card>
        <Card title="Incident timeline">
          <ul className="timeline">
            {alert.timeline.map((t, i) => (
              <li key={i}>
                <span className="mono muted">{fmtTime(t.timestamp, true)}</span>
                <strong>{titleCase(t.action)}</strong> <span className="muted">by {t.actor}</span>
                {t.details && <div className="tl-details">{t.details}</div>}
              </li>
            ))}
          </ul>
        </Card>
      </div>

      <Card title="Analyst notes">
        {alert.notes.length === 0 && <p className="muted">No notes yet.</p>}
        <ul className="notes">
          {alert.notes.map((n) => (
            <li key={n.note_id} className={n.note_type === "RESOLUTION" ? "resolution" : ""}>
              <div className="note-meta"><strong>{n.analyst}</strong> · {fmtTime(n.created_at, true)}
                {n.note_type === "RESOLUTION" && <span className="tag">resolution</span>}</div>
              <div className="note-body">{n.note}</div>
            </li>
          ))}
        </ul>
        <form className="note-form" onSubmit={(e) => {
          e.preventDefault();
          run(async () => { await api.addNote(alert.alert_id, note.trim()); setNote(""); });
        }}>
          <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={2} maxLength={2000}
            placeholder="Add an investigation note (what you checked, what you found)…" />
          <button className="btn btn-primary" type="submit" disabled={busy || !note.trim()}>Add note</button>
        </form>
      </Card>
    </div>
  );
}
