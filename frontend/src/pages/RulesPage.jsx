import { useEffect, useState } from "react";
import { useOutletContext } from "react-router-dom";
import { Card, ErrorBanner, SeverityBadge } from "../components/ui";
import { api } from "../services/api";
import { SEVERITIES } from "../theme";
import { fmtTime, titleCase } from "../services/format";

// Detection-as-code view: analysts can read rules, admins can tune thresholds.
function RuleRow({ rule, canEdit, onSaved }) {
  const [draft, setDraft] = useState(() => ({ ...rule, thresholdText: {} }));
  const [error, setError] = useState(null);
  const [saved, setSaved] = useState(false);
  useEffect(() => setDraft({ ...rule, thresholdText: {} }), [rule]);

  const value = (k) => draft.thresholdText[k] ?? (Array.isArray(rule.threshold[k])
    ? rule.threshold[k].join(", ") : String(rule.threshold[k]));

  const save = async () => {
    setError(null);
    const threshold = {};
    for (const [k, text] of Object.entries(draft.thresholdText)) {
      threshold[k] = Array.isArray(rule.threshold[k])
        ? text.split(",").map((p) => Number(p.trim())).filter((p) => p !== 0 && !Number.isNaN(p))
        : Number(text);
    }
    try {
      const updated = await api.updateRule(rule.rule_id, {
        enabled: draft.enabled, severity: draft.severity,
        ...(Object.keys(threshold).length ? { threshold } : {}),
      });
      onSaved(updated);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (err) {
      setError(err);
    }
  };

  return (
    <Card title={`${rule.rule_id} · ${rule.rule_name}`} subtitle={rule.description}
      actions={<SeverityBadge severity={rule.severity} />}>
      <div className="rule-grid">
        {Object.keys(rule.threshold).map((k) => (
          <label key={k}>{titleCase(k)}
            <input value={value(k)} disabled={!canEdit} spellCheck={false}
              onChange={(e) => setDraft({ ...draft, thresholdText: { ...draft.thresholdText, [k]: e.target.value } })} />
          </label>
        ))}
        <label>Severity
          <select value={draft.severity} disabled={!canEdit}
            onChange={(e) => setDraft({ ...draft, severity: e.target.value })}>
            {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
          </select>
        </label>
        <label className="check">
          <input type="checkbox" checked={draft.enabled} disabled={!canEdit}
            onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })} /> Enabled
        </label>
      </div>
      <p className="mitre">{rule.mitre_hint}</p>
      <ErrorBanner error={error} />
      <div className="row-actions">
        {canEdit && <button type="button" className="btn btn-primary" onClick={save}>Save rule</button>}
        {saved && <span className="saved">✓ Saved — applied to new flows immediately</span>}
        <span className="fine">Last updated {fmtTime(rule.updated_at, true)}</span>
      </div>
    </Card>
  );
}

export default function RulesPage() {
  const { user } = useOutletContext();
  const [rules, setRules] = useState([]);
  const [error, setError] = useState(null);
  useEffect(() => { api.rules().then((r) => setRules(r.items)).catch(setError); }, []);
  const canEdit = user.role === "admin";

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Detection Rules</h1>
          <p className="muted">{canEdit
            ? "Admin mode: threshold changes are validated, audited and hot-reloaded into the engine."
            : "Read-only for analysts. Sign in with the admin key to tune thresholds."}</p>
        </div>
      </div>
      <ErrorBanner error={error} />
      <div className="grid-2">
        {rules.map((r) => (
          <RuleRow key={r.rule_id} rule={r} canEdit={canEdit}
            onSaved={(u) => setRules(rules.map((x) => (x.rule_id === u.rule_id ? u : x)))} />
        ))}
      </div>
    </div>
  );
}
