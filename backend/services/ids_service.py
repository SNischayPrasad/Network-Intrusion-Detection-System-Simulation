"""
Flow ingestion service: validate -> detect -> store -> correlate -> export.

This is where the real-time pipeline lives:

    Simulator --POST--> /api/flows --> IDSService.process_flow()
                                          ├─ HybridIDSEngine.analyze()
                                          ├─ INSERT network_flows / model_results
                                          ├─ correlate into incidents
                                          ├─ INSERT alerts + audit entry
                                          └─ append SIEM JSON event
"""

import json
import logging
import uuid
from datetime import timedelta

from backend.services.audit import write_audit
from backend.utils.time_utils import now_iso
from ids.config import SEVERITIES
from ids.engine import HybridIDSEngine
from ids.siem_export import append_to_jsonl
from ids.validation import format_timestamp, parse_timestamp

log = logging.getLogger("ids.service")


class DuplicateFlowError(Exception):
    """Raised when a flow_id has already been ingested (idempotency protection)."""


class IDSService:
    def __init__(self, settings, db, engine: HybridIDSEngine | None = None):
        self.settings = settings
        self.db = db
        self.engine = engine or HybridIDSEngine.from_project_files(
            enable_ml=settings.ml_enabled, rules=db.load_rules())
        log.info("IDS engine ready | ML %s | %d rules",
                 "ENABLED" if self.engine.ml_enabled else "DISABLED", len(self.engine.rules))

    def reload_rules(self):
        self.engine.set_rules(self.db.load_rules())

    # ------------------------------------------------------------------
    def process_flow(self, flow: dict, actor: str = "sensor", role: str = "sensor",
                     ml_probability: float | None = None) -> dict:
        flow = {k: v for k, v in flow.items() if v is not None}
        flow.setdefault("flow_id", f"FLOW-{uuid.uuid4().hex[:12].upper()}")

        with self.db.write_lock:
            with self.db.connect() as conn:
                exists = conn.execute("SELECT 1 FROM network_flows WHERE flow_id = ?",
                                      (flow["flow_id"],)).fetchone()
                if exists:
                    raise DuplicateFlowError(flow["flow_id"])

                # may raise FlowValidationError
                result = self.engine.analyze(flow, ml_probability=ml_probability)
                clean = result["flow"]
                clean["flow_id"] = flow["flow_id"]
                self._insert_flow(conn, clean, result)

                alert = result["alert"]
                incident_id = None
                if alert:
                    alert["flow_id"] = clean["flow_id"]
                    incident_id = self._correlate(conn, alert)
                    self._insert_alert(conn, alert, incident_id)
                    write_audit(conn, "ids-engine", "system", "ALERT_CREATED", "alert",
                                alert["alert_id"],
                                f"{alert['alert_type']} | severity={alert['severity']} "
                                f"risk={alert['risk_score']}", timestamp=alert["detected_at"])

        if alert and self.settings.siem_export_enabled:
            try:
                append_to_jsonl(alert, self.settings.siem_export_path)
            except OSError:  # SIEM export must never break detection
                log.exception("SIEM export failed")

        return {
            "flow_id": clean["flow_id"],
            "timestamp": clean["timestamp"],
            "classification": result["classification"],
            "risk_score": result["risk_score"],
            "risk_band": result["risk_band"],
            "severity": result["severity"],
            "signature_score": result["signature_score"],
            "anomaly_score": result["anomaly"]["score"],
            "ml_score": None if result["ml_probability"] is None
            else round(result["ml_probability"] * 100, 1),
            "rule_matches": result["rule_matches"],
            "features": result["features"],
            "data_quality_warnings": result["data_quality_warnings"],
            "alert": None if not alert else {
                "alert_id": alert["alert_id"], "alert_type": alert["alert_type"],
                "rule_id": alert["rule_id"], "severity": alert["severity"],
                "risk_score": alert["risk_score"], "status": alert["status"],
                "incident_id": incident_id,
            },
        }

    # ------------------------------------------------------------------
    def _insert_flow(self, conn, flow, result):
        detection = {
            "features": result["features"],
            "anomaly": result["anomaly"],
            "rule_matches": result["rule_matches"],
            "ml_probability": result["ml_probability"],
            "data_quality_warnings": result["data_quality_warnings"],
        }
        conn.execute(
            """INSERT INTO network_flows (flow_id, timestamp, source_ip, destination_ip,
               source_port, destination_port, protocol, packet_count, byte_count, duration,
               connection_count, failed_connection_count, syn_count, rst_count,
               average_packet_size, signature_score, anomaly_score, ml_score, risk_score,
               risk_band, classification, detection_json, label, scenario_type, ingested_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (flow["flow_id"], flow["timestamp"], flow["source_ip"], flow["destination_ip"],
             flow["source_port"], flow["destination_port"], flow["protocol"],
             flow["packet_count"], flow["byte_count"], flow["duration_seconds"],
             flow["connection_count"], flow["failed_connection_count"], flow["syn_count"],
             flow["rst_count"], result["features"]["average_packet_size"],
             result["signature_score"], result["anomaly"]["score"],
             None if result["ml_probability"] is None else round(result["ml_probability"] * 100, 1),
             result["risk_score"], result["risk_band"], result["classification"],
             json.dumps(detection), flow.get("label"), flow.get("scenario_type"), now_iso()))
        if result["ml_probability"] is not None:
            prob = result["ml_probability"]
            conn.execute(
                "INSERT INTO model_results (flow_id, model_name, prediction, score, created_at) "
                "VALUES (?,?,?,?,?)",
                (flow["flow_id"], self.engine.ml_detector.name,
                 "SUSPICIOUS" if prob >= 0.5 else "NORMAL", round(prob, 4), now_iso()))

    def _correlate(self, conn, alert) -> str:
        """Attach the alert to an open incident (same source + type within window)."""
        ts = parse_timestamp(alert["timestamp"])
        window_start = format_timestamp(
            ts - timedelta(seconds=self.settings.correlation_window_seconds))
        row = conn.execute(
            "SELECT * FROM incidents WHERE source_ip = ? AND alert_type = ? AND last_seen >= ? "
            "ORDER BY last_seen DESC LIMIT 1",
            (alert["source_ip"], alert["alert_type"], window_start)).fetchone()
        if row:
            worst = max(row["max_severity"], alert["severity"], key=SEVERITIES.index)
            conn.execute(
                "UPDATE incidents SET last_seen = MAX(last_seen, ?), alert_count = alert_count + 1, "
                "max_risk_score = MAX(max_risk_score, ?), max_severity = ? WHERE incident_id = ?",
                (alert["timestamp"], alert["risk_score"], worst, row["incident_id"]))
            return row["incident_id"]
        incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        conn.execute(
            "INSERT INTO incidents (incident_id, source_ip, alert_type, first_seen, last_seen, "
            "alert_count, max_severity, max_risk_score) VALUES (?,?,?,?,?,1,?,?)",
            (incident_id, alert["source_ip"], alert["alert_type"], alert["timestamp"],
             alert["timestamp"], alert["severity"], alert["risk_score"]))
        return incident_id

    def _insert_alert(self, conn, alert, incident_id):
        conn.execute(
            """INSERT INTO alerts (alert_id, flow_id, incident_id, rule_id, alert_type, severity,
               description, reason, risk_score, signature_score, anomaly_score, ml_score, status,
               source_ip, destination_ip, source_port, destination_port, protocol,
               matched_rules_json, mitre_hint, created_at, detected_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (alert["alert_id"], alert["flow_id"], incident_id, alert["rule_id"],
             alert["alert_type"], alert["severity"], alert["description"], alert["reason"],
             alert["risk_score"], alert["signature_score"], alert["anomaly_score"],
             alert["ml_score"], alert["status"], alert["source_ip"], alert["destination_ip"],
             alert["source_port"], alert["destination_port"], alert["protocol"],
             json.dumps(alert["matched_rules"]), alert["mitre_hint"], alert["timestamp"],
             alert["detected_at"], alert["detected_at"]))
