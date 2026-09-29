"""
SQLite persistence layer (standard-library sqlite3, no ORM).

Secure-coding rules followed here:
  * EVERY query uses parameter placeholders (?) — never string formatting
    with user input — which prevents SQL injection.
  * Foreign keys are enforced.
  * No packet payloads are stored: only flow metadata and detection results.

Entity relationships
--------------------
    network_flows 1 ──── 0..1 alerts           (a flow may raise one alert)
    incidents     1 ──── 1..* alerts           (correlated group of alerts)
    alerts        1 ──── 0..* incident_notes   (analyst notes / resolutions)
    network_flows 1 ──── 0..* model_results    (ML predictions per flow)
    rules         (referenced by alerts.rule_id; ANOMALY / ML are virtual ids)
    audit_log     (append-only record of who did what, when)
"""

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS network_flows (
    flow_id                 TEXT PRIMARY KEY,
    timestamp               TEXT NOT NULL,
    source_ip               TEXT NOT NULL,
    destination_ip          TEXT NOT NULL,
    source_port             INTEGER NOT NULL,
    destination_port        INTEGER NOT NULL,
    protocol                TEXT NOT NULL CHECK (protocol IN ('TCP','UDP','ICMP')),
    packet_count            INTEGER NOT NULL,
    byte_count              INTEGER NOT NULL,
    duration                REAL NOT NULL,
    connection_count        INTEGER NOT NULL DEFAULT 0,
    failed_connection_count INTEGER NOT NULL DEFAULT 0,
    syn_count               INTEGER NOT NULL DEFAULT 0,
    rst_count               INTEGER NOT NULL DEFAULT 0,
    average_packet_size     REAL NOT NULL DEFAULT 0,
    signature_score         REAL NOT NULL DEFAULT 0,
    anomaly_score           REAL NOT NULL DEFAULT 0,
    ml_score                REAL,
    risk_score              REAL NOT NULL,
    risk_band               TEXT NOT NULL,
    classification          TEXT NOT NULL,
    detection_json          TEXT NOT NULL,      -- features, anomaly details, rule matches
    label                   TEXT,               -- synthetic ground truth (if known)
    scenario_type           TEXT,
    ingested_at             TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_flows_timestamp      ON network_flows(timestamp);
CREATE INDEX IF NOT EXISTS idx_flows_source_ip      ON network_flows(source_ip);
CREATE INDEX IF NOT EXISTS idx_flows_classification ON network_flows(classification);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id    TEXT PRIMARY KEY,
    source_ip      TEXT NOT NULL,
    alert_type     TEXT NOT NULL,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    alert_count    INTEGER NOT NULL DEFAULT 1,
    max_severity   TEXT NOT NULL,
    max_risk_score REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incidents_key ON incidents(source_ip, alert_type, last_seen);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id                 TEXT PRIMARY KEY,
    flow_id                  TEXT NOT NULL UNIQUE REFERENCES network_flows(flow_id),
    incident_id              TEXT REFERENCES incidents(incident_id),
    rule_id                  TEXT NOT NULL,
    alert_type               TEXT NOT NULL,
    severity                 TEXT NOT NULL CHECK (severity IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL')),
    description              TEXT NOT NULL,
    reason                   TEXT NOT NULL,
    risk_score               REAL NOT NULL,
    signature_score          REAL NOT NULL DEFAULT 0,
    anomaly_score            REAL NOT NULL DEFAULT 0,
    ml_score                 REAL,
    status                   TEXT NOT NULL DEFAULT 'NEW'
                             CHECK (status IN ('NEW','INVESTIGATING','RESOLVED','FALSE_POSITIVE')),
    source_ip                TEXT NOT NULL,
    destination_ip           TEXT NOT NULL,
    source_port              INTEGER NOT NULL,
    destination_port         INTEGER NOT NULL,
    protocol                 TEXT NOT NULL,
    matched_rules_json       TEXT NOT NULL DEFAULT '[]',
    mitre_hint               TEXT NOT NULL DEFAULT '',
    created_at               TEXT NOT NULL,   -- event time of the flow
    detected_at              TEXT NOT NULL,   -- wall-clock time of detection
    updated_at               TEXT NOT NULL,
    assigned_to              TEXT,
    investigation_started_at TEXT,
    resolved_at              TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_created   ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_status    ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_source    ON alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_incident  ON alerts(incident_id);

CREATE TABLE IF NOT EXISTS rules (
    rule_id     TEXT PRIMARY KEY,
    rule_name   TEXT NOT NULL,
    description TEXT NOT NULL,
    severity    TEXT NOT NULL,
    threshold   TEXT NOT NULL,          -- JSON object of tunable thresholds
    enabled     INTEGER NOT NULL DEFAULT 1,
    mitre_hint  TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incident_notes (
    note_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id   TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
    note       TEXT NOT NULL,
    note_type  TEXT NOT NULL DEFAULT 'NOTE' CHECK (note_type IN ('NOTE','RESOLUTION')),
    analyst    TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notes_alert ON incident_notes(alert_id);

CREATE TABLE IF NOT EXISTS model_results (
    result_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id    TEXT NOT NULL REFERENCES network_flows(flow_id) ON DELETE CASCADE,
    model_name TEXT NOT NULL,
    prediction TEXT NOT NULL,
    score      REAL NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_model_results_flow ON model_results(flow_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    actor       TEXT NOT NULL,
    role        TEXT NOT NULL,
    action      TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id   TEXT NOT NULL,
    details     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_log(target_type, target_id);
"""


class Database:
    """
    Hands out one reusable connection per thread.

    Opening a SQLite connection costs ~5–10 ms on Windows, so reusing it per
    thread is much faster than connect/close on every request. Each `with
    db.connect()` block is still its own transaction (commit or rollback).
    """

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Serialises writes from the threadpool (SQLite allows one writer at a time).
        self.write_lock = threading.RLock()
        self._local = threading.local()

    def _thread_connection(self):
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=30)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            # Per-connection setting: safe with WAL and avoids a full disk sync per commit.
            conn.execute("PRAGMA synchronous = NORMAL")
            self._local.conn = conn
        return conn

    @contextmanager
    def connect(self):
        conn = self._thread_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def init_schema(self):
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode = WAL")   # readers don't block the writer
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.executescript(SCHEMA)

    def seed_rules(self, rules, now_iso):
        """Insert default rules only if they are not already present."""
        with self.connect() as conn:
            for r in rules:
                conn.execute(
                    "INSERT OR IGNORE INTO rules (rule_id, rule_name, description, severity, "
                    "threshold, enabled, mitre_hint, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                    (r["rule_id"], r["rule_name"], r["description"], r["severity"],
                     json.dumps(r["threshold"]), int(r["enabled"]), r.get("mitre_hint", ""),
                     now_iso))

    def load_rules(self):
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM rules ORDER BY rule_id").fetchall()
        return [rule_row_to_dict(r) for r in rows]


def rule_row_to_dict(row):
    d = dict(row)
    d["threshold"] = json.loads(d["threshold"])
    d["enabled"] = bool(d["enabled"])
    return d


def row_to_dict(row):
    return dict(row) if row is not None else None
