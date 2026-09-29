"""
Central IDS configuration.

Every threshold in this file is a PROJECT ASSUMPTION chosen to work with the
synthetic dataset. In a real SOC these numbers must be calibrated against the
organisation's own traffic baseline (and re-tuned over time).

Keeping all tunables in one place is an industry habit: it makes detection
logic reviewable ("detection-as-code") and avoids magic numbers scattered
throughout the codebase.
"""

from copy import deepcopy

# ---------------------------------------------------------------------------
# Supported values
# ---------------------------------------------------------------------------
SUPPORTED_PROTOCOLS = ("TCP", "UDP", "ICMP")

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

ALERT_STATUSES = ("NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE")

# Allowed analyst workflow transitions (current status -> allowed next statuses)
STATUS_TRANSITIONS = {
    "NEW": ("INVESTIGATING", "FALSE_POSITIVE"),
    "INVESTIGATING": ("RESOLVED", "FALSE_POSITIVE"),
    "RESOLVED": ("INVESTIGATING",),        # re-open if new evidence appears
    "FALSE_POSITIVE": ("INVESTIGATING",),  # re-open if the FP call was wrong
}

CLASSIFICATIONS = ("NORMAL", "SUSPICIOUS", "POTENTIAL_INTRUSION")

# Well-known service ports that are *expected* in our simulated environment.
KNOWN_SERVICE_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 123: "NTP", 143: "IMAP", 443: "HTTPS", 465: "SMTPS",
    587: "SMTP-SUBMISSION", 993: "IMAPS", 995: "POP3S", 3306: "MYSQL",
    5432: "POSTGRESQL", 6379: "REDIS", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
    873: "RSYNC",
}

# Ports that are commonly associated with legacy/insecure services or that are
# frequently seen in malicious tooling. Seeing them is not proof of anything,
# but it is worth an analyst's attention in most enterprise networks.
WATCHLIST_PORTS = {
    23: "Telnet (cleartext remote admin)",
    2323: "Alternate Telnet",
    4444: "Common default for remote-shell tooling",
    5555: "Android Debug Bridge / remote tooling",
    6667: "IRC (historically used for botnet C2)",
    1337: "Non-standard 'leet' port",
    31337: "Non-standard 'elite' port",
    12345: "Legacy trojan default port",
    3389: "RDP exposed to untrusted source",
}

# ---------------------------------------------------------------------------
# Feature-engineering parameters
# ---------------------------------------------------------------------------
FEATURE_CONFIG = {
    # Rates are computed over max(duration, this floor) so that a 1 ms flow does
    # not produce an absurd "1,000,000 bytes/second" value.
    "rate_duration_floor_seconds": 1.0,
    # Sliding window used to compute per-source diversity features
    # (unique destination ports / IPs contacted by the same source).
    "source_window_seconds": 60,
}

# ---------------------------------------------------------------------------
# Signature / rule-based detection
# ---------------------------------------------------------------------------
# Each rule has an id, name, severity, description, thresholds and a *candidate*
# MITRE ATT&CK mapping. The mapping is a hint for analysts, NOT a verdict:
# a statistical pattern alone never proves which technique (if any) is in use.
DEFAULT_RULES = [
    {
        "rule_id": "IDS-001",
        "rule_name": "High Connection Rate",
        "severity": "HIGH",
        "description": "Connection rate exceeded configured baseline.",
        "threshold": {"connection_rate_per_sec": 10.0, "connection_count": 150},
        "enabled": True,
        "mitre_hint": "TA0040 Impact / T1498 Network Denial of Service "
                      "(requires corroborating evidence)",
    },
    {
        "rule_id": "IDS-002",
        "rule_name": "Repeated Failed Connections",
        "severity": "HIGH",
        "description": "Many connection attempts failed; possible password-guessing "
                       "or misconfigured client.",
        "threshold": {"failed_connection_count": 10, "failure_ratio": 0.5},
        "enabled": True,
        "mitre_hint": "TA0006 Credential Access / T1110 Brute Force "
                      "(only if authentication logs confirm)",
    },
    {
        "rule_id": "IDS-003",
        "rule_name": "Multi-Port Probing Pattern",
        "severity": "HIGH",
        "description": "One source contacted an unusually large number of distinct "
                       "destination ports within the time window.",
        "threshold": {"unique_destination_ports": 12},
        "enabled": True,
        "mitre_hint": "TA0007 Discovery / T1046 Network Service Discovery",
    },
    {
        "rule_id": "IDS-004",
        "rule_name": "SYN-Heavy Connection Behavior",
        "severity": "CRITICAL",
        "description": "A large share of packets were TCP SYNs with few completed "
                       "handshakes (half-open connection pattern).",
        "threshold": {"syn_count": 100, "syn_ratio": 0.7},
        "enabled": True,
        "mitre_hint": "TA0040 Impact / T1498 Network Denial of Service "
                      "(or T1499 Endpoint DoS)",
    },
    {
        "rule_id": "IDS-005",
        "rule_name": "Unusual Service-Port Activity",
        "severity": "MEDIUM",
        "description": "Traffic to a watch-listed / non-standard service port.",
        "threshold": {"watchlist_ports": sorted(WATCHLIST_PORTS)},
        "enabled": True,
        "mitre_hint": "TA0011 Command and Control / T1571 Non-Standard Port",
    },
    {
        "rule_id": "IDS-006",
        "rule_name": "Abnormally High Traffic Volume",
        "severity": "MEDIUM",
        "description": "Flow volume or throughput far above the normal baseline.",
        "threshold": {"byte_count": 500_000_000, "bytes_per_second": 5_000_000},
        "enabled": True,
        "mitre_hint": "TA0010 Exfiltration / T1048 Exfiltration Over "
                      "Alternative Protocol (backups are a common false positive)",
    },
]

# Base risk contribution of a rule match, by severity.
SEVERITY_SCORES = {"INFO": 10, "LOW": 25, "MEDIUM": 50, "HIGH": 75, "CRITICAL": 90}

# Every additional rule matched on the same flow adds this many points (capped at 100).
ADDITIONAL_RULE_BONUS = 5

# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------
ANOMALY_CONFIG = {
    # Metrics that the statistical baseline tracks.
    "metrics": [
        "packets_per_second",
        "bytes_per_second",
        "connection_rate",
        "failure_ratio",
        "unique_destination_ports",
    ],
    # Heavy-tailed metrics are log-transformed (log1p) before computing Z-scores.
    "log_metrics": [
        "packets_per_second",
        "bytes_per_second",
        "connection_rate",
        "unique_destination_ports",
    ],
    # Z-score at which a metric starts contributing, and where it saturates at 100.
    "z_warn": 2.0,
    "z_max": 6.0,
    # Standard-deviation floor (in transformed units) so near-constant metrics
    # don't turn tiny deviations into huge Z-scores.
    "min_std": {
        "packets_per_second": 0.25,
        "bytes_per_second": 0.25,
        "connection_rate": 0.25,
        "failure_ratio": 0.10,
        "unique_destination_ports": 0.25,
    },
    # IQR fence multiplier for "extreme outlier" (Tukey's outer fence = 3.0).
    "iqr_multiplier": 3.0,
    "iqr_bonus_per_metric": 5,
    # EWMA smoothing factor for the optional adaptive (moving-average) baseline.
    "ewma_alpha": 0.01,
    "adaptive_baseline": False,
}

# ---------------------------------------------------------------------------
# Hybrid risk scoring
# ---------------------------------------------------------------------------
RISK_WEIGHTS_WITH_ML = {"signature": 0.40, "anomaly": 0.30, "ml": 0.30}
RISK_WEIGHTS_WITHOUT_ML = {"signature": 0.60, "anomaly": 0.40}

# A signature match should never be "averaged away" to NORMAL. The final score
# is floored at the start of the band matching the rule's severity
# (MEDIUM -> 41, HIGH -> 61). CRITICAL is deliberately floored at the HIGH band:
# reaching "CRITICAL INVESTIGATION" requires corroboration from anomaly/ML.
RULE_SEVERITY_RISK_FLOOR = {"INFO": 0, "LOW": 21, "MEDIUM": 41, "HIGH": 61, "CRITICAL": 61}

# Without rules, anomaly can contribute at most 40 points (0.4 * 100), which is
# below the SUSPICIOUS threshold — so an anomaly-only detection could never alert.
# These floors let a single, highly confident detector raise SUSPICIOUS on its own.
SINGLE_DETECTOR_FLOORS = {
    "anomaly": {"min_score": 75, "floor": 41},   # anomaly score >= 75
    "ml": {"min_score": 85, "floor": 41},        # ML probability >= 85%
}

# Risk bands (inclusive upper bounds). Project assumptions — calibrate in a real SOC.
RISK_BANDS = [
    (20, "NORMAL", "INFO"),
    (40, "LOW RISK", "LOW"),
    (60, "SUSPICIOUS", "MEDIUM"),
    (80, "HIGH RISK", "HIGH"),
    (100, "CRITICAL INVESTIGATION", "CRITICAL"),
]

# Classification thresholds on the final 0–100 risk score.
CLASSIFICATION_THRESHOLDS = {
    "SUSPICIOUS": 41,          # risk >= 41 -> SUSPICIOUS
    "POTENTIAL_INTRUSION": 81,  # risk >= 81 -> POTENTIAL_INTRUSION
}

# An alert is raised when the final risk reaches this value OR any rule matches.
ALERT_RISK_THRESHOLD = 41

# ---------------------------------------------------------------------------
# Alert correlation
# ---------------------------------------------------------------------------
CORRELATION_WINDOW_SECONDS = 60


def get_default_rules():
    """Return a deep copy so callers can modify rules without side effects."""
    return deepcopy(DEFAULT_RULES)
