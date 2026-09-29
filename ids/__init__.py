"""
ids — the core Hybrid Network Intrusion Detection engine.

This package is intentionally independent of the web backend so it can be
used from scripts, notebooks, tests, and the ML pipeline.

Modules
-------
config            Central thresholds, weights, and risk bands (all tunable).
validation        Input validation for IPs, ports, protocols, and numbers.
feature_extractor Turns a raw flow record into security-relevant features.
rule_engine       Signature / rule-based detection (IDS-001 ... IDS-006).
anomaly_detector  Statistical baseline + Z-score / IQR anomaly scoring.
risk_engine       Hybrid weighted risk score (rules + anomaly + optional ML).
alert_engine      Builds analyst-ready alerts with investigation guidance.
correlation       Groups related alerts into incidents.
engine            The HybridIDSEngine that wires all of the above together.
siem_export       Converts alerts into SIEM-friendly JSON events.

SAFETY: Everything here analyses *data records*. Nothing in this package
sends, sniffs, or crafts network packets.
"""

__version__ = "1.0.0"
