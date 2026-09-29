"""
SIEM export (conceptual integration, no commercial SIEM required).

    IDS -> JSON alert -> log forwarder / API -> SIEM -> correlation -> SOC analyst

Most SIEMs (Splunk, Elastic, Microsoft Sentinel, Wazuh, QRadar...) ingest
newline-delimited JSON. We write alerts to a JSONL file using field names
inspired by the Elastic Common Schema (ECS) so a log shipper (e.g. Filebeat,
Fluent Bit, a Splunk Universal Forwarder) could tail the file and forward it.

Only metadata is exported — never packet payloads.
"""

import json
from pathlib import Path


def to_siem_event(alert: dict) -> dict:
    """Map an internal alert into a flat, SIEM-friendly JSON document."""
    return {
        "@timestamp": alert["timestamp"],
        "event.kind": "alert",
        "event.category": "network",
        "event.module": "network-ids-simulation",
        "event.severity_label": alert["severity"],
        "event.risk_score": alert["risk_score"],
        "rule.id": alert["rule_id"],
        "rule.name": alert["alert_type"],
        "source.ip": alert["source_ip"],
        "source.port": alert["source_port"],
        "destination.ip": alert["destination_ip"],
        "destination.port": alert["destination_port"],
        "network.transport": alert["protocol"].lower(),
        "alert.id": alert["alert_id"],
        "alert.status": alert.get("status", "NEW"),
        "message": alert.get("reason", ""),
        "threat.candidate_mapping": alert.get("mitre_hint", ""),
    }


def append_to_jsonl(alert: dict, path) -> None:
    """Append one SIEM event per line (the format log forwarders expect)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(to_siem_event(alert)) + "\n")
