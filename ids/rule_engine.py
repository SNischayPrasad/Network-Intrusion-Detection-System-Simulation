"""
Signature / rule-based detection.

Each rule encodes a known suspicious *behaviour pattern* with configurable
thresholds. A rule match means:

    "This flow looks like a pattern that deserves investigation."

It does NOT prove malicious activity. A backup job can exceed the volume rule;
a misconfigured service can trigger failed-connection rules. That is why every
match becomes an alert for a human analyst rather than an automatic block.

Main entry point: analyze_flow(features, flow, rules=None)
"""

from dataclasses import asdict, dataclass

from ids.config import (
    ADDITIONAL_RULE_BONUS,
    SEVERITIES,
    SEVERITY_SCORES,
    WATCHLIST_PORTS,
    get_default_rules,
)


@dataclass
class RuleMatch:
    rule_id: str
    name: str
    severity: str
    description: str
    evidence: str          # human-readable "why did this fire?"
    mitre_hint: str = ""

    def to_dict(self):
        return asdict(self)


# ---------------------------------------------------------------------------
# Individual rule checks. Each returns an evidence string if it fires, else None.
# Keeping each rule as a small pure function makes it easy to unit-test.
# ---------------------------------------------------------------------------
def _check_high_connection_rate(f, flow, t):
    rate_hit = f["connection_rate"] >= t["connection_rate_per_sec"]
    count_hit = f["connection_count"] >= t["connection_count"]
    if rate_hit or count_hit:
        return (f"connection_rate={f['connection_rate']:.1f}/s "
                f"(threshold {t['connection_rate_per_sec']}/s), "
                f"connection_count={int(f['connection_count'])} "
                f"(threshold {t['connection_count']})")
    return None


def _check_failed_connections(f, flow, t):
    if (f["failed_connection_count"] >= t["failed_connection_count"]
            and f["failure_ratio"] >= t["failure_ratio"]):
        return (f"failed_connections={int(f['failed_connection_count'])} "
                f"(threshold {t['failed_connection_count']}), "
                f"failure_ratio={f['failure_ratio']:.2f} (threshold {t['failure_ratio']})")
    return None


def _check_multi_port(f, flow, t):
    if f["unique_destination_ports"] >= t["unique_destination_ports"]:
        return (f"unique_destination_ports={int(f['unique_destination_ports'])} in window "
                f"(threshold {t['unique_destination_ports']})")
    return None


def _check_syn_heavy(f, flow, t):
    if flow.get("protocol") != "TCP":
        return None
    if f["syn_count"] >= t["syn_count"] and f["syn_ratio"] >= t["syn_ratio"]:
        return (f"syn_count={int(f['syn_count'])} (threshold {t['syn_count']}), "
                f"syn_ratio={f['syn_ratio']:.2f} (threshold {t['syn_ratio']})")
    return None


def _check_unusual_port(f, flow, t):
    port = flow.get("destination_port")
    watchlist = set(t.get("watchlist_ports", []))
    if port in watchlist:
        reason = WATCHLIST_PORTS.get(port, "watch-listed port")
        return f"destination_port={port} is on the watchlist ({reason})"
    return None


def _check_high_volume(f, flow, t):
    if f["byte_count"] >= t["byte_count"] or f["bytes_per_second"] >= t["bytes_per_second"]:
        return (f"byte_count={int(f['byte_count']):,} (threshold {t['byte_count']:,}), "
                f"bytes_per_second={f['bytes_per_second']:,.0f} "
                f"(threshold {t['bytes_per_second']:,})")
    return None


RULE_CHECKS = {
    "IDS-001": _check_high_connection_rate,
    "IDS-002": _check_failed_connections,
    "IDS-003": _check_multi_port,
    "IDS-004": _check_syn_heavy,
    "IDS-005": _check_unusual_port,
    "IDS-006": _check_high_volume,
}


def analyze_flow(features: dict, flow: dict, rules: list | None = None):
    """
    Evaluate every enabled rule against one flow.

    Parameters
    ----------
    features : output of extract_network_features()
    flow     : the validated flow record (needed for protocol / port context)
    rules    : list of rule dicts (defaults to ids.config.DEFAULT_RULES).
               Rules loaded from the database use the same shape.

    Returns
    -------
    list[RuleMatch] ordered from most to least severe.
    """
    rules = rules if rules is not None else get_default_rules()
    matches = []
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        check = RULE_CHECKS.get(rule["rule_id"])
        if check is None:
            continue  # unknown rule id: ignore rather than crash
        try:
            evidence = check(features, flow, rule["threshold"])
        except (KeyError, TypeError):
            # A mis-configured threshold must not take the whole IDS down.
            evidence = None
        if evidence:
            matches.append(RuleMatch(
                rule_id=rule["rule_id"],
                name=rule["rule_name"],
                severity=rule["severity"],
                description=rule["description"],
                evidence=evidence,
                mitre_hint=rule.get("mitre_hint", ""),
            ))
    matches.sort(key=lambda m: SEVERITIES.index(m.severity), reverse=True)
    return matches


def calculate_signature_score(matches) -> float:
    """
    Convert rule matches into a 0–100 signature risk.

    Highest-severity match sets the base score; each extra match adds a small
    bonus because multiple independent indicators increase confidence.
    """
    if not matches:
        return 0.0
    base = max(SEVERITY_SCORES[m.severity] for m in matches)
    bonus = ADDITIONAL_RULE_BONUS * (len(matches) - 1)
    return float(min(100, base + bonus))
