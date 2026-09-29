"""
Detection-rule management (tuning thresholds without code changes).

Threshold updates are strictly validated: only keys that already exist for
the rule may be changed, and values must be positive numbers (or a list of
valid ports for the watch-list rule). Every change is written to the audit log
because silently weakened detection rules are a classic insider-threat /
defense-evasion concern.
"""

import json

from backend.services.audit import write_audit
from backend.utils.time_utils import now_iso
from ids.validation import is_valid_port


class RuleValidationError(ValueError):
    pass


def _validate_threshold(current: dict, proposed: dict) -> dict:
    unknown = set(proposed) - set(current)
    if unknown:
        raise RuleValidationError(f"Unknown threshold keys: {', '.join(sorted(unknown))}. "
                                  f"Allowed: {', '.join(sorted(current))}")
    merged = dict(current)
    for key, value in proposed.items():
        if isinstance(current[key], list):
            if not isinstance(value, list) or not value or \
                    not all(is_valid_port(p) for p in value):
                raise RuleValidationError(f"{key} must be a non-empty list of ports (0-65535)")
            merged[key] = sorted({int(p) for p in value})
        else:
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
                raise RuleValidationError(f"{key} must be a positive number")
            if key.endswith("ratio") and value > 1:
                raise RuleValidationError(f"{key} is a ratio and must be between 0 and 1")
            merged[key] = value
    return merged


def update_rule(db, rule_id, update, principal):
    with db.write_lock, db.connect() as conn:
        row = conn.execute("SELECT * FROM rules WHERE rule_id = ?", (rule_id,)).fetchone()
        if row is None:
            return None
        threshold = json.loads(row["threshold"])
        changes = []
        if update.threshold is not None:
            new_threshold = _validate_threshold(threshold, update.threshold)
            changes.append(f"threshold {threshold} -> {new_threshold}")
            threshold = new_threshold
        enabled = row["enabled"] if update.enabled is None else int(update.enabled)
        if enabled != row["enabled"]:
            changes.append(f"enabled {bool(row['enabled'])} -> {bool(enabled)}")
        severity = update.severity or row["severity"]
        if severity != row["severity"]:
            changes.append(f"severity {row['severity']} -> {severity}")

        conn.execute("UPDATE rules SET threshold = ?, enabled = ?, severity = ?, updated_at = ? "
                     "WHERE rule_id = ?",
                     (json.dumps(threshold), enabled, severity, now_iso(), rule_id))
        write_audit(conn, principal.name, principal.role, "RULE_UPDATED", "rule", rule_id,
                    "; ".join(changes) or "no changes")
        updated = dict(conn.execute("SELECT * FROM rules WHERE rule_id = ?", (rule_id,)).fetchone())
    updated["threshold"] = json.loads(updated["threshold"])
    updated["enabled"] = bool(updated["enabled"])
    return updated
