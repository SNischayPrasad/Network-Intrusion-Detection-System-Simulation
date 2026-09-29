"""
Input validation for network-flow records.

Secure-coding principle: NEVER trust input. Flow records may come from a
simulator, a CSV file, or an HTTP API. Every field is validated before the
detection engine sees it, and every problem is reported clearly.

Two kinds of problems are distinguished:

* ERRORS   – the record cannot be analysed safely (malformed IP, invalid port,
             unsupported protocol). The record is rejected.
* WARNINGS – data-quality issues that can be repaired (a missing packet count,
             a negative duration). The value is imputed and the issue recorded
             so an analyst can see that the data was not perfect.
"""

import ipaddress
import math
from datetime import datetime, timezone

from ids.config import SUPPORTED_PROTOCOLS

NUMERIC_FIELDS = (
    "packet_count",
    "byte_count",
    "duration_seconds",
    "connection_count",
    "failed_connection_count",
    "syn_count",
    "rst_count",
)

# Upper sanity bounds: values beyond these are almost certainly corrupt data.
MAX_REASONABLE = {
    "packet_count": 10**9,
    "byte_count": 10**13,
    "duration_seconds": 86_400 * 7,
    "connection_count": 10**7,
    "failed_connection_count": 10**7,
    "syn_count": 10**9,
    "rst_count": 10**9,
}


class FlowValidationError(ValueError):
    """Raised when a flow record contains unrecoverable errors."""

    def __init__(self, errors):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


def is_valid_ip(value) -> bool:
    """True for a syntactically valid IPv4 or IPv6 address string."""
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def is_valid_port(value) -> bool:
    """True for an integer port in the range 0–65535 (bools are rejected)."""
    if isinstance(value, bool):
        return False
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if isinstance(value, str) and value.strip().isdigit():
        value = int(value.strip())
    return isinstance(value, int) and 0 <= value <= 65535


def normalize_protocol(value):
    """Return the upper-case protocol name, or None if it is unsupported."""
    if not isinstance(value, str):
        return None
    proto = value.strip().upper()
    return proto if proto in SUPPORTED_PROTOCOLS else None


def _to_number(value):
    """Convert value to a finite float, or return None if impossible."""
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if math.isnan(number) or math.isinf(number):
        return None
    return number


def parse_timestamp(value):
    """Parse an ISO-8601 timestamp into an aware UTC datetime (or None)."""
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str) and value.strip():
        text = value.strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return None
    else:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def format_timestamp(dt: datetime) -> str:
    """Canonical fixed-width UTC format used everywhere: 2026-09-28T10:15:00.123Z"""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + \
        f"{dt.microsecond // 1000:03d}Z"


def validate_flow(flow: dict):
    """
    Validate and clean a raw flow record.

    Returns
    -------
    (clean_flow, warnings)
        clean_flow : dict with normalised types
        warnings   : list[str] of repaired data-quality issues

    Raises
    ------
    FlowValidationError if the record has unrecoverable errors.
    """
    if not isinstance(flow, dict):
        raise FlowValidationError(["flow record must be a JSON object / dict"])

    errors, warnings = [], []
    clean = dict(flow)

    # --- IP addresses -------------------------------------------------------
    for field in ("source_ip", "destination_ip"):
        value = flow.get(field)
        if not is_valid_ip(value):
            errors.append(f"{field} is missing or not a valid IP address: {value!r}")
        else:
            clean[field] = str(ipaddress.ip_address(value.strip()))

    # --- Protocol -------------------------------------------------------------
    proto = normalize_protocol(flow.get("protocol"))
    if proto is None:
        errors.append(
            f"protocol {flow.get('protocol')!r} is not supported "
            f"(expected one of {', '.join(SUPPORTED_PROTOCOLS)})"
        )
    else:
        clean["protocol"] = proto

    # --- Ports ----------------------------------------------------------------
    for field in ("source_port", "destination_port"):
        value = flow.get(field)
        if value is None and proto == "ICMP":
            clean[field] = 0  # ICMP has no ports
            continue
        if not is_valid_port(value):
            errors.append(f"{field} must be an integer between 0 and 65535: {value!r}")
        else:
            clean[field] = int(value)

    # --- Numeric counters (repairable) ---------------------------------------
    for field in NUMERIC_FIELDS:
        # Accept the short alias "duration" as well as "duration_seconds".
        raw = flow.get(field)
        if raw is None and field == "duration_seconds":
            raw = flow.get("duration")
        number = _to_number(raw)
        if number is None:
            warnings.append(f"{field} missing or non-numeric -> imputed 0")
            number = 0.0
        elif number < 0:
            warnings.append(f"{field} was negative ({number}) -> clamped to 0")
            number = 0.0
        elif number > MAX_REASONABLE[field]:
            errors.append(f"{field} value {number} exceeds sanity limit")
        clean[field] = float(number) if field == "duration_seconds" else int(round(number))

    # Logical consistency: failed connections cannot exceed total connections.
    if not errors:
        if clean["failed_connection_count"] > clean["connection_count"]:
            warnings.append(
                "failed_connection_count > connection_count -> connection_count raised to match"
            )
            clean["connection_count"] = clean["failed_connection_count"]

    # --- Timestamp -----------------------------------------------------------
    ts = parse_timestamp(flow.get("timestamp"))
    if flow.get("timestamp") is not None and ts is None:
        warnings.append(f"timestamp {flow.get('timestamp')!r} unparseable -> using current time")
    if ts is None:
        ts = datetime.now(timezone.utc)
    clean["timestamp"] = format_timestamp(ts)

    if errors:
        raise FlowValidationError(errors)
    return clean, warnings
