"""
Network feature engineering.

A raw flow record says *what happened* (packets, bytes, ports...). Features
describe *how it behaved* (rates, ratios, diversity) — which is what detection
logic actually needs. For example, 5,000 bytes is meaningless on its own, but
5,000 bytes in 0.01 s vs. in 10 minutes tells very different stories.

Main entry points
-----------------
extract_network_features(flow, context=None)
    Features for a single flow. `context` optionally supplies per-source
    window statistics (unique destination ports / IPs).

SourceWindowTracker
    Keeps a sliding time window per source IP so we can compute
    "how many distinct ports has this source touched in the last 60 s?".
    That is how port-probing patterns are recognised: each single flow looks
    harmless, only the aggregate reveals the pattern.

extract_features_for_records(records)
    Convenience helper that runs a whole (time-sorted) dataset through the
    tracker + extractor — used by the ML pipeline and evaluation scripts.
"""

import threading
from collections import defaultdict, deque

from ids.config import FEATURE_CONFIG
from ids.validation import parse_timestamp, validate_flow

# Order matters only for display / ML matrices.
FEATURE_NAMES = [
    "packet_count",
    "byte_count",
    "duration",
    "bytes_per_second",
    "packets_per_second",
    "average_packet_size",
    "connection_count",
    "failed_connection_count",
    "failure_ratio",
    "syn_count",
    "rst_count",
    "syn_ratio",
    "unique_destination_ports",
    "unique_destination_ips",
    "connection_rate",
]


def safe_divide(numerator, denominator, default=0.0):
    """Division that never raises ZeroDivisionError (returns `default` instead)."""
    try:
        if denominator == 0:
            return default
        return numerator / denominator
    except (TypeError, ZeroDivisionError):
        return default


def extract_network_features(flow: dict, context: dict | None = None, validate: bool = True):
    """
    Compute detection features for one flow record.

    Parameters
    ----------
    flow     : raw or already-validated flow dict
    context  : optional {"unique_destination_ports": int, "unique_destination_ips": int}
    validate : run ids.validation.validate_flow first (default True).
               Raises FlowValidationError for unrecoverable input.

    Returns
    -------
    dict of feature_name -> float, plus a "data_quality_warnings" list.
    """
    warnings = []
    if validate:
        flow, warnings = validate_flow(flow)

    floor = FEATURE_CONFIG["rate_duration_floor_seconds"]
    context = context or {}

    packets = float(flow.get("packet_count", 0) or 0)
    byte_count = float(flow.get("byte_count", 0) or 0)
    duration = float(flow.get("duration_seconds", flow.get("duration", 0)) or 0)
    connections = float(flow.get("connection_count", 0) or 0)
    failed = float(flow.get("failed_connection_count", 0) or 0)
    syn = float(flow.get("syn_count", 0) or 0)
    rst = float(flow.get("rst_count", 0) or 0)

    # Rates use a duration floor: avoids division by zero AND avoids absurd
    # rates for sub-second flows.
    rate_window = max(duration, floor)

    features = {
        "packet_count": packets,
        "byte_count": byte_count,
        "duration": duration,
        "bytes_per_second": safe_divide(byte_count, rate_window),
        "packets_per_second": safe_divide(packets, rate_window),
        "average_packet_size": safe_divide(byte_count, packets),
        "connection_count": connections,
        "failed_connection_count": failed,
        "failure_ratio": min(1.0, safe_divide(failed, connections)),
        "syn_count": syn,
        "rst_count": rst,
        "syn_ratio": min(1.0, safe_divide(syn, packets)),
        # Diversity features come from the per-source window (default: this flow only).
        "unique_destination_ports": float(context.get("unique_destination_ports", 1)),
        "unique_destination_ips": float(context.get("unique_destination_ips", 1)),
        "connection_rate": safe_divide(connections, rate_window),
    }
    features = {k: round(v, 4) for k, v in features.items()}
    features["data_quality_warnings"] = warnings
    return features


class SourceWindowTracker:
    """
    Sliding-window memory of recent flows per source IP.

    For each source we keep (timestamp, destination_ip, destination_port)
    tuples from the last `window_seconds`. Thread-safe so the web backend can
    share one tracker across request threads.

    Note: the window is keyed on the flow's *event* timestamp, so replaying a
    historical dataset gives the same answers as live ingestion.
    """

    def __init__(self, window_seconds: int | None = None):
        self.window_seconds = window_seconds or FEATURE_CONFIG["source_window_seconds"]
        self._events = defaultdict(deque)
        self._lock = threading.Lock()

    def observe(self, flow: dict) -> dict:
        """Record the flow and return window context for its source."""
        ts = parse_timestamp(flow.get("timestamp"))
        epoch = ts.timestamp() if ts else 0.0
        src = flow.get("source_ip")
        with self._lock:
            events = self._events[src]
            events.append((epoch, flow.get("destination_ip"), flow.get("destination_port")))
            cutoff = epoch - self.window_seconds
            while events and events[0][0] < cutoff:
                events.popleft()
            # Filter again: out-of-order arrivals can leave stale items mid-queue.
            ports = {e[2] for e in events if e[0] >= cutoff}
            ips = {e[1] for e in events if e[0] >= cutoff}
        return {
            "unique_destination_ports": max(1, len(ports)),
            "unique_destination_ips": max(1, len(ips)),
            "window_flow_count": len(events),
        }

    def reset(self):
        with self._lock:
            self._events.clear()


def extract_features_for_records(records):
    """
    Run a list of flow dicts (any order) through the tracker + extractor.

    Records are processed in timestamp order so window features are correct.
    Returns a list of feature dicts in the ORIGINAL input order.
    """
    tracker = SourceWindowTracker()
    order = sorted(range(len(records)), key=lambda i: str(records[i].get("timestamp", "")))
    results = [None] * len(records)
    for i in order:
        clean, warnings = validate_flow(records[i])
        context = tracker.observe(clean)
        feats = extract_network_features(clean, context=context, validate=False)
        feats["data_quality_warnings"] = warnings
        results[i] = feats
    return results
