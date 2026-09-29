"""
Real-time synthetic traffic simulator.

Continuously generates synthetic network-flow EVENTS (JSON data) and either
prints them or POSTs them to YOUR LOCAL IDS backend for analysis.

SAFETY GUARANTEES
  * No packets are generated or sent — only JSON descriptions of flows.
  * --post only accepts loopback URLs (localhost / 127.0.0.1 / ::1).
    The simulator refuses to send data to any other host.

Examples (from the project root):
    # Print normal traffic to the console, slowly
    python -m simulator.traffic_simulator --mode normal --speed slow

    # Stream mixed traffic into the local backend
    python -m simulator.traffic_simulator --mode mixed --speed fast --post http://127.0.0.1:8000/api/flows

    # Inject a single named scenario (useful for demos)
    python -m simulator.traffic_simulator --scenario multi_port --post http://127.0.0.1:8000/api/flows
"""

import argparse
import ipaddress
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from simulator.scenarios import (  # noqa: E402
    ALL_SCENARIOS,
    NORMAL_SCENARIOS,
    SCENARIO_ALIASES,
    SUSPICIOUS_SCENARIOS,
    generate,
    pick_weighted,
)

SPEEDS = {"slow": 2.0, "medium": 1.0, "fast": 0.25}  # seconds between events


def is_loopback_url(url: str) -> bool:
    """Only allow http(s) URLs that point at this machine."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    host = parsed.hostname
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class FlowSimulator:
    def __init__(self, mode="mixed", suspicious_ratio=0.15, seed=None):
        if mode not in ("normal", "mixed"):
            raise ValueError("mode must be 'normal' or 'mixed'")
        self.mode = mode
        self.suspicious_ratio = suspicious_ratio
        self.rng = random.Random(seed)

    def next_batch(self, scenario=None):
        """Return the next list of flow records (bursts return several)."""
        now = datetime.now(timezone.utc)
        if scenario:
            records = generate(self.rng, scenario, now)
        elif self.mode == "mixed" and self.rng.random() < self.suspicious_ratio:
            records = generate(self.rng, pick_weighted(self.rng, SUSPICIOUS_SCENARIOS), now)
        else:
            records = generate(self.rng, pick_weighted(self.rng, NORMAL_SCENARIOS), now)
        for rec in records:
            rec["flow_id"] = f"SIM-{uuid.uuid4().hex[:12].upper()}"
        return records


def post_flow(url, flow, api_key, timeout=5):
    """POST one flow to the local backend and return the parsed JSON response."""
    body = json.dumps(flow).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json",
        "X-API-Key": api_key,
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (loopback only)
        return json.loads(resp.read().decode("utf-8"))


def _summary(flow):
    return (f"{flow['timestamp']}  {flow['source_ip']:>15}:{flow['source_port']:<5} -> "
            f"{flow['destination_ip']:>15}:{flow['destination_port']:<5} {flow['protocol']:<4} "
            f"pkts={flow['packet_count']:<6} bytes={flow['byte_count']:<11} "
            f"conns={flow['connection_count']:<4} failed={flow['failed_connection_count']:<4} "
            f"[{flow['scenario_type']}]")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Synthetic network-flow simulator (data only).")
    parser.add_argument("--mode", choices=["normal", "mixed"], default="mixed")
    parser.add_argument("--speed", choices=list(SPEEDS), default="medium")
    parser.add_argument("--interval", type=float, help="override seconds between events")
    parser.add_argument("--count", type=int, default=0, help="number of batches (0 = run forever)")
    parser.add_argument("--suspicious-ratio", type=float, default=0.15)
    parser.add_argument("--scenario", help="emit a specific scenario: " +
                        ", ".join(sorted(set(SCENARIO_ALIASES) | set(ALL_SCENARIOS))))
    parser.add_argument("--post", metavar="URL", help="POST flows to a LOCAL backend URL")
    parser.add_argument("--api-key", default=os.getenv("IDS_SENSOR_KEY", "sensor-dev-key-change-me"))
    parser.add_argument("--json", action="store_true", help="print full JSON instead of summaries")
    parser.add_argument("--seed", type=int)
    args = parser.parse_args(argv)

    if args.post and not is_loopback_url(args.post):
        parser.error("For safety, --post only accepts localhost / 127.0.0.1 / ::1 URLs.")

    interval = args.interval if args.interval is not None else SPEEDS[args.speed]
    count = args.count or (1 if args.scenario else 0)
    sim = FlowSimulator(args.mode, args.suspicious_ratio, args.seed)

    print(f"[*] Synthetic traffic simulator | mode={args.mode} interval={interval}s "
          f"target={'LOCAL API ' + args.post if args.post else 'stdout'}  (Ctrl+C to stop)")
    sent = 0
    try:
        while count == 0 or sent < count:
            for flow in sim.next_batch(args.scenario):
                print(json.dumps(flow) if args.json else _summary(flow))
                if args.post:
                    try:
                        result = post_flow(args.post, flow, args.api_key)
                        alert = result.get("alert")
                        print(f"      -> {result['classification']:<19} risk={result['risk_score']:<5}"
                              + (f" ALERT {alert['alert_id']} {alert['severity']} "
                                 f"{alert['alert_type']}" if alert else ""))
                    except urllib.error.HTTPError as exc:
                        print(f"      !! backend rejected flow: HTTP {exc.code} "
                              f"{exc.read().decode('utf-8', 'replace')[:200]}")
                    except urllib.error.URLError as exc:
                        print(f"      !! backend unreachable ({exc.reason}). Is it running?")
                        return 1
                    time.sleep(min(interval, 0.05))   # small gap inside bursts
            sent += 1
            if count == 0 or sent < count:
                time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[*] Simulator stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
