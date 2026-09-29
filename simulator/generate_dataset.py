"""
Synthetic network-traffic dataset generator.

Creates data/network_traffic.csv with labelled flow records (NORMAL / SUSPICIOUS)
representing everyday traffic plus several suspicious statistical patterns.

SAFETY: this script only writes a CSV file. It never touches the network.

Usage (from the project root):
    python -m simulator.generate_dataset
    python -m simulator.generate_dataset --rows 10000 --suspicious-ratio 0.2 --seed 7
"""

import argparse
import csv
import math
import random
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:          # allow "python simulator/generate_dataset.py"
    sys.path.insert(0, str(PROJECT_ROOT))

from simulator.scenarios import (  # noqa: E402
    NORMAL_SCENARIOS,
    SUSPICIOUS_SCENARIOS,
    pick_weighted,
)

COLUMNS = [
    "flow_id", "timestamp", "source_ip", "destination_ip", "source_port",
    "destination_port", "protocol", "packet_count", "byte_count", "duration_seconds",
    "connection_count", "failed_connection_count", "syn_count", "rst_count",
    "average_packet_size", "label", "scenario_type",
]


def _diurnal_time(rng, start, hours):
    """Pick a timestamp weighted toward business hours (busier around 14:00)."""
    while True:
        offset = rng.uniform(0, hours * 3600)
        t = start + timedelta(seconds=offset)
        hour = t.hour + t.minute / 60
        weight = 0.25 + 0.75 * math.exp(-((hour - 14) ** 2) / (2 * 4 ** 2))
        if rng.random() < weight:
            return t


def generate_dataset(rows=6000, suspicious_ratio=0.18, seed=42,
                     start=datetime(2026, 9, 27, tzinfo=timezone.utc), hours=24):
    """Return a list of flow dicts sorted by time, with flow_ids assigned."""
    if rows < 100:
        raise ValueError("rows must be at least 100")
    if not 0 < suspicious_ratio < 0.9:
        raise ValueError("suspicious_ratio must be between 0 and 0.9")

    rng = random.Random(seed)
    target_suspicious = int(rows * suspicious_ratio)
    target_normal = rows - target_suspicious
    records = []

    # ---- Normal background traffic ------------------------------------------
    while sum(r["label"] == "NORMAL" for r in records) < target_normal:
        name = pick_weighted(rng, NORMAL_SCENARIOS)
        records.extend(NORMAL_SCENARIOS[name][0](rng, _diurnal_time(rng, start, hours)))

    # ---- Suspicious episodes -------------------------------------------------
    suspicious = []
    while len(suspicious) < target_suspicious:
        name = pick_weighted(rng, SUSPICIOUS_SCENARIOS)
        func = SUSPICIOUS_SCENARIOS[name][0]
        t = start + timedelta(seconds=rng.uniform(0, hours * 3600 - 600))
        if name == "MULTI_PORT_PROBING_PATTERN":
            suspicious.extend(func(rng, t))           # already a burst
            continue
        # An "episode": the same source repeats the behaviour a few times,
        # seconds apart — exactly what alert correlation should group.
        first = func(rng, t)[0]
        suspicious.append(first)
        for _ in range(rng.randint(0, 5)):
            t += timedelta(seconds=rng.uniform(3, 25))
            rec = func(rng, t)[0]
            rec["source_ip"], rec["destination_ip"] = first["source_ip"], first["destination_ip"]
            suspicious.append(rec)
    records.extend(suspicious[: target_suspicious + 40])  # keep whole bursts roughly intact

    records.sort(key=lambda r: r["timestamp"])
    for i, rec in enumerate(records, start=1):
        rec["flow_id"] = f"FLOW-{i:06d}"
    return records


def write_csv(records, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        writer.writeheader()
        for rec in records:
            writer.writerow({c: rec[c] for c in COLUMNS})


def main(argv=None):
    parser = argparse.ArgumentParser(description="Generate a synthetic network-flow dataset.")
    parser.add_argument("--rows", type=int, default=6000, help="approximate number of flows")
    parser.add_argument("--suspicious-ratio", type=float, default=0.18)
    parser.add_argument("--seed", type=int, default=42, help="random seed (reproducible)")
    parser.add_argument("--hours", type=int, default=24, help="time span of the dataset")
    parser.add_argument("--start", default="2026-09-27T00:00:00Z", help="ISO start time (UTC)")
    parser.add_argument("--output", default=str(PROJECT_ROOT / "data" / "network_traffic.csv"))
    args = parser.parse_args(argv)

    start = datetime.fromisoformat(args.start.replace("Z", "+00:00"))
    records = generate_dataset(args.rows, args.suspicious_ratio, args.seed, start, args.hours)
    write_csv(records, args.output)

    labels = Counter(r["label"] for r in records)
    scenarios = Counter(r["scenario_type"] for r in records)
    print(f"[+] Wrote {len(records)} synthetic flow records -> {args.output}")
    print(f"    Labels: {dict(labels)}")
    print("    Scenarios:")
    for name, count in scenarios.most_common():
        print(f"      {name:<30} {count:>5}")


if __name__ == "__main__":
    main()
