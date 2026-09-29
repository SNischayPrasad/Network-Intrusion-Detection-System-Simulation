"""
Replay the synthetic dataset through the IDS engine into the SQLite database.

Timestamps are shifted so the dataset ENDS "now" — the dashboard's
"Last 24 hours" view is then populated immediately.

Usage (from the project root, backend NOT required to be running):
    python scripts/seed_database.py --reset
    python scripts/seed_database.py --limit 2000
"""

import argparse
import csv
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import Settings  # noqa: E402
from backend.models.database import Database  # noqa: E402
from backend.services.ids_service import DuplicateFlowError, IDSService  # noqa: E402
from backend.utils.time_utils import now_iso  # noqa: E402
from ids.config import get_default_rules  # noqa: E402
from ids.validation import format_timestamp, parse_timestamp  # noqa: E402

NUMERIC = ("source_port", "destination_port", "packet_count", "byte_count", "connection_count",
           "failed_connection_count", "syn_count", "rst_count")


def load_rows(path, limit=None):
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    rows.sort(key=lambda r: r["timestamp"])
    if limit:
        rows = rows[-limit:]                      # keep the most recent part of the day
    for r in rows:
        for k in NUMERIC:
            r[k] = int(r[k])
        r["duration_seconds"] = float(r["duration_seconds"])
        r["average_packet_size"] = float(r["average_packet_size"])
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description="Seed the IDS database from the synthetic CSV.")
    parser.add_argument("--csv", default=str(PROJECT_ROOT / "data" / "network_traffic.csv"))
    parser.add_argument("--limit", type=int, help="only replay the most recent N flows")
    parser.add_argument("--reset", action="store_true", help="delete the existing database first")
    parser.add_argument("--no-shift", action="store_true", help="keep original timestamps")
    args = parser.parse_args(argv)

    settings = Settings()
    settings.siem_export_enabled = False          # don't flood the SIEM file while seeding
    if args.reset:
        for suffix in ("", "-wal", "-shm"):
            p = Path(str(settings.db_path) + suffix)
            if p.exists():
                p.unlink()
        print(f"[*] Removed existing database {settings.db_path}")

    if not Path(args.csv).exists():
        print(f"[!] {args.csv} not found. Run: python -m simulator.generate_dataset")
        return 1

    db = Database(settings.db_path)
    db.init_schema()
    db.seed_rules(get_default_rules(), now_iso())
    service = IDSService(settings, db)

    rows = load_rows(args.csv, args.limit)
    shift = timedelta(0)
    if not args.no_shift:
        last = parse_timestamp(rows[-1]["timestamp"])
        shift = (datetime.now(timezone.utc) - timedelta(minutes=2)) - last

    started = time.perf_counter()
    for row in rows:
        row["timestamp"] = format_timestamp(parse_timestamp(row["timestamp"]) + shift)

    # Batch ML scoring: one vectorised call is ~100x faster than 6,000 single calls.
    ml_probs = [None] * len(rows)
    if service.engine.ml_enabled:
        from ids.feature_extractor import extract_features_for_records
        from ml.data_prep import feature_matrix
        feats = extract_features_for_records(rows)
        ml_probs = service.engine.ml_detector.model.predict_proba(feature_matrix(feats))[:, 1]

    counts, alerts, dupes = {}, 0, 0
    for i, row in enumerate(rows, 1):
        try:
            result = service.process_flow(row, actor="seed-script", role="system",
                                          ml_probability=None if ml_probs[i - 1] is None
                                          else float(ml_probs[i - 1]))
        except DuplicateFlowError:
            dupes += 1
            continue
        counts[result["classification"]] = counts.get(result["classification"], 0) + 1
        alerts += result["alert"] is not None
        if i % 500 == 0:
            print(f"    processed {i}/{len(rows)} flows ...")

    elapsed = time.perf_counter() - started
    print(f"[+] Seeded {sum(counts.values())} flows in {elapsed:.1f}s "
          f"({sum(counts.values()) / max(elapsed, 1e-9):.0f} flows/s) | ML "
          f"{'enabled' if service.engine.ml_enabled else 'disabled'}")
    print(f"    Classifications: {counts}")
    print(f"    Alerts raised:   {alerts}   Duplicates skipped: {dupes}")
    print(f"    Database:        {settings.db_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
