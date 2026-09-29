"""Time-range helpers shared by the dashboard and alert filters."""

from datetime import datetime, timedelta, timezone

from ids.validation import format_timestamp, parse_timestamp

RANGES = {
    "15m": timedelta(minutes=15),
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}

# Chart bucket size (seconds) for each range — keeps charts at ~60–100 points.
BUCKETS = {"15m": 30, "1h": 60, "6h": 300, "24h": 900, "7d": 10800, "30d": 43200}


def now_iso() -> str:
    return format_timestamp(datetime.now(timezone.utc))


def since_for_range(range_key: str | None):
    """Return the ISO lower bound for a range key, or None for 'all'."""
    if not range_key or range_key == "all":
        return None
    if range_key not in RANGES:
        raise ValueError(f"range must be one of: {', '.join(list(RANGES) + ['all'])}")
    return format_timestamp(datetime.now(timezone.utc) - RANGES[range_key])


def bucket_seconds_for(range_key: str | None, first_ts: str | None = None,
                       last_ts: str | None = None) -> int:
    if range_key in BUCKETS:
        return BUCKETS[range_key]
    if first_ts and last_ts:
        span = (parse_timestamp(last_ts) - parse_timestamp(first_ts)).total_seconds()
        return max(60, int(span // 80) // 60 * 60 or 60)
    return 900


def bucket_start(ts: str, bucket_seconds: int) -> int:
    epoch = int(parse_timestamp(ts).timestamp())
    return epoch - (epoch % bucket_seconds)


def epoch_to_iso(epoch: int) -> str:
    return format_timestamp(datetime.fromtimestamp(epoch, tz=timezone.utc))
