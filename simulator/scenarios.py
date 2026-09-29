"""
Synthetic network-flow scenarios.

╔══════════════════════════════════════════════════════════════════════════╗
║ SAFETY: every function in this module returns Python dictionaries that    ║
║ DESCRIBE network flows. No sockets are opened and no packets are sent.    ║
║ All IP addresses come from the documentation-only ranges reserved by      ║
║ RFC 5737, which are never routed on the public Internet:                  ║
║     192.0.2.0/24     (TEST-NET-1)  -> our "internal clients"              ║
║     198.51.100.0/24  (TEST-NET-2)  -> our "internal servers"              ║
║     203.0.113.0/24   (TEST-NET-3)  -> "external" hosts                    ║
╚══════════════════════════════════════════════════════════════════════════╝

Each scenario function has the signature

    scenario(rng: random.Random, start: datetime) -> list[dict]

and returns ONE OR MORE flow records (probing-like patterns are bursts of many
small records, because that is how they appear in real flow logs).

Realism notes (these deliberately create imperfect detection, like real life):
* Some NORMAL traffic looks unusual (large backups, busy proxies, a mistyped
  password) -> produces genuine false positives.
* Some SUSPICIOUS traffic is "low and slow" (just under rule thresholds)
  -> produces genuine false negatives for rule-only detection.
"""

import random
from datetime import datetime, timedelta

from ids.validation import format_timestamp

# ---------------------------------------------------------------------------
# Address plan (documentation ranges only)
# ---------------------------------------------------------------------------
CLIENTS = [f"192.0.2.{i}" for i in range(10, 121)]
WEB_SERVERS = [f"198.51.100.{i}" for i in range(10, 20)]
DNS_SERVER = "198.51.100.53"
MAIL_SERVER = "198.51.100.25"
SSH_BASTION = "198.51.100.22"
DB_SERVERS = [f"198.51.100.{i}" for i in range(40, 46)]
BACKUP_SERVER = "198.51.100.70"
EXTERNAL_USERS = [f"203.0.113.{i}" for i in range(10, 100)]
EXTERNAL_SUSPECTS = [f"203.0.113.{i}" for i in range(150, 251)]
INTERNAL_SUSPECTS = [f"192.0.2.{i}" for i in range(200, 211)]

WATCHLIST_DEST_PORTS = [23, 2323, 4444, 5555, 6667, 1337, 31337, 12345]
PROBE_PORT_POOL = sorted(set(list(range(1, 1025)) + [1433, 1521, 2049, 3306, 3389, 5432,
                                                      5900, 6379, 8000, 8080, 8443, 9200]))


def _ephemeral(rng):
    return rng.randint(49152, 65535)


def _flow(start, src, dst, sport, dport, proto, packets, byte_count, duration,
          conns, failed, syn, rst, label, scenario):
    packets = max(1, int(packets))
    byte_count = max(packets * 40, int(byte_count))  # minimum realistic header size
    return {
        "timestamp": format_timestamp(start),
        "source_ip": src,
        "destination_ip": dst,
        "source_port": int(sport),
        "destination_port": int(dport),
        "protocol": proto,
        "packet_count": packets,
        "byte_count": byte_count,
        "duration_seconds": round(max(0.0, duration), 3),
        "connection_count": int(conns),
        "failed_connection_count": int(min(failed, conns)),
        "syn_count": int(syn),
        "rst_count": int(rst),
        "average_packet_size": round(byte_count / packets, 2),
        "label": label,
        "scenario_type": scenario,
    }


# ===========================================================================
# NORMAL scenarios
# ===========================================================================
def normal_web(rng, start):
    """Everyday HTTPS/HTTP browsing from internal clients or external customers."""
    src = rng.choice(CLIENTS) if rng.random() < 0.8 else rng.choice(EXTERNAL_USERS)
    dport = rng.choices([443, 80, 8080], weights=[80, 17, 3])[0]
    variant = rng.random()
    if variant < 0.03:
        # A refused connection (service down / wrong port): tiny, 1 failure.
        return [_flow(start, src, rng.choice(WEB_SERVERS), _ephemeral(rng), dport, "TCP",
                      rng.randint(1, 2), rng.randint(40, 120), rng.uniform(0, 0.05),
                      1, 1, 1, 1, "NORMAL", "NORMAL_WEB")]
    if variant < 0.07:
        # Busy page with many parallel requests (a legitimately "noisy" client).
        conns = rng.randint(20, 90)
        duration = rng.uniform(8, 60)
    else:
        conns = rng.randint(1, 6)
        duration = rng.lognormvariate(1.2, 1.0)
    packets = conns * rng.randint(6, 40)
    avg = rng.uniform(300, 1300)
    failed = 1 if rng.random() < 0.05 else 0
    return [_flow(start, src, rng.choice(WEB_SERVERS), _ephemeral(rng), dport, "TCP",
                  packets, packets * avg, min(duration, 600), conns, failed,
                  conns + rng.randint(0, 1), rng.randint(0, 1) + failed,
                  "NORMAL", "NORMAL_WEB")]


def normal_dns(rng, start):
    """Short UDP request/response pairs to the internal resolver."""
    src = rng.choice(CLIENTS)
    packets = rng.choice([2, 2, 2, 4])
    failed = 1 if rng.random() < 0.01 else 0
    return [_flow(start, src, DNS_SERVER, _ephemeral(rng), 53, "UDP",
                  packets, packets * rng.uniform(60, 250), rng.uniform(0.005, 0.3),
                  1, failed, 0, 0, "NORMAL", "NORMAL_DNS")]


def normal_ssh(rng, start):
    """Administrator SSH sessions to the bastion host (long, interactive)."""
    src = rng.choice(CLIENTS[:20])  # only a few admins use SSH
    duration = rng.uniform(5, 3600)
    packets = int(duration * rng.uniform(0.5, 6)) + 20
    failed = 1 if rng.random() < 0.04 else 0   # a mistyped password happens
    conns = 1 + failed
    return [_flow(start, src, SSH_BASTION, _ephemeral(rng), 22, "TCP",
                  packets, packets * rng.uniform(80, 400), duration, conns, failed,
                  conns, failed, "NORMAL", "NORMAL_SSH")]


def normal_email(rng, start):
    """Mail submission / retrieval to the internal mail server."""
    src = rng.choice(CLIENTS)
    dport = rng.choice([25, 587, 993])
    conns = rng.randint(1, 3)
    packets = rng.randint(10, 400)
    return [_flow(start, src, MAIL_SERVER, _ephemeral(rng), dport, "TCP",
                  packets, packets * rng.uniform(200, 1200), rng.uniform(0.5, 30),
                  conns, 0, conns, 0, "NORMAL", "NORMAL_EMAIL")]


def normal_database(rng, start):
    """Application servers talking to databases (connection pooling)."""
    src = rng.choice(WEB_SERVERS)
    dport = rng.choice([5432, 3306])
    conns = rng.randint(1, 12)
    packets = rng.randint(10, 2000)
    return [_flow(start, src, rng.choice(DB_SERVERS), _ephemeral(rng), dport, "TCP",
                  packets, packets * rng.uniform(100, 900), rng.uniform(0.1, 120),
                  conns, 0, conns, 0, "NORMAL", "NORMAL_DATABASE")]


def normal_bulk_transfer(rng, start):
    """Nightly backups: huge but legitimate. A classic false-positive source."""
    src = rng.choice(DB_SERVERS)
    byte_count = rng.uniform(150e6, 2.5e9)
    duration = rng.uniform(120, 1200)
    packets = byte_count / 1400
    return [_flow(start, src, BACKUP_SERVER, _ephemeral(rng), rng.choice([873, 22]), "TCP",
                  packets, byte_count, duration, 1, 0, 1, 0,
                  "NORMAL", "NORMAL_BULK_TRANSFER")]


# ===========================================================================
# SUSPICIOUS scenarios (statistical patterns represented as DATA)
# ===========================================================================
def _suspect_source(rng):
    return rng.choice(EXTERNAL_SUSPECTS) if rng.random() < 0.8 else rng.choice(INTERNAL_SUSPECTS)


def high_connection_rate(rng, start):
    """Unusually high connection frequency toward a web service."""
    conns = rng.randint(120, 800)
    duration = rng.uniform(5, 40)
    packets = conns * rng.randint(3, 8)
    failed = int(conns * rng.uniform(0.0, 0.2))
    return [_flow(start, _suspect_source(rng), rng.choice(WEB_SERVERS), _ephemeral(rng),
                  rng.choice([80, 443]), "TCP", packets, packets * rng.uniform(60, 200),
                  duration, conns, failed, conns, failed,
                  "SUSPICIOUS", "HIGH_CONNECTION_RATE")]


def repeated_failed_connections(rng, start):
    """Many failed attempts to a login-type service (password-guessing-like)."""
    if rng.random() < 0.2:
        conns = rng.randint(4, 12)                    # "low and slow" variant
        failed = max(3, int(conns * rng.uniform(0.6, 0.95)))
    else:
        conns = rng.randint(12, 120)
        failed = int(conns * rng.uniform(0.6, 0.98))
    dport = rng.choice([22, 22, 3389, 445, 21])
    dst = SSH_BASTION if dport == 22 else rng.choice(WEB_SERVERS + DB_SERVERS)
    packets = conns * rng.randint(3, 6)
    return [_flow(start, _suspect_source(rng), dst, _ephemeral(rng), dport, "TCP",
                  packets, packets * rng.uniform(60, 140), rng.uniform(10, 120),
                  conns, failed, conns, failed,
                  "SUSPICIOUS", "REPEATED_FAILED_CONNECTIONS")]


def multi_port_probing(rng, start, n_ports=None):
    """
    One source touching many destination ports in a short time.
    Emitted as a BURST of tiny records (one per port) — individually each record
    looks like a harmless refused connection; the pattern only appears when the
    IDS aggregates by source over a time window.
    """
    src, dst = _suspect_source(rng), rng.choice(WEB_SERVERS + DB_SERVERS)
    n_ports = n_ports or rng.randint(15, 40)
    ports = rng.sample(PROBE_PORT_POOL, n_ports)
    records, ts = [], start
    for port in ports:
        open_port = rng.random() < 0.12
        records.append(_flow(ts, src, dst, _ephemeral(rng), port, "TCP",
                             3 if open_port else rng.randint(1, 2),
                             rng.randint(40, 180), rng.uniform(0, 0.05), 1,
                             0 if open_port else 1, 1, 1,
                             "SUSPICIOUS", "MULTI_PORT_PROBING_PATTERN"))
        ts += timedelta(seconds=rng.uniform(0.2, 2.0))
    return records


def syn_heavy(rng, start):
    """Mostly SYN packets with few completed handshakes (half-open pattern)."""
    packets = rng.randint(300, 5000)
    syn = int(packets * rng.uniform(0.75, 0.98))
    conns = int(syn * rng.uniform(0.5, 1.0))
    failed = int(conns * rng.uniform(0.7, 0.99))
    return [_flow(start, _suspect_source(rng), rng.choice(WEB_SERVERS), _ephemeral(rng),
                  rng.choice([80, 443]), "TCP", packets, packets * rng.uniform(54, 70),
                  rng.uniform(2, 30), conns, failed, syn, rng.randint(0, packets // 20),
                  "SUSPICIOUS", "SYN_HEAVY_PATTERN")]


def unusual_port_activity(rng, start):
    """Internal host talking to an external host on a watch-listed port."""
    if rng.random() < 0.2:
        # External source reaching RDP directly.
        src, dst, dport = rng.choice(EXTERNAL_SUSPECTS), rng.choice(WEB_SERVERS), 3389
    else:
        src = rng.choice(INTERNAL_SUSPECTS + CLIENTS[-10:])
        dst, dport = rng.choice(EXTERNAL_SUSPECTS), rng.choice(WATCHLIST_DEST_PORTS)
    packets = rng.randint(5, 60)
    conns = rng.randint(1, 3)
    return [_flow(start, src, dst, _ephemeral(rng), dport, "TCP",
                  packets, packets * rng.uniform(60, 400), rng.uniform(1, 300),
                  conns, 0, conns, 0, "SUSPICIOUS", "UNUSUAL_PORT_ACTIVITY")]


def high_traffic_volume(rng, start):
    """Internal host sending an abnormally large volume to an external host."""
    byte_count = rng.uniform(4e8, 5e9)
    duration = rng.uniform(60, 900)
    return [_flow(start, rng.choice(CLIENTS + INTERNAL_SUSPECTS), rng.choice(EXTERNAL_SUSPECTS),
                  _ephemeral(rng), rng.choice([443, 8443, 21]), "TCP",
                  byte_count / 1400, byte_count, duration, 1, 0, 1, 0,
                  "SUSPICIOUS", "HIGH_TRAFFIC_VOLUME")]


# ---------------------------------------------------------------------------
# Registries
# ---------------------------------------------------------------------------
NORMAL_SCENARIOS = {
    "NORMAL_WEB": (normal_web, 45),
    "NORMAL_DNS": (normal_dns, 25),
    "NORMAL_SSH": (normal_ssh, 7),
    "NORMAL_EMAIL": (normal_email, 8),
    "NORMAL_DATABASE": (normal_database, 13),
    "NORMAL_BULK_TRANSFER": (normal_bulk_transfer, 2),
}

SUSPICIOUS_SCENARIOS = {
    "HIGH_CONNECTION_RATE": (high_connection_rate, 18),
    "REPEATED_FAILED_CONNECTIONS": (repeated_failed_connections, 22),
    "MULTI_PORT_PROBING_PATTERN": (multi_port_probing, 3),   # each call = a burst
    "SYN_HEAVY_PATTERN": (syn_heavy, 14),
    "UNUSUAL_PORT_ACTIVITY": (unusual_port_activity, 20),
    "HIGH_TRAFFIC_VOLUME": (high_traffic_volume, 11),
}

ALL_SCENARIOS = {**NORMAL_SCENARIOS, **SUSPICIOUS_SCENARIOS}

# Friendly CLI aliases -> scenario names (used by traffic_simulator --scenario)
SCENARIO_ALIASES = {
    "https": "NORMAL_WEB", "web": "NORMAL_WEB", "dns": "NORMAL_DNS", "ssh": "NORMAL_SSH",
    "email": "NORMAL_EMAIL", "database": "NORMAL_DATABASE", "backup": "NORMAL_BULK_TRANSFER",
    "high_rate": "HIGH_CONNECTION_RATE", "failed": "REPEATED_FAILED_CONNECTIONS",
    "multi_port": "MULTI_PORT_PROBING_PATTERN", "syn": "SYN_HEAVY_PATTERN",
    "unusual_port": "UNUSUAL_PORT_ACTIVITY", "volume": "HIGH_TRAFFIC_VOLUME",
}


def pick_weighted(rng, registry):
    names = list(registry)
    weights = [registry[n][1] for n in names]
    return rng.choices(names, weights=weights)[0]


def generate(rng: random.Random, scenario_name: str, start: datetime):
    """Generate records for a named scenario (accepts aliases)."""
    name = SCENARIO_ALIASES.get(scenario_name.lower(), scenario_name.upper())
    if name not in ALL_SCENARIOS:
        raise ValueError(f"Unknown scenario {scenario_name!r}. "
                         f"Choose from: {', '.join(sorted(ALL_SCENARIOS))}")
    return ALL_SCENARIOS[name][0](rng, start)


def fixed_https_example(start):
    """Deterministic 'Scenario A' record used in docs and the demo walkthrough."""
    return _flow(start, "192.0.2.15", "198.51.100.20", 49152, 443, "TCP",
                 18, 12400, 2.8, 3, 0, 2, 0, "NORMAL", "NORMAL_WEB")
