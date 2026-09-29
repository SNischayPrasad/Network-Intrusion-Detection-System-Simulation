"""Dataset generator and traffic-simulator safety tests."""

import ipaddress

from simulator.generate_dataset import COLUMNS, generate_dataset
from simulator.traffic_simulator import FlowSimulator, is_loopback_url

DOC_RANGES = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def test_dataset_generator(record_property):
    """TC-36 | Synthetic dataset generator | generate 5,000+ rows (seed 42) | Expected: >=5000 rows, all columns, both labels, only RFC 5737 IPs"""
    rows = generate_dataset(rows=5000, seed=42)
    labels = {r["label"] for r in rows}
    ips_ok = all(any(ipaddress.ip_address(r[f]) in n for n in DOC_RANGES)
                 for r in rows for f in ("source_ip", "destination_ip"))
    record_property("actual", f"rows={len(rows)}, labels={sorted(labels)}, "
                              f"scenarios={len({r['scenario_type'] for r in rows})}, doc-range IPs only={ips_ok}")
    assert len(rows) >= 5000 and labels == {"NORMAL", "SUSPICIOUS"} and ips_ok
    assert all(set(COLUMNS) <= set(r) for r in rows)


def test_simulator_safety(record_property):
    """TC-37 | Simulator safety | normal mode output + loopback URL guard | Expected: only NORMAL records; external URLs refused"""
    sim = FlowSimulator(mode="normal", seed=1)
    labels = {rec["label"] for _ in range(200) for rec in sim.next_batch()}
    allowed = [is_loopback_url(u) for u in ("http://127.0.0.1:8000/api/flows",
                                            "http://localhost:8000/api/flows",
                                            "http://example.com/api/flows",
                                            "http://8.8.8.8/api", "ftp://127.0.0.1/")]
    record_property("actual", f"labels={labels}, url checks={allowed}")
    assert labels == {"NORMAL"} and allowed == [True, True, False, False, False]
