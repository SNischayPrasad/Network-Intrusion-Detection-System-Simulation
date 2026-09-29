# Incident Report — ALT-5CA4CB50

_Generated 2026-09-29T04:42:45.517Z by Network IDS Simulation. Synthetic data — for training only._

## 1. Summary

| Field | Value |
|---|---|
| Alert ID | ALT-5CA4CB50 |
| Incident (correlated group) | INC-E4D2243B |
| Detection | High Connection Rate (IDS-001) |
| Severity | **CRITICAL** |
| Final risk score | 87.9/100 |
| Status | RESOLVED |
| Event time | 2026-09-29T04:42:45.440Z |
| Detected at | 2026-09-29T04:42:44.561Z |
| Assigned to | analyst-user |

## 2. Network context

* **Source:** 203.0.113.202:51515
* **Destination:** 198.51.100.22:22 (TCP)
* **Packets / bytes:** 1,600 / 128,000
* **Duration:** 20.0 s
* **Connections (failed):** 400 (360)
* **SYN / RST:** 400 / 360
* **Unique destination ports from source (60 s window):** 1

## 3. Detection evidence

**Reason:** connection\_rate=20.0/s (threshold 10.0/s), connection\_count=400 (threshold 150)

* Signature score: 80.0
* Anomaly score: 86.4
* ML score: 100.0

| Rule | Severity | Evidence |
|---|---|---|
| IDS-001 High Connection Rate | HIGH | connection\_rate=20.0/s (threshold 10.0/s), connection\_count=400 (threshold 150) |
| IDS-002 Repeated Failed Connections | HIGH | failed\_connections=360 (threshold 10), failure\_ratio=0.90 (threshold 0.5) |

**Anomaly contributors (Z-score vs. baseline):** failure_ratio (z=6.26), connection_rate (z=5.58)

**Candidate ATT&CK mapping (unconfirmed):** TA0040 Impact / T1498 Network Denial of Service (requires corroborating evidence)

## 4. Timeline

* `2026-09-29T04:42:44.561Z` — **ALERT_CREATED** by ids-engine: High Connection Rate \| severity=CRITICAL risk=87.9
* `2026-09-29T04:42:45.463Z` — **STATUS_CHANGED** by analyst-user: NEW -\> INVESTIGATING
* `2026-09-29T04:42:45.494Z` — **NOTE_ADDED** by analyst-user: Reviewed synthetic auth logs: 360 failed SSH attempts from an unknown external source, no successful login. Source not in asset inventory.
* `2026-09-29T04:42:45.505Z` — **STATUS_CHANGED** by analyst-user: INVESTIGATING -\> RESOLVED \| Confirmed password-guessing pattern (simulated). Recommend blocking source at perimeter and enforcing key-based SSH. Closing.

## 5. Analyst notes

* `2026-09-29T04:42:45.494Z` [NOTE] analyst-user: Reviewed synthetic auth logs: 360 failed SSH attempts from an unknown external source, no successful login. Source not in asset inventory.
* `2026-09-29T04:42:45.505Z` [RESOLUTION] analyst-user: Confirmed password-guessing pattern (simulated). Recommend blocking source at perimeter and enforcing key-based SSH. Closing.

## 6. Recommended investigation steps

1. Check whether the destination service experienced degraded performance.
2. Identify whether many sources are involved (distributed) or a single one.
3. Confirm with the service owner whether a load test or batch job was scheduled.
4. Check whether the source IP is a known asset (CMDB / asset inventory) or an approved scanner / monitoring system.
5. Compare this activity with the source's historical baseline on the dashboard.
6. Review firewall and proxy records for the same source and time window.
7. Determine whether the activity is expected (change ticket, maintenance, new app).

---
_A detection indicates behaviour requiring investigation; it is not proof of malicious activity. This report was generated from synthetic data for defensive cybersecurity education._
