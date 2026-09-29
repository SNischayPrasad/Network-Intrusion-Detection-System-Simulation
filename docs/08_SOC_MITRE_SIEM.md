# 08 · SOC Workflow, MITRE ATT&CK Mapping & SIEM Integration

## 30. SOC analyst workflow
```
Network Event ─► IDS Detection ─► Alert ─► SOC Queue ─► Triage ─► Investigate Context
      ─► Determine Severity ─► Escalate / Resolve / False Positive ─► Document
```
| Stage | What happens | Where in this project |
|---|---|---|
| Network event | A flow is observed | `POST /api/flows` |
| IDS detection | Rules, anomaly and ML score the flow | `HybridIDSEngine.analyze()` |
| Alert | Risky flows become alerts with a reason | `generate_alert()` |
| SOC queue | Alerts wait, newest and highest risk first | **Alert Queue** page, filters |
| Triage | "Is this worth my time?" Check severity, risk and incident size | Queue columns, **Incidents** page |
| Investigate context | Evidence, baseline deviation, playbook steps, history of the source | Investigation page |
| Determine severity | Confirm or adjust the risk based on context | Risk breakdown and notes |
| Escalate / resolve / false positive | Change status (closure requires a note) | Status buttons |
| Document | Notes, timeline, incident report | Notes, audit log, **Download report** |

### Tier-1 SOC responsibilities
- Monitor the alert queue and dashboards continuously; acknowledge new alerts quickly (MTTA).
- Triage: separate noise from real signals using the playbooks and context.
- Perform first-level investigation: asset lookup, log review, and comparison with the baseline.
- Close false positives **with a reason**. That reason is data for tuning.
- Escalate confirmed or unclear high-severity cases to Tier 2 or incident response, with a clear write-up.
- Document everything: timestamps, what was checked, what was found.
- Report noisy rules to detection engineering.

### Demonstrating this project in a SOC interview (about 5 minutes)
1. **Dashboard (30 s):** "This is 24 hours of synthetic traffic. 6,018 flows, 21% suspicious, and here are the critical alerts."
2. **Queue (30 s):** filter to *High + Critical, New*.
3. **Investigate (2 min):**
   - Open a *Repeated Failed Connections* alert and read out the evidence ("360 of 400 failed, ratio 0.9").
   - Show the Z-score table.
   - Say what you would check next (authentication logs for a success after the failures, whether the source is in inventory).
4. **Act (1 min):** Start investigation → note → Resolve with a justification. Show the audit timeline and the report.
5. **False positive (1 min):** open a *High Traffic Volume* alert from the backup server and explain why it is benign, then mark it FALSE_POSITIVE. Mention the measured backup false-positive rate (81.5%) and how you would tune it (an allow-list for the backup server).

---

## 33. MITRE ATT&CK mapping (high level)

MITRE ATT&CK is a public knowledge base of adversary **tactics** (the *why*, e.g. Discovery, TA0007) and **techniques** (the *how*, e.g. Network Service Discovery, T1046).

**Important:** a statistical anomaly is **not** evidence of a specific technique. A burst of connections to many ports *could* be network service discovery, but it could also be a monitoring tool, a misconfigured client or an approved vulnerability scan. Mapping should happen **only when sufficient evidence exists**, usually after investigation. This project therefore labels every mapping as a **candidate (unconfirmed)**.

| Rule | Candidate tactic / technique | Would need to confirm |
|---|---|---|
| IDS-001 High Connection Rate | TA0040 Impact / T1498 Network Denial of Service | Service degradation; many sources; not a load test |
| IDS-002 Repeated Failed Connections | TA0006 Credential Access / T1110 Brute Force | Authentication logs show failed logins for accounts |
| IDS-003 Multi-Port Probing Pattern | TA0007 Discovery / T1046 Network Service Discovery | The source is not an authorised scanner |
| IDS-004 SYN-Heavy Behavior | TA0040 Impact / T1498 (or T1499 Endpoint Denial of Service) | Half-open backlog on the target, service impact |
| IDS-005 Unusual Service Port | TA0011 Command and Control / T1571 Non-Standard Port | The process on the host, destination reputation |
| IDS-006 High Traffic Volume | TA0010 Exfiltration / T1048 Exfiltration Over Alternative Protocol | What data moved; not a backup or sync |

How ATT&CK mapping helps:
- **Detection documentation:** each rule states which behaviour it is meant to catch, and coverage gaps become visible.
- **SOC investigation:** the candidate technique suggests the next questions and data sources.
- **Threat hunting:** hunters pick techniques and ask "would we detect this?"
- **Security reporting:** management sees coverage and trends in a common language.

---

## 34. SIEM integration (conceptual, no commercial SIEM required)
```
IDS ─► JSON Alert ─► Log Forwarder / API ─► SIEM ─► Correlation ─► SOC Analyst
```
- **Implemented:** when `IDS_SIEM_EXPORT_ENABLED=true`, every alert is appended as one JSON line to `logs/siem_alerts.jsonl` (`ids/siem_export.py`). A log shipper such as **Filebeat**, **Fluent Bit** or a **Splunk Universal Forwarder** can tail that file and forward it to **Elastic / OpenSearch**, **Wazuh**, **Splunk** or **Microsoft Sentinel**.
- **Pull option:** `GET /api/alerts/{id}/siem` returns the same event over the API.
- **Field names** follow the spirit of the Elastic Common Schema, so SIEM correlation rules can join IDS alerts with firewall, authentication and endpoint logs on `source.ip`.

Safe sample (generated by the project):
```json
{
  "@timestamp": "2026-09-29T04:19:46.798Z",
  "event.kind": "alert",
  "event.category": "network",
  "event.module": "network-ids-simulation",
  "event.severity_label": "HIGH",
  "event.risk_score": 78,
  "rule.id": "IDS-001",
  "rule.name": "High Connection Rate",
  "source.ip": "192.0.2.15",
  "source.port": 51515,
  "destination.ip": "198.51.100.20",
  "destination.port": 443,
  "network.transport": "tcp",
  "alert.id": "ALT-1001ABCD",
  "alert.status": "NEW",
  "message": "connection_rate=20.0/s (threshold 10.0/s)",
  "threat.candidate_mapping": "TA0040 Impact / T1498 Network Denial of Service"
}
```
**What the SIEM adds:**
- **Cross-source correlation:** for example, a failed-connection alert combined with a successful login in authentication logs means escalate.
- **Operations:** long-term retention, dashboards, case management and SOAR playbooks.
