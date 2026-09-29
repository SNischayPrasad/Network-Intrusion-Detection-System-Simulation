# Project Report: Network Intrusion Detection System (IDS) Simulation

**Course:** Cybersecurity · **Author:** Nischay · **Type:** Defensive security project (synthetic data only)

---

## Abstract
This project designs, implements and evaluates a network-based hybrid intrusion detection system (IDS) that operates entirely on synthetic network-flow data.

- **Data:** a generator produces 6,019 labelled flows covering six normal traffic types and six suspicious behaviour patterns, using only RFC 5737 documentation IP addresses.
- **Detection:** each flow is validated, converted into 15 behavioural features and scored by three detectors: six configurable signature rules, a statistical anomaly detector (log-scale Z-scores with IQR confirmation) and an optional Random Forest classifier.
- **Risk and alerting:** a weighted risk engine with evidence-preserving floors fuses the scores into a 0–100 risk and a classification (NORMAL, SUSPICIOUS or POTENTIAL_INTRUSION). Risky flows become alerts with evidence and defensive playbooks, and are correlated into incidents.
- **Operations:** a FastAPI service with role-based access control persists all events in SQLite, and a React SOC console supports monitoring, investigation and incident management.
- **Results:** on a stratified held-out test set of 1,505 flows, recall rose from 0.855 (rules alone) to 0.971 (rules + anomaly) and 0.996 (rules + anomaly + ML), at a false-positive rate of 4.0%. The dominant false-positive source was legitimate bulk backups.
- **Verification:** 37 automated tests verify functional, security and safety requirements.

## 1. Introduction
Networks carry a mix of legitimate and malicious activity. Perimeter controls such as firewalls decide which connections are allowed, but many attacks use allowed paths. Intrusion detection systems provide the visibility needed to notice suspicious behaviour and enable a human-led response. This project reproduces the essential components of a modern IDS and SOC workflow in a form that is safe, reproducible and suitable for education.

## 2. Problem Statement
Build an explainable IDS that:
- detects multiple classes of suspicious network behaviour;
- quantifies its own accuracy honestly;
- controls false positives;
- supports the full analyst workflow from alert to documented resolution.

All of this must be done without real networks, real attack traffic or any offensive capability.

## 3. Objectives
1. Generate realistic, labelled, safe synthetic flow data and a real-time simulator.
2. Engineer robust security features, with handling for malformed and missing input.
3. Implement signature, anomaly and ML detection, and fuse them with a configurable risk model.
4. Generate, prioritise and correlate alerts.
5. Provide a SOC dashboard, investigation page and incident workflow.
6. Evaluate with precision, recall, F1, FPR and confusion matrices, and test the system automatically.
7. Apply secure-coding practices throughout.

## 4. Network Security Background
Network communication is carried in packets identified by IP addresses, ports and protocols (TCP, UDP, ICMP). TCP connections begin with a SYN, SYN-ACK, ACK handshake, and refused connections are commonly answered with RST. A *flow* aggregates the packets of one conversation, keyed by the 5-tuple, into counters (packets, bytes, duration, flags). Flow telemetry (NetFlow, IPFIX, Zeek conn logs) is the basis of scalable monitoring. It avoids storing payloads and still works with encrypted traffic.

## 5. Intrusion Detection Systems
- An IDS detects and alerts. An IPS additionally blocks inline.
- Network IDS (NIDS) sensors observe traffic across many hosts. Host IDS (HIDS) agents observe one host's logs and files.
- Detection strategies are signature-based (known patterns), anomaly-based (deviation from normal) and hybrid.
- Outputs are *alerts*, which analysts triage; related alerts form *incidents*.

## 6. Existing Approaches
| Approach | Examples | Strengths | Weaknesses |
|---|---|---|---|
| Signature NIDS | Snort, Suricata | Precise, explainable, fast | Misses novel or variant behaviour; rule maintenance |
| Flow / behaviour analytics | Zeek scripts, NetFlow analysers | Scalable, payload-free | Coarser visibility |
| Statistical anomaly detection | baselining, Z-score, EWMA | Detects unknown behaviour | False positives, baseline poisoning |
| ML-based IDS | supervised classifiers, Isolation Forest, autoencoders | Learns multi-feature patterns | Needs labels, drift, explainability |
| SIEM correlation | Splunk, Elastic, Sentinel, Wazuh | Cross-source context | Depends on the quality of its inputs |

This project combines the first four ideas and exports to the fifth.

## 7. Proposed System
A hybrid, flow-based IDS with three independent detectors and an explicit risk-fusion stage. It includes:
- an analyst-facing alert model (reason, evidence, playbook, candidate ATT&CK mapping);
- correlation into incidents;
- a secured REST API and a SOC console;
- a reproducible evaluation harness that measures every detection layer on the same held-out data.

## 8. Architecture
Synthetic generator/simulator → flow collector (validation) → feature extractor (with a per-source 60 s window) → {rule engine, anomaly detector, ML model} → risk engine → alert engine → correlation → SQLite (plus SIEM JSONL) → REST API → React dashboard → analyst. See [docs/02_ARCHITECTURE.md](../docs/02_ARCHITECTURE.md) for the diagram and component responsibilities.

## 9. Synthetic Dataset
- **Size and balance:** 6,019 flows over a simulated 24 hours with a business-hours curve. 81.7% are NORMAL and 18.3% SUSPICIOUS.
- **Normal traffic:** web (2,189), DNS (1,259), database (668), email (367), SSH (339) and bulk backups (98).
- **Suspicious patterns:** multi-port probing bursts (306), unusual ports (191), repeated failed connections (190), high connection rate (187), high volume (115) and SYN-heavy (110).
- **Realistic difficulty:** difficult cases are included on purpose, such as legitimate backups, busy clients, mistyped passwords and "low and slow" guessing, so the detection is realistically imperfect.
- **Safety:** addresses come only from 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24.

## 10. Traffic Simulation
The simulator emits flow events continuously in `normal` or `mixed` mode at configurable speeds, or injects a named scenario. It either prints JSON or POSTs to the local API. For safety, it refuses any non-loopback destination (unit-tested). In a live test it streamed 202 flows, which produced 91 alerts with 0 errors.

## 11. Feature Engineering
Fifteen features are computed per flow:
- **Volume and time:** packet_count, byte_count, duration.
- **Rates:** bytes_per_second, packets_per_second and connection_rate, each over max(duration, 1 s).
- **Sizes and ratios:** average_packet_size, failure_ratio, syn_ratio.
- **Counters:** connection_count, failed_connection_count, syn_count, rst_count.
- **Diversity:** unique destination ports and IPs per source in a 60 s event-time window.

Malformed IPs, invalid ports and unsupported protocols are rejected. Missing or negative counters are imputed and flagged as data-quality warnings. Division by zero is impossible by construction.

## 12. Signature Detection
Six rules: IDS-001 high connection rate, IDS-002 repeated failed connections, IDS-003 multi-port probing, IDS-004 SYN-heavy, IDS-005 watch-listed port, IDS-006 high volume.
- Thresholds are stored as data, editable by administrators, validated, audited and hot-reloaded.
- A match produces human-readable evidence.
- The signature score is the highest matched severity (50/75/90) plus 5 per additional rule.

## 13. Anomaly Detection
A baseline of mean, standard deviation, Q1 and Q3 is fitted on 3,690 normal training flows, in log space, for five metrics. Deviations are scored as follows:
- Each metric's Z-score maps linearly from z = 2 (score 0) to z = 6 (score 100).
- Standard-deviation floors apply to near-constant metrics.
- Values beyond Tukey's outer fence (Q3 + 3·IQR) add confirmation points.
- Final score = 0.7 × worst metric + 0.3 × mean metric.

Per-metric explanations are shown to the analyst. An optional EWMA adaptive baseline exists but is disabled by default because of poisoning risk.

## 14. Machine Learning
- **Features:** the 10 specified features, with log1p scaling.
- **Split:** stratified 75/25 train/test (seed 42).

| Model | Type | Precision | Recall | F1 | FPR | ROC-AUC |
|---|---|---|---|---|---|---|
| Logistic Regression | Supervised | 0.812 | 0.956 | 0.878 | 5.0% | 0.985 |
| Random Forest | Supervised | 0.865 | 0.975 | 0.916 | 3.4% | 0.996 |
| Isolation Forest | Unsupervised | 0.579 | 0.975 | 0.726 | 15.9% | 0.968 |

The Random Forest was selected for the hybrid engine. Its most important features were failed_connection_count (0.184), bytes_per_second (0.150) and average_packet_size (0.145).

## 15. Hybrid Detection
Risk = 0.4·signature + 0.3·anomaly + 0.3·ML (or 0.6/0.4 without ML). The weights are configurable.

The evaluation revealed two flaws in the initial design, and a floor was added for each:
1. **Rule dilution.** Averaging diluted MEDIUM rule matches below the alert threshold, so the hybrid had lower recall than rules alone (0.676 vs 0.855). *Fix:* a rule-severity floor.
2. **Anomaly ceiling.** The anomaly detector alone could contribute at most 40 points and could never raise an alert. *Fix:* a single-confident-detector floor (anomaly ≥ 75 or ML ≥ 85% → 41).

## 16. Risk Scoring
Bands: 0–20 NORMAL, 21–40 LOW RISK, 41–60 SUSPICIOUS, 61–80 HIGH RISK, 81–100 CRITICAL INVESTIGATION. These map to alert severities INFO through CRITICAL, and to the classifications NORMAL (0–40), SUSPICIOUS (41–80) and POTENTIAL_INTRUSION (81–100). These thresholds are project assumptions that a real SOC would calibrate.

## 17. Alert Generation
An alert is raised when any rule matches or the risk is ≥ 41. Each alert contains:
- identifiers, network context and the primary rule;
- all matched rules with evidence, the per-layer scores and the final risk;
- a reason, a description and a candidate ATT&CK mapping (explicitly unconfirmed);
- a defensive investigation playbook.

## 18. Alert Correlation
Alerts sharing a source IP and alert type within a sliding 60 s window form an incident, which records first and last seen, alert count, maximum severity and maximum risk. In testing, a burst of 100 alerts from one source collapsed into a single incident. In the live dashboard, a 20-record probing burst appears as one incident.

## 19. Dashboard
The React console provides:
- six KPI cards;
- eight overview charts;
- a traffic-analytics page with nine charts, each captioned with its analytical purpose;
- a filterable alert queue, an incidents view, a rules page (admin-editable) and the investigation page.

Data refreshes by polling every 5 s. Polling was chosen over SSE or WebSockets for simplicity and robustness. Severity is always conveyed by icon and text as well as colour.

## 20. SOC Workflow
Event → detection → alert → queue → triage → context investigation → severity determination → escalate, resolve or false positive → documentation.
- **Status transitions** are enforced server-side, and closure requires a written resolution.
- **Records:** every action is recorded in an append-only audit log that forms the incident timeline.
- **Reporting:** a Markdown incident report can be downloaded.

## 21. Testing
There are 37 automated pytest tests (unit and integration, using temporary databases). They cover:
- normal and suspicious scenarios, and invalid or missing input;
- features, rules, anomaly scoring, risk and alerts;
- correlation, the status workflow, notes, storage and dashboard statistics;
- ML prediction, API validation, an empty dataset, duplicates, RBAC, rule hot-reload, reports and security headers;
- dataset safety and simulator safety.

All 37 pass. The results table (with actual observed values) is generated automatically in `reports/test_results.md`. An end-to-end script reproduces the full analyst walkthrough against the running API.

## 22. Security
Controls: synthetic data only; no payload storage; API-key authentication with constant-time comparison; least-privilege RBAC (sensor, analyst, admin); Pydantic and semantic validation; parameterised SQL; rate limiting; CORS restriction; security headers; generic error responses; secrets in environment variables; git-ignored databases and model pickles; append-only audit logging.

IDS data is itself sensitive, because it maps who communicates with whom and which detections exist. Production would add SSO with MFA, TLS, encryption at rest and log integrity protection.

## 23. Results
| Detector (test set, n = 1,505; 275 suspicious) | Precision | Recall | F1 | FPR | FN |
|---|---|---|---|---|---|
| Rules only | 0.914 | 0.855 | 0.883 | 1.8% | 40 |
| Anomaly only | 0.857 | 0.676 | 0.756 | 2.5% | 89 |
| Rules + anomaly | 0.848 | 0.971 | 0.905 | 3.9% | 8 |
| Rules + anomaly + ML | 0.848 | **0.996** | **0.916** | 4.0% | **1** |

Per-scenario detection rates for the full hybrid were 96–100% for every suspicious pattern. Scenario tests A–G produced the expected verdicts (normal flows scored 0–0.3, and suspicious scenarios 54–96).

**Performance:**
- The engine takes about 0.2 ms per flow without ML.
- Replaying the full dataset through the complete pipeline, including database writes, takes about 7 s (≈ 840 flows/s). This came after two optimisations found by profiling: batched ML inference, and reusing database connections instead of opening one per request.

## 24. False Positives
The hybrid produced 49 false positives on 1,230 normal test flows (4.0%):
- **Bulk backups:** 22 of 27 backup flows (81.5%) were flagged by the volume rule. A multi-gigabyte transfer is statistically indistinguishable from exfiltration without context.
- **Busy web clients:** 23 of 565 web flows (4.1%) were flagged by connection-rate indicators.

**Mitigations:** asset-aware allow-lists (e.g. backup server plus schedule), per-host baselines, correlation, and analyst FALSE_POSITIVE feedback used for tuning.

## 25. False Negatives
Rules alone missed 40 suspicious flows, mainly:
- "low and slow" password guessing below the 10-failure threshold;
- the first 11 records of each probing burst, before the 12-port window threshold is reached.

Adding anomaly detection reduced misses to 8, and adding ML reduced them to 1. Remaining risks outside the dataset include attacks that closely mimic normal traffic, encrypted-payload threats invisible to flow data, and distributed low-rate activity spread across many sources.

## 26. Limitations
- **Data:** synthetic data generated by the same code that labels it, so metrics are optimistic.
- **Visibility:** flow-level only (no payload or TLS metadata).
- **Correlation:** correlation and the source window are in-memory, single-process and per alert type.
- **Access and scale:** simplified API-key authentication; SQLite and polling limit scale.
- **Model maintenance:** no automated retraining or drift monitoring.

## 27. Future Scope
All of these are defensive:
- authorised PCAP ingestion;
- NetFlow/IPFIX, Zeek and Suricata sensors;
- SIEM forwarding (Filebeat → Elastic/Wazuh/Splunk);
- threat-intelligence enrichment;
- per-host and seasonal baselines, and better anomaly models;
- cross-type correlation and UEBA;
- feedback-driven rule tuning;
- cloud flow-log monitoring;
- container deployment and centralised logging;
- SSO with MFA;
- model drift monitoring with scheduled retraining.

## 28. Conclusion
The project shows that a hybrid approach gives substantially better coverage than any single detection method: recall rose from 0.855 to 0.996. It also shows that detection quality has to be *measured*. The evaluation exposed two design flaws in the initial risk fusion, which were fixed with evidence-based floors. The false-positive analysis reinforces a central SOC lesson: context such as asset inventory, schedules and analyst feedback is as important as detection logic. The system delivers the complete workflow (synthetic traffic, detection, alerting, correlation, investigation and documentation) safely, reproducibly and with automated verification, making it a practical foundation for further study in network security monitoring and detection engineering.

## References
1. NIST SP 800-94, *Guide to Intrusion Detection and Prevention Systems (IDPS)*.
2. RFC 5737, *IPv4 Address Blocks Reserved for Documentation*.
3. RFC 7011, *Specification of the IP Flow Information Export (IPFIX) Protocol*.
4. MITRE ATT&CK®, https://attack.mitre.org/
5. Elastic Common Schema (ECS) reference.
6. Pedregosa et al., *Scikit-learn: Machine Learning in Python*, JMLR 12, 2011.
