# 10 · Resume, LinkedIn & Interview Kit

All numbers below come from this repository's own measured results. Re-check them against `reports/` if you regenerate the data.

## 39. Resume / LinkedIn proof

### A. Resume bullet points (pick 3)
- **Built a hybrid network intrusion detection system** in Python combining 6 configurable signature rules, a Z-score/IQR statistical anomaly detector and a Random Forest. On a 1,505-flow held-out test set the hybrid engine raised recall from **0.855 (rules only) to 0.996** at a 4.0% false-positive rate.
- **Developed a SOC dashboard and incident workflow** (FastAPI, React, SQLite) with real-time flow ingestion, hybrid risk scoring (0–100), alert correlation into incidents, an analyst investigation page, audit-logged status changes and Markdown incident reports.
- **Engineered 15 network-flow features** (rates, failure/SYN ratios, 60-second per-source port diversity) over a 6,000+ record synthetic dataset. Secured the API with RBAC, input validation, rate limiting and audit logging, verified by **37 automated tests**.

### B. Two-line project description
> Defensive, fully synthetic network IDS simulation that detects suspicious flow patterns with signature rules, statistical anomaly detection and machine learning, and fuses them into a single risk score.
> Alerts flow into a React SOC console where analysts triage, investigate, correlate and document incidents end to end.

### C. LinkedIn project post
> 🛡️ **Project: Network Intrusion Detection System (IDS) Simulation**
>
> I built a hybrid network IDS from scratch to understand how Security Operations Centres detect and investigate suspicious traffic, using 100% synthetic data and documentation-only IP ranges.
>
> **What it does**
> 🔹 Generates 6,000+ labelled network flows (normal web/DNS/SSH/DB traffic plus patterns like repeated failed logins, port-probing bursts and SYN-heavy traffic)
> 🔹 Detects them with 3 layers: signature rules, a statistical anomaly detector (Z-score + IQR) and a Random Forest
> 🔹 Combines the layers into a 0–100 risk score, raises alerts with evidence and defensive playbooks, and correlates them into incidents
> 🔹 Gives analysts a React SOC console for the whole NEW → INVESTIGATING → RESOLVED / FALSE-POSITIVE workflow
>
> **What I learned by measuring it**
> 📊 Rules alone caught 85.5% of suspicious test flows; the hybrid caught 99.6%
> ⚠️ But nightly backups were flagged 81% of the time. A great lesson in why false positives, context and tuning matter as much as detection
> 🔧 My first risk formula let quiet detectors "average away" a strong rule match. The evaluation exposed it, and I fixed it with evidence-based floors
>
> **Stack:** Python · FastAPI · scikit-learn · SQLite · React · Recharts · pytest (37 tests)
>
> Defensive education only. No real traffic, scanning or attacks.
> 🔗 GitHub: <link>
>
> #cybersecurity #SOC #intrusiondetection #networksecurity #python #machinelearning #blueteam

### D. Technical skills demonstrated
| Area | Skills |
|---|---|
| Network Security | TCP/UDP/ICMP, ports and services, TCP flags (SYN/RST), flow analysis (5-tuple) |
| Intrusion Detection | signature rules, anomaly detection, hybrid scoring, detection-as-code, threshold tuning |
| SOC Operations | alert triage, investigation, correlation, incident documentation, ATT&CK (candidate) mapping, SIEM export |
| Network Traffic Analysis | feature engineering, rate and ratio metrics, sliding windows, traffic visualisation |
| Anomaly & Signature Detection | Z-score, IQR, log transforms, EWMA, rule design |
| Machine Learning | Logistic Regression, Random Forest, Isolation Forest, stratified splits, precision/recall/F1, confusion matrices |
| Security Analytics | KPI dashboards, risk distributions, false-positive analysis |
| Secure Engineering | input validation, RBAC, rate limiting, audit logs, secret management, parameterised SQL |
| Software Engineering | Python, FastAPI, SQLite, React, REST design, pytest, Git |

### E. GitHub repository description
> Defensive network intrusion detection simulation featuring synthetic traffic generation, signature-based and anomaly-based detection, risk scoring, alert correlation, SOC analytics, and optional machine learning.

---

## 41. Interview preparation: 10 questions, 10 answers

**1. Explain your project.**
> "I built a network intrusion detection simulation that works end to end: from raw flow records to an analyst closing an incident. A generator creates about 6,000 labelled synthetic flows (normal web, DNS, SSH, database and backup traffic) plus six suspicious patterns such as repeated failed connections, port-probing bursts and SYN-heavy traffic. I only used documentation IP ranges, so nothing touches a real network. Each flow goes through validation and feature extraction, then three detectors: six signature rules, a statistical anomaly detector and an optional Random Forest. A risk engine combines them into a 0–100 score, and risky flows become alerts with evidence and an investigation playbook. Alerts from the same source are correlated into incidents. A FastAPI backend stores everything in SQLite, and a React SOC console lets an analyst triage, investigate, add notes and close alerts as resolved or false positive. I measured it on a held-out test set: rules alone had 0.855 recall, and the hybrid reached 0.996 at a 4% false-positive rate. I also have 37 automated tests."

**2. What's the difference between an IDS and an IPS, and why did you build an IDS?**
> "An IDS is passive. It watches a copy of the traffic and raises alerts. An IPS sits inline and can automatically drop or block. I built an IDS deliberately. First, my own measurements showed about 4% false positives, and as an IPS those would be blocked backups and blocked users. Second, the part I wanted to learn was the analyst's decision-making. Third, a simulation that blocks nothing can't cause harm. In real deployments, teams usually run IPS rules in alert-only mode first and enable blocking only for high-confidence signatures."

**3. Why analyse flows instead of packets?**
> "Flows are summaries: the 5-tuple plus packet, byte, duration and flag counts. They scale to large networks, don't store payloads (which matters for privacy), and most traffic is encrypted anyway. That's how NetFlow, IPFIX and Zeek's conn.log are used in real SOCs. The trade-off is that I can't see content, so I detect behaviour (rates, ratios, diversity) rather than specific exploit strings."

**4. Walk me through your signature rules. How do you avoid hard-coding them?**
> "There are six rules: high connection rate, repeated failed connections, multi-port probing, SYN-heavy behaviour, watch-listed ports and abnormal volume. Each one is a small pure function that returns an evidence string, like 'failed_connections=360, ratio=0.90', so every alert explains itself. The thresholds live in the database as JSON. An admin can tune them through the API, which validates the keys and ranges, writes an audit entry and hot-reloads the engine. I audit rule changes because quietly weakening a rule is a classic way to evade detection."

**5. How does your anomaly detector work, and what are its weaknesses?**
> "It learns a baseline (mean, standard deviation and quartiles) from normal training traffic only, for packet rate, byte rate, connection rate, failure ratio and destination-port diversity. Traffic is heavy-tailed, so I log-transform the rates first. For a new flow I compute Z-scores, map z = 2 to 6 onto 0–100, and confirm with Tukey's IQR fence. The analyst sees which metric drove the score. The weaknesses: 'unusual' isn't 'malicious', so backups and new applications look anomalous. It also needs a clean baseline. That's why the adaptive EWMA baseline is off by default: an attacker could slowly teach it that their behaviour is normal."

**6. Which features mattered most, and how did you engineer them?**
> "Ratios and rates matter more than raw counts. For example, failure ratio is failed connections divided by total, and SYN ratio is SYNs divided by packets. I used a 1-second floor on duration so a 5 ms DNS flow doesn't produce an absurd bytes-per-second value. The most interesting feature is unique destination ports per source over a 60-second sliding window. A single probe record looks like an ordinary refused connection; you only see the pattern in aggregate. In the Random Forest, failed_connection_count, bytes_per_second and average_packet_size were the top three by importance."

**7. How is your risk score calculated, and did you get it right the first time?**
> "It's a weighted sum: 40% rules, 30% anomaly, 30% ML, or 60/40 when ML is off, then mapped to bands (NORMAL, LOW, SUSPICIOUS, HIGH, CRITICAL). I did not get it right first time, and the evaluation proved it. The first version had lower recall than rules alone, because a MEDIUM rule match averaged with two quiet detectors fell below the alert threshold. I added a floor so a rule match always lands at least in its severity band. The next run showed the opposite problem: anomaly alone could contribute at most 40 points, so it could never alert. I added a floor for any single highly confident detector. After that, each layer increased recall: 0.855, then 0.971, then 0.996. The lesson for me was to measure detection logic, not just assume it's right."

**8. Your ML model scored 0.97 recall. Should we trust that?**
> "Not at face value. The data is synthetic and generated by the same code that labels it, so it's cleaner than real traffic, and real-world performance would be lower. What I trust is the relative comparison, because every layer was evaluated on the same held-out, stratified test set. I also didn't rely on accuracy: always predicting NORMAL scores 82% accuracy on this data. I reported precision, recall, F1, FPR and confusion matrices. In production I'd retrain on labelled real alerts (analyst closures are free labels), monitor for drift, and treat ML-only detections as lower confidence until corroborated."

**9. How do you handle false positives?**
> "First by measuring them. I report false-positive rates per scenario: backups were flagged 81.5% of the time and busy web pages 4.1%. Then there are several levers. Correlation groups repeated alerts into incidents so one noisy source doesn't flood the queue. Risk ranking puts CRITICAL at the top. Threshold tuning is available through the rules page. Closing an alert as FALSE_POSITIVE requires a written reason, which becomes tuning data. For backups specifically, I'd add context: an allow-list for the backup server and its schedule, instead of raising the global volume threshold and going blind to real exfiltration."

**10. Walk me through what you'd do as a Tier-1 analyst with one of your alerts.**
> "Take a CRITICAL 'Repeated Failed Connections' alert: 360 of 400 SSH connections failed in 20 seconds from an external IP. First I check the incident: is it one alert or part of a larger burst? Then I work through the context on the investigation page. The anomaly table shows failure ratio and connection rate far above baseline. I check whether the source is in the asset inventory or is an approved scanner. The most important check is whether authentication logs show a *successful* login after the failures, because that changes it from 'attempt' to 'possible compromise'. I note everything I checked. If there's no success and the source is unknown, I resolve it with a recommendation such as blocking at the perimeter and enforcing key-based SSH. If there was a success, I escalate to Tier 2 with the timeline. Every step shows up in the audit timeline and the incident report."
