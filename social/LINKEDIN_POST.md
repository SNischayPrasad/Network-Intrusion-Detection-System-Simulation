# LinkedIn Post Kit — Network IDS Simulation

**Assets:** `social/linkedin_carousel.pdf` (10 slides, upload as a *Document*) · single-image alternative: `social/slides/slide_01.png`
**Repo link used below:** `https://github.com/SNischayPrasad/Network-Intrusion-Detection-System-Simulation`. Change it if your GitHub username or repo name differs.

---

## Version A — Detailed post (recommended; ~2,800 characters, LinkedIn limit is 3,000)

> Only the first ~210 characters show before "…see more", so the first two lines are the hook.

```
I built a Network Intrusion Detection System that caught 99.6% of suspicious traffic in testing.

The most valuable part wasn't that number. It was finding out where my own design was wrong. 🧵👇

🛡️ 𝗪𝗵𝗮𝘁 𝗜 𝗯𝘂𝗶𝗹𝘁
A hybrid network IDS simulation, from raw flow records to a closed incident, the way a SOC works:

🔹 Generated 6,019 labelled synthetic network flows: normal web, DNS, SSH, email and database traffic, plus six suspicious patterns (repeated failed logins, port-probing bursts, SYN-heavy traffic, abnormal volume…)
🔹 Engineered 15 security features: connection rate, failure ratio, SYN ratio, and destination-port diversity per source over a 60-second window
🔹 Detected with 3 layers: 6 signature rules + statistical anomaly detection (Z-score + IQR) + a Random Forest model
🔹 Fused them into one 0–100 risk score, then turned risky flows into explainable alerts with investigation playbooks
🔹 Correlated related alerts into incidents (64% fewer items to triage)
🔹 Built a React SOC console where an analyst can triage, investigate, add notes and close alerts as Resolved or False Positive, with a full audit trail and downloadable incident reports

📊 𝗪𝗵𝗮𝘁 𝘁𝗵𝗲 𝗺𝗲𝗮𝘀𝘂𝗿𝗲𝗺𝗲𝗻𝘁𝘀 𝘀𝗵𝗼𝘄𝗲𝗱 (1,505-flow held-out test set)
• Rules only → caught 85.5% of suspicious flows
• Rules + anomaly detection → 97.1%
• Rules + anomaly + ML → 99.6% (missed flows went from 40 to 1)
• The cost: the false-positive rate rose from 1.8% to 4.0%

💡 𝗪𝗵𝗮𝘁 𝗜 𝗹𝗲𝗮𝗿𝗻𝗲𝗱
1️⃣ My first risk formula made the hybrid system WORSE than rules alone (recall dropped to 0.676). Averaging quietly diluted strong evidence. I only found it because I measured every layer separately, and fixed it with evidence-based risk floors.
2️⃣ Legitimate nightly backups were flagged 81.5% of the time. A 2 GB backup looks exactly like data exfiltration to a volume rule. Detection needs context, not just lower thresholds.
3️⃣ Accuracy is misleading. A model that always answers "normal" scores 81.7% accuracy on this data and catches nothing. Precision, recall and false-positive rate tell the real story.
4️⃣ Explainable alerts ("why did this fire?") matter as much as the detection itself.

🔐 Engineered like a real tool: role-based access, input validation, rate limiting, an append-only audit log, secrets kept out of code, and 37 automated tests (all passing).

⚖️ Built for defensive cybersecurity education only: 100% synthetic data, documentation-only IP ranges, and no scanning, exploits or real attack traffic.

🧰 Python · FastAPI · scikit-learn · SQLite · React · Recharts · pytest

Code, docs and the full project report are in the comments 👇

I'd love feedback from SOC analysts and detection engineers: how do you handle backup-style false positives in your environment?

#Cybersecurity #SOC #IntrusionDetection #NetworkSecurity #BlueTeam
```

### First comment (post immediately after publishing)
```
🔗 GitHub repo (code, docs, test results, model evaluation):
https://github.com/SNischayPrasad/Network-Intrusion-Detection-System-Simulation

📄 Start with the README. The "Results" and "False Positives" sections are the most interesting part.
```
*(Putting the link in a comment instead of the post body usually gets better reach.)*

---

## Version B — Short post (~770 characters)

```
Rules caught 85.5%. The hybrid caught 99.6%. 🛡️

I built a Network Intrusion Detection System simulation (synthetic data only) to learn how SOCs detect and investigate suspicious traffic:

✅ 6,019 synthetic network flows, 15 engineered security features
✅ Signature rules + statistical anomaly detection + Random Forest → one 0–100 risk score
✅ Explainable alerts, incident correlation and a React SOC dashboard
✅ Full analyst workflow: investigate → document → resolve / false positive
✅ 37 automated tests, role-based access and an audit log

Biggest lesson: 81.5% of legitimate nightly backups were flagged as "high volume". Context matters as much as detection logic.

Code + full report in the comments 👇

#Cybersecurity #SOC #IntrusionDetection #Python #BlueTeam
```

---

## Document (PDF carousel) settings
- **Document title:** `How I built a Hybrid Network IDS (and what the data taught me)`
- Upload `social/linkedin_carousel.pdf`. LinkedIn shows it as a swipeable carousel.

## Alt text (accessibility; add when uploading images)
| Slide | Alt text |
|---|---|
| 1 | Title slide: "I built a Network Intrusion Detection System simulation" over a screenshot of a dark SOC dashboard with KPI cards and traffic charts. |
| 2 | Six-step pipeline: synthetic traffic, feature engineering, three detection layers, hybrid risk score, alerts and incidents, SOC analyst workflow. |
| 3 | Dashboard KPIs and a traffic-over-time chart showing normal vs suspicious flows across a simulated day. |
| 4 | Three detection layers (signature rules, statistical anomaly detection, machine learning) combined into a hybrid 0–100 risk score. |
| 5 | Alert investigation panels: rule evidence (92 failed connections, failure ratio 0.85) and an anomaly Z-score table. |
| 6 | Results bar chart: recall 0.855 rules only, 0.676 anomaly only, 0.971 rules plus anomaly, 0.996 full hybrid; missed flows 40 to 1; false-positive rate 4.0%. |
| 7 | Three lessons: the first risk formula reduced recall, backups were flagged 81.5% of the time, and accuracy is misleading. |
| 8 | Alert workflow NEW, INVESTIGATING, RESOLVED or FALSE POSITIVE, with an audited incident timeline; correlation reduced triage items by 64%. |
| 9 | Engineering quality: role-based access, validation, rate limiting, audit log, 37 of 37 tests passing, about 840 flows per second. |
| 10 | Safety statement: synthetic data only, documentation IP ranges, no scanning or attacks; call to action to find the code in the comments. |

## Posting tips
- **Hashtags:** 3–5 is ideal on LinkedIn. Suggested: #Cybersecurity #SOC #IntrusionDetection #NetworkSecurity #BlueTeam (optional extras: #ThreatDetection #Python #MachineLearning #StudentProject).
- **Timing:** Tuesday–Thursday, 8–10 AM or 12–1 PM in your audience's time zone.
- **Engagement:** reply to every comment in the first 1–2 hours. The closing question invites replies.
- **Tagging:** mention your professor, college or course only if they would be happy to be tagged.
- **Project section:** also add it under *Profile → Add section → Projects*, using the Version B text and the repo link.
- **Be interview-ready:** anyone reading this may ask about the risk floors, the backup false positives or why you chose an IDS over an IPS. The answers are in `docs/10_CAREER_KIT.md`. If you used AI coding assistance, saying so openly (e.g. "built with AI-assisted development") is increasingly common and reads as honest; just make sure you can explain every design decision yourself.
