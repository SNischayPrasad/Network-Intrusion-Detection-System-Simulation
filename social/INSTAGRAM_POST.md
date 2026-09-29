# Instagram Post Kit — Network IDS Simulation

**Assets:** `social/slides/slide_01.png` … `slide_10.png` (1080×1350, the 4:5 portrait format Instagram shows largest in the feed). Upload all 10 as one carousel, in order.

---

## Caption (~1,700 characters; Instagram limit is 2,200)

```
I built a Network Intrusion Detection System 🛡️💻
Swipe to see how it catches suspicious traffic → and what it taught me 👉

🔍 What is it?
An IDS is like a security camera for a network. It watches traffic and raises an alert when something looks wrong, so a human analyst can investigate.

⚙️ How mine works
➊ Generates 6,019 synthetic network flows (normal + suspicious)
➋ Extracts 15 security features: connection rate, failed logins, port diversity…
➌ Detects with 3 layers: signature rules + anomaly detection + machine learning
➍ Combines everything into one 0–100 risk score
➎ Sends explainable alerts to a SOC dashboard where an analyst investigates and closes them

📊 The results
Rules alone caught 85.5% of suspicious traffic.
All three layers together caught 99.6% 🎯
Missed threats dropped from 40 to 1.

💡 Lessons I didn't expect
⚠️ My first formula made the system WORSE, until I measured it and fixed it
⚠️ Normal nightly backups were flagged 81.5% of the time, because they look like data theft
⚠️ "Accuracy" can lie: guessing "normal" every time still scores 81.7%

🔐 37/37 automated tests passing · role-based access · audit logging

✅ 100% synthetic data, built for defensive cybersecurity education only. No real networks, no scanning, no attacks.

🧰 Python · FastAPI · React · scikit-learn · SQLite

Full code + project report 🔗 link in bio

Which slide was most interesting to you? Tell me below 👇

.
.
.
#cybersecurity #cybersecuritystudent #infosec #networksecurity #ethicalhacking #blueteam #soc #socanalyst #intrusiondetection #threatdetection #python #machinelearning #datascience #coding #programming #computerscience #techstudent #studentproject #100daysofcode #devlife
```

> **Hashtag note:** Instagram currently recommends a handful of *relevant* hashtags rather than 30. For a leaner version, keep the 8 most relevant:
> `#cybersecurity #infosec #networksecurity #blueteam #socanalyst #intrusiondetection #python #cybersecuritystudent`

## Short caption alternative (for a single image or a Reel)
```
Rules caught 85.5%. My hybrid IDS caught 99.6% 🛡️
Built a Network Intrusion Detection System with signature rules + anomaly detection + ML, plus a SOC dashboard to investigate every alert.
100% synthetic data · defensive education only.
Code + report 🔗 link in bio
#cybersecurity #infosec #blueteam #socanalyst #python
```

---

## Link in bio
Instagram captions can't hold clickable links. Put the repo URL in your bio (or a Linktree / bio-link page) before posting:
`https://github.com/SNischayPrasad/Network-Intrusion-Detection-System-Simulation`

## Alt text (Advanced settings → Write alt text, per slide)
1. Title slide "I built a Network Intrusion Detection System simulation" with a dark SOC dashboard screenshot.
2. Six-step diagram from synthetic traffic to the SOC analyst workflow.
3. Dashboard KPI cards and a traffic-over-time chart of normal vs suspicious flows.
4. Three detection layers combined into a 0–100 hybrid risk score.
5. Alert evidence panel and anomaly Z-score table explaining why an alert fired.
6. Recall bar chart: 0.855 rules only up to 0.996 full hybrid; missed flows 40 to 1.
7. Three lessons: a formula bug found by measuring, backups flagged as suspicious, accuracy is misleading.
8. Alert status workflow and an audited incident timeline.
9. Security features and 37 of 37 automated tests passing.
10. Safety statement (synthetic data only) and "link in comments / bio".

## Stories (share after posting)
- **Story 1:** slide 6 (results) + sticker "New post 👆" linking to the post.
- **Story 2:** slide 7 (lessons) + a poll: "Would you trust a detector with 4% false positives? Yes / Depends".
- **Story 3:** a screen recording of the live dashboard auto-refreshing, + a link sticker to the GitHub repo.

## Optional Reel script (20–25 s, screen recording + text overlays)
| Time | Visual (record from your own running app) | Text overlay |
|---|---|---|
| 0–2 s | Dashboard with the Live toggle pulsing | "I built an Intrusion Detection System 🛡️" |
| 2–6 s | Terminal: `python -m simulator.traffic_simulator … --post` scrolling | "Synthetic traffic streams in (no real attacks)" |
| 6–10 s | Alert queue filling with CRITICAL alerts | "3 detection layers score every flow" |
| 10–15 s | Open an alert → "Why this alert fired" + anomaly table | "Every alert explains itself" |
| 15–19 s | Click Start investigation → add note → Resolve | "Investigate → document → resolve" |
| 19–23 s | Slide 6 (results) | "Rules: 85.5% → Hybrid: 99.6% caught" |
| 23–25 s | Slide 10 | "Code in bio 🔗" |
Suggested audio: any trending lo-fi or tech beat. Keep text on screen for at least 2 seconds per line.

## Posting tips
- Post the carousel in slide order. Slide 1 is the cover and slide 2 hooks the swipe.
- Best times for student and tech audiences: weekday evenings, 6–9 PM local time.
- Pin a comment with a one-line summary + "link in bio".
- Reply to comments quickly in the first hour; it boosts reach.
- Keep the defensive-education wording. It signals professionalism to recruiters who find your profile.
