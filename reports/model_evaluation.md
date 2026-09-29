# Model & Detection Evaluation Results

_Generated automatically by `python -m ml.train_model` on 2026-09-29 04:40 UTC._

* Dataset: `data/network_traffic.csv` — 6019 flows (1099 SUSPICIOUS / 4920 NORMAL)
* Split: stratified 75/25 train/test (seed 42) — test set = 1505 flows
* Anomaly baseline fitted on 3690 NORMAL training flows only
* scikit-learn 1.9.1

## 1. Machine-learning models (held-out test set)

| Model | Type | Accuracy | Precision | Recall | F1 | FPR | ROC-AUC | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Logistic Regression | Supervised | 0.952 | 0.812 | 0.956 | 0.878 | 0.050 | 0.985 | 263 | 61 | 12 | 1169 |
| Random Forest | Supervised | 0.967 | 0.865 | 0.975 | 0.916 | 0.034 | 0.996 | 268 | 42 | 7 | 1188 |
| Isolation Forest (unsupervised) | Unsupervised | 0.866 | 0.579 | 0.975 | 0.726 | 0.159 | 0.968 | 268 | 195 | 7 | 1035 |

## 2. IDS detection layers compared (same test set)

| Detector | Accuracy | Precision | Recall | F1 | FPR | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|---|
| Rule engine only | 0.959 | 0.914 | 0.855 | 0.883 | 0.018 | 235 | 22 | 40 | 1208 |
| Anomaly detector only (score>=50) | 0.920 | 0.857 | 0.676 | 0.756 | 0.025 | 186 | 31 | 89 | 1199 |
| Hybrid: rules + anomaly | 0.963 | 0.848 | 0.971 | 0.905 | 0.039 | 267 | 48 | 8 | 1182 |
| Hybrid: rules + anomaly + ML | 0.967 | 0.848 | 0.996 | 0.916 | 0.040 | 274 | 49 | 1 | 1181 |

## 3. Hybrid IDS (with ML) — flag rate per scenario (test set)

For SUSPICIOUS scenarios the flag rate is the **detection rate** (higher is better).
For NORMAL scenarios it is the **false-positive rate** (lower is better).

| Scenario | Ground truth | Test flows | Flagged | Flag rate |
|---|---|---|---|---|
| NORMAL_BULK_TRANSFER | NORMAL | 27 | 22 | 81.5% |
| NORMAL_DATABASE | NORMAL | 149 | 1 | 0.7% |
| NORMAL_DNS | NORMAL | 316 | 3 | 0.9% |
| NORMAL_EMAIL | NORMAL | 88 | 0 | 0.0% |
| NORMAL_SSH | NORMAL | 85 | 0 | 0.0% |
| NORMAL_WEB | NORMAL | 565 | 23 | 4.1% |
| HIGH_CONNECTION_RATE | SUSPICIOUS | 48 | 48 | 100.0% |
| HIGH_TRAFFIC_VOLUME | SUSPICIOUS | 28 | 27 | 96.4% |
| MULTI_PORT_PROBING_PATTERN | SUSPICIOUS | 73 | 73 | 100.0% |
| REPEATED_FAILED_CONNECTIONS | SUSPICIOUS | 45 | 45 | 100.0% |
| SYN_HEAVY_PATTERN | SUSPICIOUS | 29 | 29 | 100.0% |
| UNUSUAL_PORT_ACTIVITY | SUSPICIOUS | 52 | 52 | 100.0% |

## 4. Random Forest feature importance

| Feature | Importance |
|---|---|
| failed_connection_count | 0.184 |
| bytes_per_second | 0.150 |
| average_packet_size | 0.145 |
| packets_per_second | 0.102 |
| rst_count | 0.098 |
| duration | 0.083 |
| byte_count | 0.070 |
| packet_count | 0.067 |
| syn_count | 0.067 |
| connection_count | 0.033 |

## 5. How to read these numbers

* **Precision** — of the flows we flagged, how many were truly suspicious (low precision = analyst time wasted on false positives).
* **Recall** — of the truly suspicious flows, how many we caught (low recall = missed intrusions / false negatives).
* **Accuracy is not enough**: always predicting NORMAL would already score 81.7% accuracy on this dataset.
* The data is synthetic, so absolute numbers are optimistic compared with real networks. What matters is the *relative* behaviour of each detection layer.
