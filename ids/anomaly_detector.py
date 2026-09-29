"""
Statistical anomaly-based detection.

Idea
----
    Normal Baseline -> Observe New Flow -> Compare Against Baseline
                    -> Calculate Deviation -> Generate Anomaly Score (0–100)

1. Learn what "normal" looks like from NORMAL traffic only
   (mean, standard deviation, quartiles for each metric).
2. For a new flow, measure how far each metric sits from normal:
     * Z-score   : (x - mean) / std  — "how many standard deviations away?"
     * IQR fence : x > Q3 + k * IQR  — robust to skewed data / outliers
3. Convert deviations into a 0–100 score with a per-metric explanation.

Heavy-tailed metrics (rates, counts) are log-transformed with log1p first,
because network traffic is highly skewed: a normal download can be 1000x
bigger than a DNS query. On a log scale the Z-score becomes meaningful.

Only *upward* deviations are scored — an unusually quiet flow is not a
security concern for the metrics we track.

Why anomaly detection?
    + It can flag behaviour no rule was written for (previously unseen patterns).
    - "Unusual" is not the same as "malicious": new apps, backups, or a
      marketing campaign all look unusual, so false positives are expected.
"""

import json
import math
from pathlib import Path

import numpy as np

from ids.config import ANOMALY_CONFIG

# Fallback baseline (log-space statistics) used when no dataset-derived
# baseline file exists yet. Values were derived from the synthetic NORMAL
# traffic profile so the IDS works out of the box.
DEFAULT_BASELINE = {
    "packets_per_second": {"mean": 2.48, "std": 1.39, "q1": 1.10, "q3": 3.29},
    "bytes_per_second": {"mean": 8.28, "std": 2.15, "q1": 6.19, "q3": 9.78},
    "connection_rate": {"mean": 0.56, "std": 0.45, "q1": 0.14, "q3": 0.69},
    "failure_ratio": {"mean": 0.024, "std": 0.14, "q1": 0.0, "q3": 0.0},
    "unique_destination_ports": {"mean": 0.70, "std": 0.06, "q1": 0.69, "q3": 0.69},
}


def _transform(metric: str, value: float) -> float:
    """Apply log1p to heavy-tailed metrics; leave ratios unchanged."""
    value = max(0.0, float(value))
    return math.log1p(value) if metric in ANOMALY_CONFIG["log_metrics"] else value


def calculate_z_score(value: float, mean: float, std: float) -> float:
    """Classic Z-score with a guard against zero standard deviation."""
    if std <= 0:
        return 0.0
    return (value - mean) / std


def iqr_upper_fence(q1: float, q3: float, multiplier: float) -> float:
    """Tukey fence: values above Q3 + k*IQR are outliers (k=1.5 mild, 3.0 extreme)."""
    return q3 + multiplier * (q3 - q1)


class AnomalyDetector:
    """
    Baseline-driven anomaly scorer.

    Usage
    -----
        detector = AnomalyDetector.fit(list_of_normal_feature_dicts)
        result   = detector.calculate_anomaly_score(features)
        detector.save("models/baseline.json")
    """

    def __init__(self, baseline: dict | None = None, config: dict | None = None):
        self.config = config or ANOMALY_CONFIG
        source = baseline or DEFAULT_BASELINE
        # Copy so that EWMA updates never mutate the caller's dict / the defaults.
        self.baseline = {m: dict(v) for m, v in source.items() if not m.startswith("_")}
        self.sample_size = source.get("_sample_size")

    # ------------------------------------------------------------------ fit
    @classmethod
    def fit(cls, normal_features: list, config: dict | None = None):
        """Build a baseline from feature dicts of KNOWN-NORMAL traffic."""
        config = config or ANOMALY_CONFIG
        if not normal_features:
            raise ValueError("Cannot fit a baseline from an empty dataset")
        baseline = {}
        for metric in config["metrics"]:
            values = np.array([_transform(metric, f[metric]) for f in normal_features])
            baseline[metric] = {
                "mean": float(np.mean(values)),
                "std": float(np.std(values)),
                "q1": float(np.percentile(values, 25)),
                "q3": float(np.percentile(values, 75)),
            }
        detector = cls(baseline=baseline, config=config)
        detector.sample_size = len(normal_features)
        return detector

    # --------------------------------------------------------------- scoring
    def calculate_anomaly_score(self, features: dict) -> dict:
        """
        Score how far a flow deviates from the normal baseline.

        Returns
        -------
        {
          "score": 0–100,
          "is_anomalous": bool (score >= 50),
          "details": {metric: {value, z_score, iqr_outlier, metric_score}},
          "top_contributors": [metric names driving the score]
        }
        """
        cfg = self.config
        z_warn, z_max = cfg["z_warn"], cfg["z_max"]
        details, metric_scores, iqr_hits = {}, [], 0

        for metric in cfg["metrics"]:
            stats = self.baseline[metric]
            raw_value = float(features.get(metric, 0.0) or 0.0)
            x = _transform(metric, raw_value)
            std = max(stats["std"], cfg["min_std"].get(metric, 0.0))
            z = calculate_z_score(x, stats["mean"], std)

            fence = iqr_upper_fence(stats["q1"], stats["q3"], cfg["iqr_multiplier"])
            # Only count IQR outliers when the IQR is meaningful (non-degenerate).
            iqr_outlier = (stats["q3"] - stats["q1"]) > 0 and x > fence

            # Map Z in [z_warn, z_max] linearly to [0, 100]; only upward deviations.
            metric_score = 100.0 * min(1.0, max(0.0, (z - z_warn) / (z_max - z_warn)))
            metric_scores.append(metric_score)
            iqr_hits += int(iqr_outlier and metric_score > 0)

            details[metric] = {
                "value": round(raw_value, 4),
                "z_score": round(z, 2),
                "iqr_outlier": bool(iqr_outlier),
                "metric_score": round(metric_score, 1),
            }

        # Blend: the worst metric dominates, the average adds breadth, IQR confirms.
        score = 0.7 * max(metric_scores) + 0.3 * (sum(metric_scores) / len(metric_scores))
        score += cfg["iqr_bonus_per_metric"] * iqr_hits
        score = round(min(100.0, max(0.0, score)), 1)

        top = sorted(details, key=lambda m: details[m]["metric_score"], reverse=True)
        top = [m for m in top if details[m]["metric_score"] > 0][:3]
        return {
            "score": score,
            "is_anomalous": score >= 50,
            "details": details,
            "top_contributors": top,
        }

    # ------------------------------------------------ moving-average baseline
    def update_baseline(self, features: dict):
        """
        Optional adaptive baseline using an Exponentially Weighted Moving Average.

        mean_new = (1 - a) * mean_old + a * x
        var_new  = (1 - a) * var_old  + a * (x - mean_old)^2

        Only call this with flows you are confident are NORMAL — otherwise an
        attacker could slowly "teach" the baseline that their behaviour is normal
        (baseline poisoning). Disabled by default in ids.config.
        """
        alpha = self.config["ewma_alpha"]
        for metric in self.config["metrics"]:
            stats = self.baseline[metric]
            x = _transform(metric, features.get(metric, 0.0))
            diff = x - stats["mean"]
            stats["mean"] += alpha * diff
            stats["std"] = math.sqrt((1 - alpha) * (stats["std"] ** 2) + alpha * diff * diff)

    # ----------------------------------------------------------- persistence
    def to_dict(self):
        data = {m: dict(v) for m, v in self.baseline.items()}
        data["_sample_size"] = self.sample_size
        return data

    def save(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path):
        """Load a JSON baseline (plain data — safe to load, unlike pickles)."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(baseline=data)


class MovingAverage:
    """Simple fixed-window moving average (used for traffic-trend smoothing)."""

    def __init__(self, window: int = 5):
        self.window = max(1, window)

    def smooth(self, values):
        out, running = [], []
        for v in values:
            running.append(v)
            if len(running) > self.window:
                running.pop(0)
            out.append(round(sum(running) / len(running), 2))
        return out


def calculate_anomaly_score(features: dict, detector: AnomalyDetector | None = None) -> float:
    """Functional wrapper returning only the 0–100 anomaly score."""
    detector = detector or AnomalyDetector()
    return detector.calculate_anomaly_score(features)["score"]
