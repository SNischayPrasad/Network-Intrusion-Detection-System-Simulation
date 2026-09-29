"""
Hybrid risk scoring.

    Final Risk = w_sig * SignatureScore + w_anom * AnomalyScore + w_ml * MLScore

Default weights (configurable in ids.config):
    with ML    -> Rule 40% | Anomaly 30% | ML 30%
    without ML -> Rule 60% | Anomaly 40%

Why hybrid?  Each method covers another's blind spot:
    * Rules      : precise and explainable, but only know known patterns.
    * Anomaly    : notices new/unknown behaviour, but noisier.
    * ML         : learns multi-feature combinations from labelled history,
                   but is only as good as its training data.

Guard-rail: a signature match is floored at the band of the rule's severity
(MEDIUM -> 41, HIGH -> 61; CRITICAL also 61, so "CRITICAL INVESTIGATION"
needs corroboration). Strong rule evidence therefore cannot be diluted into
"NORMAL" just because the other detectors were quiet. (Without this floor our
own evaluation showed the hybrid detector losing recall versus rules alone.)

IMPORTANT: The band boundaries below are PROJECT ASSUMPTIONS. A real SOC
calibrates them against its own alert volume and analyst capacity.
"""

from ids.config import (
    CLASSIFICATION_THRESHOLDS,
    RISK_BANDS,
    RISK_WEIGHTS_WITH_ML,
    RISK_WEIGHTS_WITHOUT_ML,
    RULE_SEVERITY_RISK_FLOOR,
    SEVERITIES,
    SINGLE_DETECTOR_FLOORS,
)


def _normalise_weights(weights: dict) -> dict:
    total = sum(weights.values())
    if total <= 0:
        raise ValueError("risk weights must sum to a positive number")
    return {k: v / total for k, v in weights.items()}


def calculate_risk_score(signature_score: float,
                         anomaly_score: float,
                         ml_probability: float | None = None,
                         weights: dict | None = None,
                         top_rule_severity: str | None = None) -> float:
    """
    Combine detector outputs into a single 0–100 risk score.

    Parameters
    ----------
    signature_score   : 0–100 from the rule engine
    anomaly_score     : 0–100 from the anomaly detector
    ml_probability    : 0–1 probability of SUSPICIOUS from the ML model, or None
                        when ML is disabled / unavailable
    weights           : optional override, e.g. {"signature": .5, "anomaly": .5}
    top_rule_severity : severity of the most severe matched rule (for the floor)
    """
    sig = min(100.0, max(0.0, float(signature_score)))
    anom = min(100.0, max(0.0, float(anomaly_score)))

    if ml_probability is None:
        w = _normalise_weights(weights or RISK_WEIGHTS_WITHOUT_ML)
        score = w.get("signature", 0) * sig + w.get("anomaly", 0) * anom
    else:
        ml = min(100.0, max(0.0, float(ml_probability) * 100.0))
        w = _normalise_weights(weights or RISK_WEIGHTS_WITH_ML)
        score = w.get("signature", 0) * sig + w.get("anomaly", 0) * anom + w.get("ml", 0) * ml

    # Floors: the weighted score RANKS alerts; floors make sure a strong signal
    # from any single detector is never hidden by quiet detectors.
    if top_rule_severity:
        score = max(score, RULE_SEVERITY_RISK_FLOOR.get(top_rule_severity, 0))
    if anom >= SINGLE_DETECTOR_FLOORS["anomaly"]["min_score"]:
        score = max(score, SINGLE_DETECTOR_FLOORS["anomaly"]["floor"])
    if ml_probability is not None and \
            ml_probability * 100 >= SINGLE_DETECTOR_FLOORS["ml"]["min_score"]:
        score = max(score, SINGLE_DETECTOR_FLOORS["ml"]["floor"])

    return round(min(100.0, max(0.0, score)), 1)


def risk_band(score: float):
    """Map a score to (band_label, alert_severity), e.g. 76 -> ("HIGH RISK", "HIGH")."""
    for upper, label, severity in RISK_BANDS:
        if score <= upper:
            return label, severity
    return RISK_BANDS[-1][1], RISK_BANDS[-1][2]


def classify(score: float) -> str:
    """NORMAL / SUSPICIOUS / POTENTIAL_INTRUSION from the final risk score."""
    if score >= CLASSIFICATION_THRESHOLDS["POTENTIAL_INTRUSION"]:
        return "POTENTIAL_INTRUSION"
    if score >= CLASSIFICATION_THRESHOLDS["SUSPICIOUS"]:
        return "SUSPICIOUS"
    return "NORMAL"


def max_severity(*severities):
    """Return the most severe of the given severity names (ignores None)."""
    valid = [s for s in severities if s in SEVERITIES]
    if not valid:
        return "INFO"
    return max(valid, key=SEVERITIES.index)
