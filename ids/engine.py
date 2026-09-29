"""
HybridIDSEngine — the detection pipeline in one place.

    flow record
       │  validate_flow()                 (reject malformed input)
       ▼
    SourceWindowTracker.observe()        (per-source 60 s context)
       ▼
    extract_network_features()
       ├──► rule_engine.analyze_flow()           -> signature score
       ├──► AnomalyDetector.calculate_anomaly_score() -> anomaly score
       └──► MLDetector.predict_probability()     -> ML probability (optional)
       ▼
    risk_engine.calculate_risk_score()   (weighted hybrid score)
       ▼
    classify() + risk_band()             (NORMAL / SUSPICIOUS / POTENTIAL_INTRUSION)
       ▼
    alert_engine.generate_alert()        (only if risky or a rule matched)
"""

from pathlib import Path

from ids.anomaly_detector import AnomalyDetector
from ids.alert_engine import generate_alert
from ids.config import ALERT_RISK_THRESHOLD, get_default_rules
from ids.feature_extractor import SourceWindowTracker, extract_network_features
from ids.risk_engine import calculate_risk_score, classify, risk_band
from ids.rule_engine import analyze_flow, calculate_signature_score
from ids.validation import validate_flow

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BASELINE_PATH = PROJECT_ROOT / "models" / "baseline.json"
DEFAULT_MODEL_PATH = PROJECT_ROOT / "models" / "random_forest.joblib"


class HybridIDSEngine:
    def __init__(self, rules=None, anomaly_detector=None, ml_detector=None,
                 weights=None, tracker=None, alert_threshold=ALERT_RISK_THRESHOLD):
        self.rules = rules if rules is not None else get_default_rules()
        self.anomaly_detector = anomaly_detector or AnomalyDetector()
        self.ml_detector = ml_detector          # None => ML disabled
        self.weights = weights                   # None => defaults from config
        self.tracker = tracker or SourceWindowTracker()
        self.alert_threshold = alert_threshold

    # ------------------------------------------------------------ factories
    @classmethod
    def from_project_files(cls, enable_ml=True, baseline_path=DEFAULT_BASELINE_PATH,
                           model_path=DEFAULT_MODEL_PATH, rules=None):
        """
        Build an engine from trained artefacts if they exist, otherwise fall
        back to safe defaults (built-in baseline, ML disabled).
        """
        baseline_path, model_path = Path(baseline_path), Path(model_path)
        detector = AnomalyDetector.load(baseline_path) if baseline_path.exists() else None
        ml = None
        if enable_ml and model_path.exists():
            from ml.predict import MLDetector  # lazy import: ML is optional
            ml = MLDetector.load(model_path)
        return cls(rules=rules, anomaly_detector=detector, ml_detector=ml)

    @property
    def ml_enabled(self) -> bool:
        return self.ml_detector is not None

    def set_rules(self, rules):
        """Hot-swap rules (e.g. after an analyst edits thresholds)."""
        self.rules = rules

    # -------------------------------------------------------------- analyse
    def analyze(self, raw_flow: dict, ml_probability: float | None = None) -> dict:
        """
        Run the full hybrid pipeline on one flow.

        `ml_probability` lets bulk jobs pass a pre-computed (batch-predicted) ML
        score instead of calling the model once per flow.

        Raises ids.validation.FlowValidationError for malformed records.
        """
        flow, warnings = validate_flow(raw_flow)
        context = self.tracker.observe(flow)
        features = extract_network_features(flow, context=context, validate=False)
        features.pop("data_quality_warnings", None)

        matches = analyze_flow(features, flow, self.rules)
        signature_score = calculate_signature_score(matches)
        anomaly = self.anomaly_detector.calculate_anomaly_score(features)
        if not self.ml_detector:
            ml_probability = None
        elif ml_probability is None:
            ml_probability = self.ml_detector.predict_probability(features)

        top_severity = matches[0].severity if matches else None
        risk = calculate_risk_score(signature_score, anomaly["score"], ml_probability,
                                    weights=self.weights, top_rule_severity=top_severity)
        band, severity = risk_band(risk)

        result = {
            "flow": flow,
            "data_quality_warnings": warnings,
            "features": features,
            "rule_matches": [m.to_dict() for m in matches],
            "signature_score": signature_score,
            "anomaly": anomaly,
            "ml_probability": None if ml_probability is None else round(ml_probability, 4),
            "risk_score": risk,
            "risk_band": band,
            "severity": severity,
            "classification": classify(risk),
        }
        result["should_alert"] = bool(matches) or risk >= self.alert_threshold
        result["alert"] = generate_alert(flow, result) if result["should_alert"] else None
        return result
