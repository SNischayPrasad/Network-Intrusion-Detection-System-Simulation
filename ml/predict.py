"""
ML inference used by the live IDS engine.

SECURITY NOTE: joblib/pickle files can execute code when loaded. Only load
model files that YOU trained (models/ is git-ignored for this reason).
Never load a model file downloaded from an untrusted source.

CLI example:
    python -m ml.predict --flow "{\"packet_count\": 900, \"byte_count\": 54000, ...}"
"""

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib  # noqa: E402
import pandas as pd  # noqa: E402

from ml.data_prep import ML_FEATURES  # noqa: E402

DEFAULT_MODEL = PROJECT_ROOT / "models" / "random_forest.joblib"


class MLDetector:
    """Thin wrapper around a trained scikit-learn pipeline."""

    def __init__(self, model, name="Random Forest", threshold=0.5):
        self.model = model
        self.name = name
        self.threshold = threshold
        # Single-row predictions are faster without process-pool overhead.
        clf = getattr(model, "named_steps", {}).get("clf")
        if clf is not None and hasattr(clf, "n_jobs"):
            clf.n_jobs = 1

    @classmethod
    def load(cls, path=DEFAULT_MODEL):
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"{path} not found. Run: python -m ml.train_model")
        return cls(joblib.load(path))

    def predict_probability(self, features: dict) -> float:
        """Probability (0–1) that the flow is SUSPICIOUS."""
        row = pd.DataFrame([{c: float(features.get(c, 0.0) or 0.0) for c in ML_FEATURES}],
                           columns=ML_FEATURES)
        return float(self.model.predict_proba(row)[0, 1])

    def predict(self, features: dict) -> str:
        return "SUSPICIOUS" if self.predict_probability(features) >= self.threshold else "NORMAL"


def main(argv=None):
    from ids.feature_extractor import extract_network_features

    parser = argparse.ArgumentParser(description="Score one flow with the trained ML model.")
    parser.add_argument("--flow", required=True, help="flow record as JSON")
    parser.add_argument("--model", default=str(DEFAULT_MODEL))
    args = parser.parse_args(argv)

    features = extract_network_features(json.loads(args.flow))
    detector = MLDetector.load(args.model)
    prob = detector.predict_probability(features)
    print(json.dumps({"model": detector.name, "prediction": detector.predict(features),
                      "probability_suspicious": round(prob, 4)}, indent=2))


if __name__ == "__main__":
    main()
