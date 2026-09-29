"""
Model evaluation utilities + CLI.

Metrics (SUSPICIOUS = positive class):
    Accuracy  = (TP + TN) / all            — misleading on imbalanced data!
    Precision = TP / (TP + FP)             — "when we alert, how often are we right?"
    Recall    = TP / (TP + FN)             — "of real suspicious flows, how many did we catch?"
    F1        = harmonic mean of precision and recall

Why accuracy alone is insufficient: with 82% normal traffic, a model that
ALWAYS answers "NORMAL" scores 82% accuracy while catching zero intrusions.

Usage (re-evaluates the SAVED models on the held-out test split):
    python -m ml.evaluate
"""

import json
import sys
from pathlib import Path

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

MODELS_DIR = PROJECT_ROOT / "models"
REPORTS_DIR = PROJECT_ROOT / "reports"
FIGURES_DIR = REPORTS_DIR / "figures"


def compute_metrics(y_true, y_pred, y_score=None) -> dict:
    """Return a JSON-serialisable metrics dict computed from real predictions."""
    y_true, y_pred = np.asarray(y_true), np.asarray(y_pred)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    metrics = {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "false_positive_rate": round(float(fp / (fp + tn)) if (fp + tn) else 0.0, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "support": {"normal": int((y_true == 0).sum()), "suspicious": int((y_true == 1).sum())},
    }
    if y_score is not None and len(set(y_true)) > 1:
        metrics["roc_auc"] = round(float(roc_auc_score(y_true, y_score)), 4)
    return metrics


def plot_confusion_matrix(metrics: dict, title: str, path) -> None:
    """Save a labelled confusion-matrix heatmap as PNG."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    cm = metrics["confusion_matrix"]
    grid = np.array([[cm["tn"], cm["fp"]], [cm["fn"], cm["tp"]]])
    fig, ax = plt.subplots(figsize=(5.4, 4.2), dpi=130)
    ax.imshow(grid, cmap="Blues")
    labels = [["TN", "FP"], ["FN", "TP"]]
    for i in range(2):
        for j in range(2):
            color = "white" if grid[i, j] > grid.max() / 2 else "#1b2a41"
            ax.text(j, i, f"{labels[i][j]}\n{grid[i, j]}", ha="center", va="center",
                    fontsize=12, color=color, fontweight="bold")
    ax.set_xticks([0, 1], ["Pred NORMAL", "Pred SUSPICIOUS"])
    ax.set_yticks([0, 1], ["True NORMAL", "True SUSPICIOUS"])
    ax.set_title(f"{title}\nP={metrics['precision']:.2f}  R={metrics['recall']:.2f}  "
                 f"F1={metrics['f1']:.2f}", fontsize=10)
    fig.tight_layout()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path)
    plt.close(fig)


def print_metrics_table(results: dict) -> None:
    header = f"{'Model':<34}{'Acc':>7}{'Prec':>7}{'Rec':>7}{'F1':>7}{'FPR':>7}   TP   FP   FN    TN"
    print(header)
    print("-" * len(header))
    for name, m in results.items():
        cm = m["confusion_matrix"]
        print(f"{name:<34}{m['accuracy']:>7.3f}{m['precision']:>7.3f}{m['recall']:>7.3f}"
              f"{m['f1']:>7.3f}{m['false_positive_rate']:>7.3f} {cm['tp']:>4} {cm['fp']:>4} "
              f"{cm['fn']:>4} {cm['tn']:>5}")


def main():
    import joblib

    from ml.data_prep import ML_FEATURES, feature_matrix, load_dataset, split_indices

    _, _, features, y = load_dataset()
    _, test_idx = split_indices(y)
    X_test = feature_matrix([features[i] for i in test_idx], ML_FEATURES)
    y_test = y[test_idx]

    results = {}
    for name, file in [("Logistic Regression", "logistic_regression.joblib"),
                       ("Random Forest", "random_forest.joblib")]:
        path = MODELS_DIR / file
        if not path.exists():
            print(f"[!] {path} missing — run: python -m ml.train_model")
            return 1
        model = joblib.load(path)
        proba = model.predict_proba(X_test)[:, 1]
        results[name] = compute_metrics(y_test, (proba >= 0.5).astype(int), proba)

    iso_path = MODELS_DIR / "isolation_forest.joblib"
    if iso_path.exists():
        iso = joblib.load(iso_path)
        pred = (iso.predict(X_test) == -1).astype(int)
        results["Isolation Forest (unsupervised)"] = compute_metrics(
            y_test, pred, -iso.score_samples(X_test))

    print(f"Held-out test set: {len(y_test)} flows ({int(y_test.sum())} suspicious)\n")
    print_metrics_table(results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
