"""
Train and evaluate the optional ML detection layer + the anomaly baseline.

Steps
-----
1. Load data/network_traffic.csv and compute features (time-ordered, so the
   per-source window features are correct).
2. Stratified split: 75% training / 25% held-out test.
3. Fit the statistical anomaly baseline on TRAINING NORMAL flows only.
4. Train:
     SUPERVISED   (learn from labels)      : Logistic Regression, Random Forest
     UNSUPERVISED (learn "normal" only)    : Isolation Forest
5. Evaluate every model on the untouched test set — plus the rule engine,
   the anomaly detector, and the full hybrid IDS for comparison.
6. Save models (models/), metrics (reports/ml_metrics.json),
   a Markdown results report and confusion-matrix figures (reports/figures/).

All numbers in the reports are computed here from real predictions.

Usage:
    python -m ml.train_model
"""

import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib  # noqa: E402
import numpy as np  # noqa: E402
import sklearn  # noqa: E402
from sklearn.ensemble import IsolationForest, RandomForestClassifier  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.pipeline import Pipeline  # noqa: E402
from sklearn.preprocessing import FunctionTransformer, StandardScaler  # noqa: E402

from ids.anomaly_detector import AnomalyDetector  # noqa: E402
from ids.risk_engine import calculate_risk_score, classify  # noqa: E402
from ids.rule_engine import analyze_flow, calculate_signature_score  # noqa: E402
from ids.validation import validate_flow  # noqa: E402
from ml.data_prep import ML_FEATURES, feature_matrix, load_dataset, split_indices  # noqa: E402
from ml.evaluate import (  # noqa: E402
    FIGURES_DIR,
    MODELS_DIR,
    REPORTS_DIR,
    compute_metrics,
    plot_confusion_matrix,
    print_metrics_table,
)

SEED = 42


def _log_transform():
    # log1p compresses heavy-tailed traffic counts (bytes can span 6+ orders of magnitude).
    return FunctionTransformer(np.log1p, feature_names_out="one-to-one")


def build_models():
    return {
        "Logistic Regression": Pipeline([
            ("log", _log_transform()),
            ("scale", StandardScaler()),
            ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", random_state=SEED)),
        ]),
        "Random Forest": Pipeline([
            ("log", _log_transform()),
            ("clf", RandomForestClassifier(n_estimators=150, max_depth=12, min_samples_leaf=2,
                                           class_weight="balanced", random_state=SEED, n_jobs=-1)),
        ]),
    }


def evaluate_ids_detectors(records, features, y, test_idx, baseline, rf_model):
    """Compare rule-only, anomaly-only, and hybrid detection on the test set."""
    preds = defaultdict(list)
    per_scenario = defaultdict(lambda: {"total": 0, "flagged": 0})
    X_test = feature_matrix([features[i] for i in test_idx])
    ml_probs = rf_model.predict_proba(X_test)[:, 1]

    for k, i in enumerate(test_idx):
        flow, _ = validate_flow(records[i])
        f = features[i]
        matches = analyze_flow(f, flow)
        sig = calculate_signature_score(matches)
        anom = baseline.calculate_anomaly_score(f)["score"]
        top = matches[0].severity if matches else None
        risk_no_ml = calculate_risk_score(sig, anom, None, top_rule_severity=top)
        risk_ml = calculate_risk_score(sig, anom, ml_probs[k], top_rule_severity=top)

        preds["Rule engine only"].append(int(bool(matches)))
        preds["Anomaly detector only (score>=50)"].append(int(anom >= 50))
        preds["Hybrid: rules + anomaly"].append(int(classify(risk_no_ml) != "NORMAL"))
        hybrid = int(classify(risk_ml) != "NORMAL")
        preds["Hybrid: rules + anomaly + ML"].append(hybrid)

        scen = records[i]["scenario_type"]
        per_scenario[scen]["total"] += 1
        per_scenario[scen]["flagged"] += hybrid
        per_scenario[scen]["label"] = records[i]["label"]

    y_test = y[test_idx]
    results = {name: compute_metrics(y_test, p) for name, p in preds.items()}
    return results, dict(per_scenario)


def write_markdown_report(ml_results, ids_results, per_scenario, meta, importances):
    lines = [
        "# Model & Detection Evaluation Results",
        "",
        f"_Generated automatically by `python -m ml.train_model` on {meta['trained_at']}._",
        "",
        f"* Dataset: `data/network_traffic.csv` — {meta['rows']} flows "
        f"({meta['suspicious_rows']} SUSPICIOUS / {meta['rows'] - meta['suspicious_rows']} NORMAL)",
        f"* Split: stratified {int((1 - meta['test_size']) * 100)}/{int(meta['test_size'] * 100)} "
        f"train/test (seed {SEED}) — test set = {meta['test_rows']} flows",
        f"* Anomaly baseline fitted on {meta['baseline_samples']} NORMAL training flows only",
        f"* scikit-learn {meta['sklearn_version']}",
        "",
        "## 1. Machine-learning models (held-out test set)",
        "",
        "| Model | Type | Accuracy | Precision | Recall | F1 | FPR | ROC-AUC | TP | FP | FN | TN |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for name, m in ml_results.items():
        kind = "Unsupervised" if "Isolation" in name else "Supervised"
        cm = m["confusion_matrix"]
        lines.append(f"| {name} | {kind} | {m['accuracy']:.3f} | {m['precision']:.3f} | "
                     f"{m['recall']:.3f} | {m['f1']:.3f} | {m['false_positive_rate']:.3f} | "
                     f"{m.get('roc_auc', float('nan')):.3f} | {cm['tp']} | {cm['fp']} | "
                     f"{cm['fn']} | {cm['tn']} |")
    lines += [
        "",
        "## 2. IDS detection layers compared (same test set)",
        "",
        "| Detector | Accuracy | Precision | Recall | F1 | FPR | TP | FP | FN | TN |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for name, m in ids_results.items():
        cm = m["confusion_matrix"]
        lines.append(f"| {name} | {m['accuracy']:.3f} | {m['precision']:.3f} | {m['recall']:.3f} "
                     f"| {m['f1']:.3f} | {m['false_positive_rate']:.3f} | {cm['tp']} | {cm['fp']} "
                     f"| {cm['fn']} | {cm['tn']} |")
    lines += [
        "",
        "## 3. Hybrid IDS (with ML) — flag rate per scenario (test set)",
        "",
        "For SUSPICIOUS scenarios the flag rate is the **detection rate** (higher is better).",
        "For NORMAL scenarios it is the **false-positive rate** (lower is better).",
        "",
        "| Scenario | Ground truth | Test flows | Flagged | Flag rate |",
        "|---|---|---|---|---|",
    ]
    for scen, s in sorted(per_scenario.items(), key=lambda kv: (kv[1]["label"], kv[0])):
        rate = s["flagged"] / s["total"] if s["total"] else 0
        lines.append(f"| {scen} | {s['label']} | {s['total']} | {s['flagged']} | {rate:.1%} |")
    lines += [
        "",
        "## 4. Random Forest feature importance",
        "",
        "| Feature | Importance |",
        "|---|---|",
    ]
    for feat, imp in importances:
        lines.append(f"| {feat} | {imp:.3f} |")
    lines += [
        "",
        "## 5. How to read these numbers",
        "",
        "* **Precision** — of the flows we flagged, how many were truly suspicious "
        "(low precision = analyst time wasted on false positives).",
        "* **Recall** — of the truly suspicious flows, how many we caught "
        "(low recall = missed intrusions / false negatives).",
        "* **Accuracy is not enough**: always predicting NORMAL would already score "
        f"{1 - meta['suspicious_rows'] / meta['rows']:.1%} accuracy on this dataset.",
        "* The data is synthetic, so absolute numbers are optimistic compared with real "
        "networks. What matters is the *relative* behaviour of each detection layer.",
        "",
    ]
    (REPORTS_DIR / "model_evaluation.md").write_text("\n".join(lines), encoding="utf-8")


def plot_detector_comparison(ids_results):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    names = list(ids_results)
    metrics = ["precision", "recall", "f1"]
    colors = ["#2a6fdb", "#e0892b", "#2f9e6e"]
    x = np.arange(len(names))
    fig, ax = plt.subplots(figsize=(9, 4.2), dpi=130)
    for k, (metric, color) in enumerate(zip(metrics, colors)):
        vals = [ids_results[n][metric] for n in names]
        bars = ax.bar(x + (k - 1) * 0.26, vals, 0.24, label=metric.capitalize(), color=color)
        ax.bar_label(bars, fmt="%.2f", fontsize=7, padding=2)
    ax.set_xticks(x, [n.replace(" (score>=50)", "") for n in names], fontsize=8)
    ax.set_ylim(0, 1.1)
    ax.set_ylabel("Score")
    ax.set_title("Detection layers on held-out test set")
    ax.legend(frameon=False, ncol=3, loc="upper left")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "detector_comparison.png")
    plt.close(fig)


def main():
    MODELS_DIR.mkdir(exist_ok=True)
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)

    print("[1/6] Loading dataset and extracting features ...")
    df, records, features, y = load_dataset()
    train_idx, test_idx = split_indices(y)
    X = feature_matrix(features)
    X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]
    print(f"      {len(df)} flows | train={len(train_idx)} test={len(test_idx)} "
          f"| suspicious ratio={y.mean():.1%}")

    print("[2/6] Fitting anomaly baseline on NORMAL training flows ...")
    normal_train = [features[i] for i in train_idx if y[i] == 0]
    baseline = AnomalyDetector.fit(normal_train)
    baseline.save(MODELS_DIR / "baseline.json")

    print("[3/6] Training supervised models (Logistic Regression, Random Forest) ...")
    ml_results, fitted = {}, {}
    for name, model in build_models().items():
        model.fit(X_train, y_train)
        proba = model.predict_proba(X_test)[:, 1]
        ml_results[name] = compute_metrics(y_test, (proba >= 0.5).astype(int), proba)
        fitted[name] = model

    print("[4/6] Training unsupervised Isolation Forest on NORMAL training flows ...")
    iso = Pipeline([("log", _log_transform()), ("scale", StandardScaler()),
                    ("clf", IsolationForest(n_estimators=200, contamination="auto",
                                            random_state=SEED))])
    iso.fit(X_train[y_train == 0])
    iso_pred = (iso.predict(X_test) == -1).astype(int)
    ml_results["Isolation Forest (unsupervised)"] = compute_metrics(
        y_test, iso_pred, -iso.score_samples(X_test))

    print("[5/6] Evaluating rule engine, anomaly detector and hybrid IDS ...")
    ids_results, per_scenario = evaluate_ids_detectors(
        records, features, y, test_idx, baseline, fitted["Random Forest"])

    print("[6/6] Saving models, metrics and figures ...")
    joblib.dump(fitted["Logistic Regression"], MODELS_DIR / "logistic_regression.joblib")
    joblib.dump(fitted["Random Forest"], MODELS_DIR / "random_forest.joblib")
    joblib.dump(iso, MODELS_DIR / "isolation_forest.joblib")

    rf = fitted["Random Forest"].named_steps["clf"]
    importances = sorted(zip(ML_FEATURES, rf.feature_importances_), key=lambda t: -t[1])

    meta = {
        "trained_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "rows": int(len(df)),
        "suspicious_rows": int(y.sum()),
        "test_rows": int(len(test_idx)),
        "test_size": 0.25,
        "baseline_samples": len(normal_train),
        "features": ML_FEATURES,
        "sklearn_version": sklearn.__version__,
    }
    (MODELS_DIR / "model_metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    (REPORTS_DIR / "ml_metrics.json").write_text(json.dumps({
        "metadata": meta,
        "ml_models": ml_results,
        "ids_detectors": ids_results,
        "hybrid_per_scenario": per_scenario,
        "random_forest_feature_importance": {f: round(float(v), 4) for f, v in importances},
    }, indent=2), encoding="utf-8")

    for name, m in {**ml_results, **ids_results}.items():
        slug = name.lower().replace(" ", "_").replace(":", "").replace("+", "plus") \
            .replace("(", "").replace(")", "").replace(">=", "ge").replace(",", "")
        plot_confusion_matrix(m, name, FIGURES_DIR / f"confusion_matrix_{slug}.png")
    plot_detector_comparison(ids_results)
    write_markdown_report(ml_results, ids_results, per_scenario, meta, importances)

    print("\n=== ML models (held-out test set) ===")
    print_metrics_table(ml_results)
    print("\n=== IDS detection layers (held-out test set) ===")
    print_metrics_table(ids_results)
    print(f"\n[+] Models  -> {MODELS_DIR}")
    print(f"[+] Report  -> {REPORTS_DIR / 'model_evaluation.md'}")
    print(f"[+] Figures -> {FIGURES_DIR}")


if __name__ == "__main__":
    main()
