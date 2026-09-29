"""
Shared data preparation for training AND evaluation.

Using one function for both guarantees the evaluation uses exactly the same
features and the same held-out test split as training (no accidental leakage).
"""

from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from ids.feature_extractor import extract_features_for_records

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATASET_PATH = PROJECT_ROOT / "data" / "network_traffic.csv"

# The 10 features the ML models learn from (see README "Machine Learning").
ML_FEATURES = [
    "packet_count",
    "byte_count",
    "duration",
    "bytes_per_second",
    "packets_per_second",
    "connection_count",
    "failed_connection_count",
    "syn_count",
    "rst_count",
    "average_packet_size",
]

TEST_SIZE = 0.25
RANDOM_STATE = 42


def load_dataset(path=DATASET_PATH):
    """Load the CSV and compute features (in time order) for every flow."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found. Run: python -m simulator.generate_dataset")
    df = pd.read_csv(path)
    if df.empty:
        raise ValueError("Dataset is empty — nothing to train on.")
    records = df.to_dict(orient="records")
    features = extract_features_for_records(records)
    y = (df["label"] == "SUSPICIOUS").astype(int).to_numpy()
    return df, records, features, y


def feature_matrix(features, columns=ML_FEATURES):
    """List of feature dicts -> pandas DataFrame with a fixed column order."""
    return pd.DataFrame([{c: float(f[c]) for c in columns} for f in features], columns=columns)


def split_indices(y, test_size=TEST_SIZE, seed=RANDOM_STATE):
    """Stratified split so both sets keep the same NORMAL/SUSPICIOUS ratio."""
    idx = np.arange(len(y))
    train_idx, test_idx = train_test_split(idx, test_size=test_size, stratify=y,
                                           random_state=seed)
    return np.sort(train_idx), np.sort(test_idx)
