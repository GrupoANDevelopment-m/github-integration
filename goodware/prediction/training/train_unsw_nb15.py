"""
Goodware v3.0 — Training pipeline com UNSW-NB15 (REAL dataset).

Dataset: UNSW-NB15 (UNSW Sydney)
Source: https://github.com/notsodubeyous/IoT-Network-Intrusion-Detection-System-UNSW-NB15
Records: 175,341 (binary classification: normal vs attack)
Features: 45 (network flow characteristics)
Classes: Normal, Attack (Generic, DoS, Reconnaissance, etc.)

Este é um dataset mais moderno e balanceado que NSL-KDD.
"""
from __future__ import annotations

import json
import logging
import os

import numpy as np
import pandas as pd

log = logging.getLogger("goodware.prediction.training.unsw")


def load_unsw_nb15(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, encoding="utf-8-sig", low_memory=False)
    df = df.drop(columns=["id"], errors="ignore")
    # Limpar
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    return df


def train_from_unsw_nb15(csv_path: str, output_dir: str):
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.preprocessing import LabelEncoder
    from sklearn.metrics import classification_report, accuracy_score
    import joblib

    log.info(f"Loading UNSW-NB15 from {csv_path}")
    df = load_unsw_nb15(csv_path)
    log.info(f"Loaded {len(df)} rows")

    # Encode categorical
    encoders = {}
    for col in ["proto", "service", "state"]:
        if col in df.columns:
            le = LabelEncoder()
            df[col + "_enc"] = le.fit_transform(df[col].astype(str))
            encoders[col] = le

    # Features (sem colunas object)
    feature_cols = [c for c in df.columns
                    if c not in ("attack_cat", "label", "proto", "service", "state")
                    and df[c].dtype in [np.int64, np.float64, np.int32, np.float32]]
    feature_cols = [c for c in feature_cols if c + "_enc" not in df.columns]
    feature_cols += [c + "_enc" for c in encoders.keys()]

    X = df[feature_cols].values.astype(np.float32)
    y = df["label"].values.astype(int)

    log.info(f"Features: {len(feature_cols)}")
    log.info(f"Class balance: {dict(zip(*np.unique(y, return_counts=True)))}")

    # Split 80/20
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # Train RandomForest
    log.info("Training RandomForest...")
    rf = RandomForestClassifier(n_estimators=100, max_depth=20, n_jobs=-1, random_state=42)
    rf.fit(X_train, y_train)

    train_acc = rf.score(X_train, y_train)
    test_acc = rf.score(X_test, y_test)
    log.info(f"Train acc: {train_acc:.4f}, Test acc: {test_acc:.4f}")

    y_pred = rf.predict(X_test)
    log.info(f"\n{classification_report(y_test, y_pred, target_names=['normal', 'attack'])}")

    # IsolationForest
    log.info("Training IsolationForest...")
    iso = IsolationForest(n_estimators=100, contamination=0.3, random_state=42, n_jobs=-1)
    iso.fit(X_train)

    # Save
    os.makedirs(output_dir, exist_ok=True)
    joblib.dump(rf, os.path.join(output_dir, "threat_predictor_unsw_nb15.joblib"))
    joblib.dump(iso, os.path.join(output_dir, "anomaly_detector_unsw_nb15.joblib"))
    for col, enc in encoders.items():
        joblib.dump(enc, os.path.join(output_dir, f"encoder_unsw_{col}.joblib"))

    metadata = {
        "dataset": "UNSW-NB15",
        "source": "https://github.com/notsodubeyous/IoT-Network-Intrusion-Detection-System-UNSW-NB15",
        "rows_after_cleaning": int(len(df)),
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "features": feature_cols,
        "train_accuracy": float(train_acc),
        "test_accuracy": float(test_acc),
        "trained_at": "2026-09-29",
    }
    with open(os.path.join(output_dir, "training_metadata_unsw_nb15.json"), "w") as f:
        json.dump(metadata, f, indent=2)
    log.info(f"Saved to {output_dir}")
    return metadata


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="/workspace/goodware-v3/data/unsw_nb15/UNSW_NB15.csv")
    parser.add_argument("--output", default="/workspace/goodware-v3/models")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
    train_from_unsw_nb15(args.input, args.output)
