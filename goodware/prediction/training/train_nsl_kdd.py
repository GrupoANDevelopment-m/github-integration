"""
Goodware v3.0 — Training pipeline para ThreatPredictor com NSL-KDD.

Dataset: NSL-KDD (Network Intrusion Detection)
URL: https://github.com/Jehuty4949/NSL_KDD
Records: 125,973 train + 22,544 test
Features: 41 (network flow characteristics)
Classes: normal + 22 attack types

Pipeline:
1. Load NSL-KDD dataset
2. Encode categorical features (protocol_type, service, flag)
3. Train RandomForest + IsolationForest
4. Save to models/ com metadata
"""
from __future__ import annotations

import json
import logging
import os
import pickle
import sys
from pathlib import Path

import numpy as np

log = logging.getLogger("goodware.prediction.training")


NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty",
]

ATTACK_CATEGORIES = {
    # DoS
    "back": "dos", "land": "dos", "neptune": "dos", "pod": "dos", "smurf": "dos",
    "teardrop": "dos", "apache2": "dos", "udpstorm": "dos", "processtable": "dos",
    "worm": "dos", "mailbomb": "dos",
    # Probe
    "satan": "probe", "ipsweep": "probe", "nmap": "probe", "portsweep": "probe",
    "mscan": "probe", "saint": "probe",
    # R2L
    "guess_passwd": "r2l", "ftp_write": "r2l", "imap": "r2l", "phf": "r2l",
    "multihop": "r2l", "warezmaster": "r2l", "warezclient": "r2l", "spy": "r2l",
    "xlock": "r2l", "xsnoop": "r2l", "snmpguess": "r2l", "snmpgetattack": "r2l",
    "httptunnel": "r2l", "sendmail": "r2l", "named": "r2l",
    # U2R
    "buffer_overflow": "u2r", "loadmodule": "u2r", "rootkit": "u2r", "perl": "u2r",
    "sqlattack": "u2r", "xterm": "u2r", "ps": "u2r",
}


def load_nsl_kdd(path: str) -> tuple:
    """Load NSL-KDD dataset from local file."""
    import pandas as pd
    global pd

    df = pd.read_csv(path, names=NSL_KDD_COLUMNS, header=None)
    # Drop difficulty column
    if "difficulty" in df.columns:
        df = df.drop(columns=["difficulty"])
    # Encode label: normal=0, attack=1
    df["is_attack"] = (df["label"] != "normal").astype(int)
    df["attack_category"] = df["label"].map(lambda x: ATTACK_CATEGORIES.get(x, "other") if x != "normal" else "normal")
    return df


def train_from_nsl_kdd(train_path: str, test_path: str, output_dir: str):
    """Train models using NSL-KDD real dataset."""
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.preprocessing import LabelEncoder, StandardScaler
    from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
    import joblib

    log.info(f"Loading NSL-KDD from {train_path}")
    train_df = load_nsl_kdd(train_path)
    test_df = load_nsl_kdd(test_path)

    log.info(f"Train: {len(train_df)} rows, Test: {len(test_df)} rows")
    log.info(f"Train attack distribution: {train_df['attack_category'].value_counts().to_dict()}")

    # Encode categorical
    encoders = {}
    for col in ["protocol_type", "service", "flag"]:
        le = LabelEncoder()
        all_values = pd.concat([train_df[col], test_df[col]]).unique()
        le.fit(all_values)
        train_df[col + "_enc"] = le.transform(train_df[col])
        test_df[col + "_enc"] = le.transform(test_df[col])
        encoders[col] = le

    # Features — usar apenas colunas numéricas + as encoded
    feature_cols = [
        "duration", "src_bytes", "dst_bytes", "land", "wrong_fragment",
        "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
        "root_shell", "su_attempted", "num_root", "num_file_creations",
        "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
        "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
        "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
        "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
        "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
        "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
        "dst_host_serror_rate", "dst_host_srv_serror_rate",
        "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
        "protocol_type_enc", "service_enc", "flag_enc",
    ]
    X_train = train_df[feature_cols].values
    y_train = train_df["is_attack"].values
    X_test = test_df[feature_cols].values
    y_test = test_df["is_attack"].values

    # Scale
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train RandomForest
    log.info("Training RandomForest...")
    rf = RandomForestClassifier(n_estimators=100, max_depth=20, n_jobs=-1, random_state=42)
    rf.fit(X_train_scaled, y_train)

    train_acc = rf.score(X_train_scaled, y_train)
    test_acc = rf.score(X_test_scaled, y_test)
    log.info(f"RF train accuracy: {train_acc:.4f}, test accuracy: {test_acc:.4f}")

    y_pred = rf.predict(X_test_scaled)
    log.info(f"\n{classification_report(y_test, y_pred, target_names=['normal','attack'])}")

    # Train IsolationForest (unsupervised anomaly detection)
    log.info("Training IsolationForest...")
    iso = IsolationForest(n_estimators=100, contamination=0.05, random_state=42, n_jobs=-1)
    iso.fit(X_train_scaled)
    iso_train_acc = iso.score_samples(X_train_scaled).mean()

    # Save
    os.makedirs(output_dir, exist_ok=True)
    joblib.dump(rf, os.path.join(output_dir, "threat_predictor_nsl_kdd.joblib"))
    joblib.dump(iso, os.path.join(output_dir, "anomaly_detector_nsl_kdd.joblib"))
    joblib.dump(scaler, os.path.join(output_dir, "scaler_nsl_kdd.joblib"))

    for col, enc in encoders.items():
        joblib.dump(enc, os.path.join(output_dir, f"encoder_{col}.joblib"))

    # Save metadata
    metadata = {
        "dataset": "NSL-KDD",
        "train_rows": int(len(train_df)),
        "test_rows": int(len(test_df)),
        "features": feature_cols,
        "train_accuracy": float(train_acc),
        "test_accuracy": float(test_acc),
        "iso_train_score_mean": float(iso_train_acc),
        "attack_categories": list(set(ATTACK_CATEGORIES.values())),
        "trained_at": "2026-09-28",
        "source": "https://github.com/Jehuty4949/NSL_KDD",
    }
    with open(os.path.join(output_dir, "training_metadata_nsl_kdd.json"), "w") as f:
        json.dump(metadata, f, indent=2)

    log.info(f"Models saved to {output_dir}")
    return metadata


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--train", default="/workspace/NSL_KDD/KDDTrain+.txt")
    parser.add_argument("--test", default="/workspace/NSL_KDD/KDDTest+.txt")
    parser.add_argument("--output", default="/workspace/goodware-v3/models")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
    train_from_nsl_kdd(args.train, args.test, args.output)
