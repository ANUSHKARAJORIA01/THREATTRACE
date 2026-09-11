"""
train_network_model.py
------------------------
Standalone script to train the network flow threat classifier (Random
Forest) plus anomaly detector (Isolation Forest) from
data/network_flows.csv, saving both to models/network_model.pkl.

Run with:
    python training/train_network_model.py

NOTE: The training data is synthetic/demo data. Reported metrics are
prototype-only and do not reflect real-world network security performance.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, classification_report

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "network_flows.csv")
MODEL_PATH = os.path.join(BASE_DIR, "models", "network_model.pkl")

NUMERIC_FEATURES = ["source_port", "destination_port", "packet_count",
                     "byte_count", "duration", "flow_rate"]


def main():
    print("=" * 60)
    print("Training Network Threat Detection Model (PROTOTYPE)")
    print("=" * 60)

    if not os.path.exists(DATA_PATH):
        print(f"ERROR: sample data not found at {DATA_PATH}")
        return

    df = pd.read_csv(DATA_PATH).dropna(subset=["label"])
    print(f"Loaded {len(df)} synthetic network flow records.")

    X = df[NUMERIC_FEATURES].fillna(0)
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(n_estimators=150, max_depth=10, random_state=42,
                                  class_weight="balanced")
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="weighted", zero_division=0)

    print("\n--- PROTOTYPE Evaluation Metrics (synthetic demo data only) ---")
    print(f"Accuracy : {acc:.3f}")
    print(f"Precision: {precision:.3f}")
    print(f"Recall   : {recall:.3f}")
    print(f"F1 Score : {f1:.3f}")
    print("\nDetailed classification report:")
    print(classification_report(y_test, y_pred, zero_division=0))
    print("NOTE: These metrics are computed on a small synthetic dataset created for this "
          "prototype and are NOT representative of real-world production performance.")

    # Retrain classifier on full data, fit anomaly detector on full data too
    clf.fit(X, y)
    iso = IsolationForest(n_estimators=150, contamination=0.15, random_state=42)
    iso.fit(X)

    bundle = {"classifier": clf, "anomaly_detector": iso, "features": NUMERIC_FEATURES}
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(bundle, MODEL_PATH)
    print(f"\nModel bundle saved to: {MODEL_PATH}")


if __name__ == "__main__":
    main()
