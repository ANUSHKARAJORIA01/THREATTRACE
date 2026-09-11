"""
train_document_model.py
--------------------------
Standalone script that trains a lightweight supplementary classifier for
document screening, using synthetic structured features derived from
data/identity_samples.csv (field completeness / date consistency), and
saves it to models/document_model.pkl.

This model provides an optional ML signal that complements (but does not
replace) the rule-based heuristics in modules/document_detector.py.

Run with:
    python training/train_document_model.py

NOTE: Trained entirely on synthetic demo data. Metrics are prototype-only.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, classification_report

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "identity_samples.csv")
MODEL_PATH = os.path.join(BASE_DIR, "models", "document_model.pkl")


def _derive_features(df):
    """Turn identity_samples.csv rows into simple numeric features.
    NOTE: fillna('') before computing string length — df.astype(str) on a
    real NaN produces the literal string 'nan' (length 3), which would
    silently defeat the 'missing field' structural signal in the dataset."""
    feats = pd.DataFrame()
    feats["name_len"] = df["name"].fillna("").astype(str).str.len()
    feats["address_len"] = df["address"].fillna("").astype(str).str.len()
    feats["doc_num_len"] = df["document_number"].fillna("").astype(str).str.len()

    def year_of(s):
        try:
            return int(str(s)[:4])
        except Exception:
            return 0

    issue_year = df["issue_date"].apply(year_of)
    expiry_year = df["expiry_date"].apply(year_of)
    dob_year = df["date_of_birth"].apply(year_of)

    feats["issue_before_expiry"] = (expiry_year > issue_year).astype(int)
    feats["dob_before_issue"] = (issue_year > dob_year).astype(int)
    feats["validity_years"] = expiry_year - issue_year
    return feats


def main():
    print("=" * 60)
    print("Training Document Screening Support Model (PROTOTYPE)")
    print("=" * 60)

    if not os.path.exists(DATA_PATH):
        print(f"ERROR: sample data not found at {DATA_PATH}")
        return

    df = pd.read_csv(DATA_PATH).dropna(subset=["label"])
    print(f"Loaded {len(df)} synthetic identity document records.")

    X = _derive_features(df)
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(n_estimators=100, max_depth=6, random_state=42,
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
          "prototype and are NOT representative of real-world document forensics performance.")

    clf.fit(X, y)
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump({"classifier": clf, "features": list(X.columns)}, MODEL_PATH)
    print(f"\nModel saved to: {MODEL_PATH}")


if __name__ == "__main__":
    main()
