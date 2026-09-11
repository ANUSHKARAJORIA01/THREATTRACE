"""
train_email_model.py
----------------------
Standalone script to train (or retrain) the email threat classification
model from data/email_samples.csv and save it to models/email_model.pkl.

Run with:
    python training/train_email_model.py

NOTE: The training data is synthetic/demo data created for this prototype.
Reported metrics reflect performance on this synthetic dataset only and
are NOT representative of real-world production accuracy.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, classification_report

from utils.preprocessing import clean_text

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "email_samples.csv")
MODEL_PATH = os.path.join(BASE_DIR, "models", "email_model.pkl")


def main():
    print("=" * 60)
    print("Training Email Threat Classification Model (PROTOTYPE)")
    print("=" * 60)

    if not os.path.exists(DATA_PATH):
        print(f"ERROR: sample data not found at {DATA_PATH}")
        return

    df = pd.read_csv(DATA_PATH).dropna(subset=["text", "label"])
    print(f"Loaded {len(df)} synthetic sample emails.")

    X = df["text"].apply(clean_text)
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(max_features=3000, ngram_range=(1, 2), stop_words="english")),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced")),
    ])

    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)

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

    # Retrain on the full dataset for the deployed model
    pipeline.fit(X, y)
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    print(f"\nModel saved to: {MODEL_PATH}")


if __name__ == "__main__":
    main()
