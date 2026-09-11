"""
network_detector.py
--------------------
Network flow threat detection using a lightweight known-threat
classifier (Random Forest) combined with unsupervised anomaly
detection (Isolation Forest).

Expected CSV columns:
    source_ip, destination_ip, source_port, destination_port, protocol,
    packet_count, byte_count, duration, flow_rate
"""

import os
import joblib
import numpy as np
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "network_model.pkl")
SAMPLE_DATA_PATH = os.path.join(BASE_DIR, "data", "network_flows.csv")

REQUIRED_COLUMNS = ["source_ip", "destination_ip", "source_port", "destination_port",
                    "protocol", "packet_count", "byte_count", "duration", "flow_rate"]

NUMERIC_FEATURES = ["source_port", "destination_port", "packet_count",
                     "byte_count", "duration", "flow_rate"]

HIGH_RISK_PORTS = {23, 3389, 4444, 6667, 1337, 9001, 31337}


# ---------------------------------------------------------------------------
# Model loading / auto-training
# ---------------------------------------------------------------------------

def _train_model():
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.preprocessing import LabelEncoder

    if not os.path.exists(SAMPLE_DATA_PATH):
        return None

    df = pd.read_csv(SAMPLE_DATA_PATH)
    if "label" not in df.columns:
        return None

    X = df[NUMERIC_FEATURES].fillna(0)
    y = df["label"]

    clf = RandomForestClassifier(n_estimators=150, max_depth=10, random_state=42,
                                  class_weight="balanced")
    clf.fit(X, y)

    iso = IsolationForest(n_estimators=150, contamination=0.15, random_state=42)
    iso.fit(X)

    bundle = {"classifier": clf, "anomaly_detector": iso, "features": NUMERIC_FEATURES}
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(bundle, MODEL_PATH)
    return bundle


def load_model():
    if os.path.exists(MODEL_PATH):
        try:
            return joblib.load(MODEL_PATH)
        except Exception:
            pass
    return _train_model()


# ---------------------------------------------------------------------------
# Validation & demo data
# ---------------------------------------------------------------------------

def validate_columns(df: pd.DataFrame):
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    return missing


def load_demo_data(n=25):
    if os.path.exists(SAMPLE_DATA_PATH):
        df = pd.read_csv(SAMPLE_DATA_PATH)
        return df.sample(min(n, len(df)), random_state=None).reset_index(drop=True)
    return pd.DataFrame(columns=REQUIRED_COLUMNS)


# ---------------------------------------------------------------------------
# Heuristics
# ---------------------------------------------------------------------------

def _flow_indicators(row):
    indicators = []
    dst_port = int(row.get("destination_port", 0) or 0)
    if dst_port in HIGH_RISK_PORTS:
        indicators.append(f"Destination port {dst_port} is commonly associated with remote access "
                           f"or command-and-control tools")
    if row.get("duration", 0) and row.get("packet_count", 0):
        if float(row["duration"]) < 1 and int(row["packet_count"]) <= 10:
            indicators.append("Very short-duration, low-packet-count flow (possible scanning behaviour)")
    if row.get("byte_count", 0) and float(row["byte_count"]) > 1_000_000:
        indicators.append("Unusually large data transfer volume (possible exfiltration pattern)")
    if row.get("flow_rate", 0) and float(row["flow_rate"]) > 500_000:
        indicators.append("Very high flow rate relative to typical baseline traffic")
    return indicators


# ---------------------------------------------------------------------------
# Main analysis entry point
# ---------------------------------------------------------------------------

def analyze_flows(df: pd.DataFrame):
    """
    Analyze a DataFrame of network flows.

    Returns a DataFrame with added columns: classification, risk_score,
    confidence, indicators (semicolon-joined string).
    """
    missing = validate_columns(df)
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    df = df.copy()
    for col in NUMERIC_FEATURES:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    model_bundle = load_model()

    if model_bundle is not None:
        X = df[NUMERIC_FEATURES].fillna(0)
        try:
            preds = model_bundle["classifier"].predict(X)
            proba = model_bundle["classifier"].predict_proba(X)
            classes = model_bundle["classifier"].classes_
            confidences = proba.max(axis=1) * 100
            anomaly_flags = model_bundle["anomaly_detector"].predict(X)  # -1 = anomaly
        except Exception:
            preds = ["BENIGN"] * len(df)
            confidences = [0.0] * len(df)
            anomaly_flags = [1] * len(df)
    else:
        preds = ["BENIGN"] * len(df)
        confidences = [0.0] * len(df)
        anomaly_flags = [1] * len(df)

    classifications = []
    risk_scores = []
    indicators_list = []
    confidence_list = []

    for i, row in df.iterrows():
        base_class = preds[i] if i < len(preds) else "BENIGN"
        is_anomaly = (anomaly_flags[i] == -1) if i < len(anomaly_flags) else False
        conf = round(float(confidences[i]), 1) if i < len(confidences) else 0.0

        flow_inds = _flow_indicators(row)

        # UPGRADE 7: the anomaly detector alone must NOT be enough to relabel a
        # flow as something worse than BENIGN — that previously happened
        # unconditionally whenever IsolationForest flagged a flow, even with
        # zero corroborating rule-based indicators. Now: anomaly + at least
        # one corroborating heuristic indicator -> genuine "ANOMALOUS"
        # reclassification. Anomaly alone (no corroboration) -> stays BENIGN
        # classification-wise, but is surfaced as a clearly-labeled weak
        # signal with a small risk bump, not a relabel.
        anomaly_only_soft_flag = False
        if is_anomaly and base_class == "BENIGN":
            if flow_inds:
                final_class = "ANOMALOUS"
            else:
                final_class = "BENIGN"
                anomaly_only_soft_flag = True
        else:
            final_class = base_class

        base_score = {"BENIGN": 8, "SUSPICIOUS": 45, "MALICIOUS": 80, "ANOMALOUS": 55}.get(final_class, 20)
        heuristic_bonus = min(len(flow_inds) * 10, 30)
        risk = base_score + heuristic_bonus
        if anomaly_only_soft_flag:
            # Small, explainable bump — never enough alone to leave LOW territory —
            # and always accompanied by an indicator explaining exactly why.
            risk += 12
            flow_inds = flow_inds + ["Flagged as statistically unusual by the anomaly detector alone "
                                      "(no corroborating rule-based indicator) — weak signal only, "
                                      "not evidence of malicious activity by itself"]
        risk = min(round(risk), 100)

        classifications.append(final_class)
        risk_scores.append(risk)
        indicators_list.append("; ".join(flow_inds) if flow_inds else "No significant heuristic indicators")
        confidence_list.append(conf)

    df["classification"] = classifications
    df["risk_score"] = risk_scores
    df["confidence"] = confidence_list
    df["indicators"] = indicators_list
    return df


def summarize_flows(analyzed_df: pd.DataFrame):
    """Produce summary counts used by the dashboard."""
    if analyzed_df.empty:
        return {"total": 0, "benign": 0, "suspicious": 0, "malicious": 0, "anomalous": 0,
                "avg_risk": 0, "top_destinations": []}

    counts = analyzed_df["classification"].value_counts().to_dict()
    top_dest = (analyzed_df[analyzed_df["classification"] != "BENIGN"]
                .groupby("destination_ip")["risk_score"].mean()
                .sort_values(ascending=False).head(5))

    return {
        "total": len(analyzed_df),
        "benign": counts.get("BENIGN", 0),
        "suspicious": counts.get("SUSPICIOUS", 0),
        "malicious": counts.get("MALICIOUS", 0),
        "anomalous": counts.get("ANOMALOUS", 0),
        "avg_risk": round(analyzed_df["risk_score"].mean(), 1),
        "top_destinations": list(top_dest.items()),
    }
