"""
email_detector.py
------------------
AI + heuristic-based email threat detection.

Pipeline:
    Email Text -> Text Cleaning -> TF-IDF -> Logistic Regression -> Classification

If no trained model is found on disk, one is trained automatically from
data/email_samples.csv the first time the module is used.

This module performs SCREENING / CLASSIFICATION only. It does not claim
that any heuristic finding proves malicious intent — indicators are
presented as supporting signals for human review.
"""

import os
import re
import email
from email import policy
from email.parser import BytesParser
import joblib
import pandas as pd

from utils.preprocessing import (
    clean_text, extract_urls, extract_emails, count_urgent_language,
    suspicious_domain_indicators
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "email_model.pkl")
SAMPLE_DATA_PATH = os.path.join(BASE_DIR, "data", "email_samples.csv")

CLASSES = ["BENIGN", "PHISHING", "SCAM", "IMPERSONATION"]


# ---------------------------------------------------------------------------
# Model loading / auto-training
# ---------------------------------------------------------------------------

def _train_model():
    """Train a TF-IDF + Logistic Regression classifier from sample data."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline

    if not os.path.exists(SAMPLE_DATA_PATH):
        return None

    df = pd.read_csv(SAMPLE_DATA_PATH)
    df = df.dropna(subset=["text", "label"])
    X = df["text"].apply(clean_text)
    y = df["label"]

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(max_features=3000, ngram_range=(1, 2), stop_words="english")),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced")),
    ])
    pipeline.fit(X, y)

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    return pipeline


def load_model():
    """Load the trained model, training it automatically if missing."""
    if os.path.exists(MODEL_PATH):
        try:
            return joblib.load(MODEL_PATH)
        except Exception:
            pass
    return _train_model()


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def parse_eml_bytes(raw_bytes):
    """Parse a .eml file's raw bytes into a normalized dict."""
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    except Exception as e:
        return {"error": f"Could not parse .eml file: {e}"}

    sender = msg.get("From", "")
    receiver = msg.get("To", "")
    subject = msg.get("Subject", "")
    reply_to = msg.get("Reply-To", "")
    date = msg.get("Date", "")

    body = ""
    try:
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body += part.get_content()
        else:
            body = msg.get_content()
    except Exception:
        body = ""

    attachments = []
    try:
        for part in msg.iter_attachments():
            fname = part.get_filename()
            if fname:
                attachments.append(fname)
    except Exception:
        pass

    headers = {k: v for k, v in msg.items()}

    return {
        "sender": sender,
        "receiver": receiver,
        "subject": subject,
        "reply_to": reply_to,
        "date": date,
        "body": body,
        "attachments": attachments,
        "headers": headers,
        "error": None,
    }


def parse_plain_text(text, sender="", receiver="", subject=""):
    """Wrap manually pasted / .txt email content into the same normalized dict."""
    return {
        "sender": sender,
        "receiver": receiver,
        "subject": subject,
        "reply_to": "",
        "date": "",
        "body": text,
        "attachments": [],
        "headers": {},
        "error": None,
    }


# ---------------------------------------------------------------------------
# Heuristic checks
# ---------------------------------------------------------------------------

def _sender_replyto_mismatch(sender, reply_to):
    if not sender or not reply_to:
        return False
    sender_domain = sender.split("@")[-1].strip(">").lower() if "@" in sender else ""
    reply_domain = reply_to.split("@")[-1].strip(">").lower() if "@" in reply_to else ""
    return bool(sender_domain and reply_domain and sender_domain != reply_domain)


def run_heuristics(parsed_email):
    """Run rule-based checks. Returns a list of human-readable indicator strings."""
    indicators = []
    body = parsed_email.get("body", "") or ""
    subject = parsed_email.get("subject", "") or ""
    sender = parsed_email.get("sender", "") or ""
    reply_to = parsed_email.get("reply_to", "") or ""
    full_text = f"{subject} {body}"

    urgent_hits = count_urgent_language(full_text)
    if urgent_hits:
        indicators.append(f"Urgent / pressure language detected ({len(urgent_hits)} phrase(s): "
                           f"{', '.join(urgent_hits[:5])})")

    urls = extract_urls(body)
    if len(urls) > 3:
        indicators.append(f"Excessive number of links in message body ({len(urls)} links)")
    for url in urls[:5]:
        for ind in suspicious_domain_indicators(url):
            indicators.append(f"Suspicious URL pattern: {ind} ({url})")

    if _sender_replyto_mismatch(sender, reply_to):
        indicators.append(f"Sender / Reply-To domain mismatch ({sender} vs {reply_to})")

    if re.search(r'(dear (customer|user|valued))', full_text, re.IGNORECASE):
        indicators.append("Generic impersonal greeting typical of mass phishing campaigns")

    if re.search(r'(gift card|wire transfer|bank details|social security|routing number)',
                 full_text, re.IGNORECASE):
        indicators.append("Request for sensitive financial or personal information")

    if parsed_email.get("attachments"):
        risky_ext = [a for a in parsed_email["attachments"]
                     if a.lower().endswith((".exe", ".scr", ".js", ".vbs", ".bat"))]
        if risky_ext:
            indicators.append(f"Attachment(s) with high-risk executable extensions: {risky_ext}")

    return indicators


# ---------------------------------------------------------------------------
# Main analysis entry point
# ---------------------------------------------------------------------------

def analyze_email(parsed_email):
    """
    Run the full email analysis pipeline (ML classification + heuristics).

    Returns a dict with classification, risk_score, confidence, and indicators.
    This is a prototype screening tool — findings should be treated as
    supporting signals for a human investigator, not proof of malicious intent.
    """
    model = load_model()
    body = parsed_email.get("body", "") or ""
    subject = parsed_email.get("subject", "") or ""
    text = clean_text(f"{subject} {body}")

    classification = "BENIGN"
    confidence = 0.0

    if model is not None and text.strip():
        try:
            proba = model.predict_proba([text])[0]
            classes = model.named_steps["clf"].classes_
            best_idx = proba.argmax()
            classification = classes[best_idx]
            confidence = round(float(proba[best_idx]) * 100, 1)
        except Exception:
            classification = "BENIGN"
            confidence = 0.0
    else:
        classification = "BENIGN"
        confidence = 0.0

    indicators = run_heuristics(parsed_email)

    # Safety net for the screening pipeline: if the ML model says BENIGN but
    # multiple independent phishing indicators are present, do not silently
    # label the message BENIGN. The final label becomes PHISHING and is marked
    # as rule-supported. This is still a screening signal for human review.
    strong_phishing_signals = 0
    indicator_text = " ".join(indicators).lower()
    if "urgent / pressure language detected" in indicator_text:
        strong_phishing_signals += 1
    if "suspicious url pattern" in indicator_text:
        strong_phishing_signals += 1
    if "generic impersonal greeting" in indicator_text:
        strong_phishing_signals += 1
    if "request for sensitive financial" in indicator_text:
        strong_phishing_signals += 1
    if classification == "BENIGN" and strong_phishing_signals >= 2:
        classification = "PHISHING"
        classification_source = "ML + rule-based screening"
    else:
        classification_source = "ML model"

    # Blend ML confidence with heuristic signal count into a 0-100 risk score.
    base_score = {"BENIGN": 5, "PHISHING": 55, "SCAM": 55, "IMPERSONATION": 55}.get(classification, 20)
    ml_component = base_score + (confidence * 0.3 if classification != "BENIGN" else 0)
    heuristic_component = min(len(indicators) * 8, 40)
    risk_score = min(round(ml_component + heuristic_component), 100)

    if classification == "BENIGN" and not indicators:
        risk_score = min(risk_score, 15)

    return {
        "sender": parsed_email.get("sender", ""),
        "receiver": parsed_email.get("receiver", ""),
        "subject": parsed_email.get("subject", ""),
        "classification": classification,
        "confidence": confidence,
        "classification_source": classification_source,
        "risk_score": risk_score,
        "indicators": indicators,
        "urls": extract_urls(body),
        "headers": parsed_email.get("headers", {}),
        "attachments": parsed_email.get("attachments", []),
    }
