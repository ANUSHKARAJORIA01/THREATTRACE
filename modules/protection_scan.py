"""
protection_scan.py
--------------------
Lightweight, investigation-independent "Protection Mode" checks.

Protection Mode is for a normal user who just wants a quick answer
about a single email, URL, or file — no case/investigation required.

This module does NOT invent new detection logic. It reshapes the
output of the existing real detectors (email_detector, document_
detector, threat_intelligence) into a simple SAFE / SUSPICIOUS /
DANGEROUS verdict with a risk score, plain-language reasons, and a
recommended action. Because the same underlying engines are used here
and in Investigation Mode, a quick Protection Mode check and a later
full investigation of the same input will never disagree.

Verdict scale (SAFE / SUSPICIOUS / DANGEROUS) is deliberately distinct
from Investigation Mode's LOW / MEDIUM / HIGH / CRITICAL risk_engine
scale — Protection Mode is written for a general user, not an
investigator, so it uses plainer language.
"""

from modules import email_detector, document_detector, threat_intelligence
from utils.preprocessing import suspicious_domain_indicators

TI_SEVERITY_SCORES = {"LOW": 55, "MEDIUM": 75, "HIGH": 90, "CRITICAL": 98}
TI_EVIDENCE_SCORES = {"LOW": 25, "MEDIUM": 55, "HIGH": 80, "CRITICAL": 95}


def classify_protection_risk(score):
    """Map a 0-100 risk score to the Protection Mode verdict."""
    if score <= 30:
        return "SAFE"
    elif score <= 65:
        return "SUSPICIOUS"
    else:
        return "DANGEROUS"


def _recommendation(verdict):
    return {
        "SAFE": "No action needed. Continue to exercise normal caution online.",
        "SUSPICIOUS": "Proceed with caution. Do not enter passwords or personal/financial "
                       "information, and independently verify the sender or source through a "
                       "separate, trusted channel before acting.",
        "DANGEROUS": "Do not open this link or file, and do not reply or provide any "
                      "information. Report or delete it, and consider escalating to a full "
                      "investigation.",
    }[verdict]


def check_email(parsed_email):
    """Protection Mode wrapper around the real email_detector pipeline."""
    result = email_detector.analyze_email(parsed_email)

    ti_hits = threat_intelligence.correlate_evidence_indicators(
        email_urls=result["urls"], email_sender=result["sender"]
    )

    reasons = list(result["indicators"])
    for hit in ti_hits:
        reasons.append(
            f"Threat intelligence match: {hit['indicator']} — "
            f"{hit.get('threat_type') or hit['status']} (severity: {hit.get('severity') or 'n/a'})"
        )

    # A genuine TI hit nudges the score up a bit beyond the base email_detector
    # score — never a fabricated bump, always tied to a real hit found above.
    score = result["risk_score"]
    if any(h.get("status") == "known threat" for h in ti_hits):
        score = min(100, score + 15)
    elif ti_hits:
        score = min(100, score + 8)

    verdict = classify_protection_risk(score)

    return {
        "input_type": "email",
        "summary": result.get("subject") or "(no subject)",
        "risk_score": score,
        "verdict": verdict,
        "classification": result["classification"],
        "reasons": reasons if reasons else ["No heuristic indicators detected."],
        "recommendation": _recommendation(verdict),
        "ti_hits": ti_hits,
        "raw": result,
    }


def check_url(url):
    """
    Protection Mode standalone URL check. Combines the same lightweight
    domain heuristics used inside email_detector with a real local
    threat-intelligence lookup — no separate scoring logic invented.
    """
    url = (url or "").strip()
    reasons = []
    hit = threat_intelligence.check_url(url)
    domain_inds = suspicious_domain_indicators(url)
    reasons.extend(domain_inds)

    score = 5
    if hit.get("status") == "known threat":
        reasons.append(
            f"Matches known threat intelligence indicator "
            f"({hit.get('threat_type') or 'flagged'}, severity {hit.get('severity') or 'n/a'})"
        )
        score = TI_SEVERITY_SCORES.get(hit.get("severity"), 80)
    elif hit.get("status") == "suspicious":
        reasons.append(hit.get("description") or "Domain pattern matches a known flagged domain.")
        score = 60

    score += min(len(domain_inds) * 10, 30)
    score = min(round(score), 100)
    verdict = classify_protection_risk(score)

    return {
        "input_type": "url",
        "summary": url,
        "risk_score": score,
        "verdict": verdict,
        "classification": hit.get("status", "unknown").upper(),
        "reasons": reasons if reasons else ["No suspicious patterns or threat intelligence matches found."],
        "recommendation": _recommendation(verdict),
        "ti_hits": [hit] if hit.get("status") != "unknown" else [],
        "raw": hit,
    }


def check_file(file_bytes, filename, document_type="ID_CARD"):
    """
    Protection Mode standalone file check. Flags high-risk executable
    extensions directly; for image/PDF files, also runs the real
    document_detector screening pipeline as supporting information
    (useful when the "file" is actually a scanned document/screenshot).
    """
    filename = filename or "uploaded_file"
    reasons = []
    score = 5

    risky_ext = (".exe", ".scr", ".js", ".vbs", ".bat", ".ps1", ".jar", ".msi")
    if filename.lower().endswith(risky_ext):
        reasons.append(f"File has a high-risk executable/script extension "
                        f"(.{filename.rsplit('.', 1)[-1]})")
        score = 85

    doc_result = None
    is_image_or_pdf = filename.lower().endswith((".png", ".jpg", ".jpeg", ".pdf")) or \
        document_detector.is_pdf_bytes(file_bytes)
    if is_image_or_pdf:
        doc_result = document_detector.screen_document(file_bytes, filename, document_type)
        reasons.extend(doc_result.get("indicators", []))
        score = max(score, doc_result.get("risk_score", 0))

    verdict = classify_protection_risk(score)

    return {
        "input_type": "file",
        "summary": filename,
        "risk_score": score,
        "verdict": verdict,
        "classification": "DOCUMENT_SCREENED" if doc_result else "FILE_CHECKED",
        "reasons": reasons if reasons else ["No high-risk indicators found in this file."],
        "recommendation": _recommendation(verdict),
        "ti_hits": [],
        "raw": doc_result,
    }
