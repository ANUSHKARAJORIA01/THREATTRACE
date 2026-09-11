"""
risk_engine.py
---------------
Central Intelligence & Risk Correlation Engine.

Combines per-module risk scores (email, network, document, identity,
geolocation, threat intelligence) into a single weighted overall score,
and generates a human-readable explanation of the key contributing
risk factors.

This produces a PROTOTYPE risk score for demonstration/educational
purposes — it is not an absolute probability of maliciousness and
should never be used as the sole basis for a real security decision.
"""

DEFAULT_WEIGHTS = {
    "email": 0.25,
    "network": 0.20,
    "document": 0.20,
    "identity": 0.15,
    "geolocation": 0.10,
    "threat_intelligence": 0.10,
}


def risk_level_from_score(score):
    if score <= 30:
        return "LOW"
    elif score <= 60:
        return "MEDIUM"
    elif score <= 80:
        return "HIGH"
    else:
        return "CRITICAL"


def calculate_overall_risk(module_scores: dict, weights: dict = None):
    """
    module_scores: dict with any subset of keys matching DEFAULT_WEIGHTS,
                    each a 0-100 risk score (or None if not available).
    weights: optional custom weight dict; missing modules are re-normalized.
    """
    weights = weights or DEFAULT_WEIGHTS
    available = {k: v for k, v in module_scores.items() if v is not None and k in weights}

    if not available:
        return 0, "LOW", {}

    total_weight = sum(weights[k] for k in available)
    weighted_sum = sum(available[k] * weights[k] for k in available)
    overall = round(weighted_sum / total_weight) if total_weight > 0 else 0
    overall = max(0, min(overall, 100))

    contributions = {
        k: {
            "score": available[k],
            "weight": weights[k],
            "contribution": round((available[k] * weights[k]) / total_weight, 1) if total_weight else 0
        }
        for k in available
    }

    return overall, risk_level_from_score(overall), contributions


def generate_explanation(module_indicators: dict, overall_score, risk_level):
    """
    module_indicators: dict mapping module name -> list of indicator strings
    Returns a list of top human-readable explanation lines summarizing why
    the case received its risk level.
    """
    explanation = [f"Overall prototype risk score: {overall_score}/100 ({risk_level})."]

    ranked = []
    for module, indicators in module_indicators.items():
        for ind in indicators or []:
            ranked.append(f"[{module.upper()}] {ind}")

    if not ranked:
        explanation.append("No significant risk indicators were identified across analyzed evidence.")
        return explanation

    explanation.append("Key Risk Indicators:")
    explanation.extend(ranked[:10])

    if len(ranked) > 10:
        explanation.append(f"...and {len(ranked) - 10} additional indicator(s) across all evidence.")

    explanation.append(
        "Note: This is a prototype risk assessment based on heuristic and machine-learning "
        "signals. It is intended for educational/demonstration purposes and does not constitute "
        "a definitive determination of malicious intent, fraud, or identity."
    )
    return explanation


def build_module_scores_from_investigation(email_records, network_records,
                                            document_records, geolocation_records,
                                            threat_intel_hits):
    """
    Helper that aggregates raw DB records into per-module average risk
    scores usable by calculate_overall_risk().
    """
    def avg(records, key="risk_score"):
        vals = [r.get(key) for r in records if r.get(key) is not None]
        return round(sum(vals) / len(vals), 1) if vals else None

    email_score = avg(email_records)
    network_score = avg(network_records)
    document_score = avg(document_records)
    identity_score = None
    if document_records:
        id_vals = [r.get("identity_consistency_score") for r in document_records
                   if r.get("identity_consistency_score") is not None]
        if id_vals:
            # invert consistency (higher consistency = lower risk)
            identity_score = round(100 - (sum(id_vals) / len(id_vals)), 1)
    geolocation_score = avg(geolocation_records)

    ti_score = None
    if threat_intel_hits:
        severities = {"LOW": 25, "MEDIUM": 55, "HIGH": 80, "CRITICAL": 95}
        vals = [severities.get(h.get("severity"), 0) for h in threat_intel_hits
                if h.get("status") == "known threat"]
        if vals:
            ti_score = round(sum(vals) / len(vals), 1)
        elif any(h.get("status") == "suspicious" for h in threat_intel_hits):
            ti_score = 45

    return {
        "email": email_score,
        "network": network_score,
        "document": document_score,
        "identity": identity_score,
        "geolocation": geolocation_score,
        "threat_intelligence": ti_score,
    }


def _extract_correlation_indicators(email_records, network_records):
    """
    Pull raw indicators (sender domains, URLs, destination IPs) out of
    stored evidence so they can be run through actual TI lookups.
    URLs aren't stored as their own DB column today, so we recover them
    from the semicolon-joined indicator text where the email module
    logged them (see email_detector.run_heuristics -> "Suspicious URL
    pattern: ... (<url>)"). This is best-effort and never fabricates a
    URL that wasn't actually recorded.
    """
    import re
    senders = []
    urls = []
    dest_ips = []

    for r in email_records or []:
        if r.get("sender"):
            senders.append(r["sender"])
        indicators_text = r.get("indicators") or ""
        urls.extend(re.findall(r'\((https?://[^\s)]+)\)', indicators_text))

    for r in network_records or []:
        if r.get("destination_ip"):
            dest_ips.append(r["destination_ip"])

    return {
        "senders": list(dict.fromkeys(senders)),
        "urls": list(dict.fromkeys(urls)),
        "destination_ips": list(dict.fromkeys(dest_ips)),
    }


def recalculate_case_risk(investigation_id):
    """
    UPGRADE 6 — Centralized risk recalculation.

    This is the SINGLE place that:
      1. Loads all stored evidence for an investigation from the database.
      2. Extracts indicators (sender domains, URLs, destination IPs) and
         runs them through the REAL local threat-intelligence lookups
         (threat_intelligence.correlate_evidence_indicators), so TI hits
         are never fabricated or hardcoded.
      3. Builds per-module scores (including the genuine TI score).
      4. Calculates the weighted overall score + risk level.
      5. Persists overall_risk/risk_level back onto the investigation row.
      6. Returns everything the UI/report need, so no page has to
         reimplement or duplicate this logic.

    Every page in app.py (Overview, Forensic Investigation, Risk Analysis,
    Generate Report) should call this instead of recalculating risk itself.

    Also attaches (additively, without affecting overall_score/module_scores):
      - "correlation": conservative cross-investigation related-activity /
        campaign-pattern detection (correlation_engine.find_related_investigations)
      - "next_steps": evidence-triggered recommended next steps (next_steps.recommend_next_steps)
    """
    # Local import avoids a circular import at module load time
    # (database -> ... -> modules is not a dependency, but forensic_engine
    # and app.py both import risk_engine, so keeping this import local
    # here keeps risk_engine safely importable on its own too).
    from database import database as db
    from modules import threat_intelligence, correlation_engine, next_steps
    from utils import timeline as timeline_utils

    investigation = db.get_investigation(investigation_id)
    if not investigation:
        return None

    email_records = db.get_email_analysis(investigation_id)
    network_records = db.get_network_analysis(investigation_id)
    document_records = db.get_document_analysis(investigation_id)
    geolocation_records = db.get_geolocation_analysis(investigation_id)
    evidence_records = db.get_evidence(investigation_id)

    raw_indicators = _extract_correlation_indicators(email_records, network_records)
    ti_hits = threat_intelligence.correlate_evidence_indicators(
        email_urls=raw_indicators["urls"],
        email_sender=raw_indicators["senders"][0] if raw_indicators["senders"] else None,
        network_destination_ips=raw_indicators["destination_ips"],
    )
    # Also correlate every additional sender beyond the first, if any
    for extra_sender in raw_indicators["senders"][1:]:
        extra_hits = threat_intelligence.correlate_evidence_indicators(email_sender=extra_sender)
        ti_hits.extend(extra_hits)

    module_scores = build_module_scores_from_investigation(
        email_records, network_records, document_records, geolocation_records, ti_hits
    )
    overall, level, contributions = calculate_overall_risk(module_scores)

    db.update_investigation_risk(investigation_id, overall, level)

    module_indicators = {
        "email": [i for r in email_records for i in (r.get("indicators") or "").split(";") if i.strip()],
        "network": [i for r in network_records for i in (r.get("indicators") or "").split(";") if i.strip()],
        "document": [i for r in document_records for i in (r.get("indicators") or "").split(";") if i.strip()],
        "geolocation": [i for r in geolocation_records for i in (r.get("indicators") or "").split(";") if i.strip()],
        "threat_intelligence": [f"{h['indicator']} — {h.get('threat_type') or h['status']} "
                                 f"({h.get('severity') or 'n/a'})" for h in ti_hits],
    }
    explanation = generate_explanation(module_indicators, overall, level)
    timeline_events = timeline_utils.build_timeline(
        email_records, network_records, document_records, geolocation_records, evidence_records
    )

    # --- Conservative cross-investigation correlation + evidence-based next steps ---
    # Additive only: neither of these feeds back into module_scores/overall/level
    # above. Correlation confidence is computed independently by
    # correlation_engine from exact indicator overlap — it is never averaged
    # with, or blended into, any detector's own risk_score/confidence.
    compiled_for_correlation = {
        "investigation": investigation,
        "email": email_records,
        "network": network_records,
        "document": document_records,
        "geolocation": geolocation_records,
        "evidence": evidence_records,
    }
    correlation = correlation_engine.find_related_investigations(
        investigation_id, compiled_for_correlation
    )
    recalc_so_far = {"module_scores": module_scores, "overall_score": overall}
    next_step_list = next_steps.recommend_next_steps(
        compiled_for_correlation, recalc_so_far, correlation
    )

    return {
        "investigation": db.get_investigation(investigation_id),  # re-fetch with updated risk
        "module_scores": module_scores,
        "contributions": contributions,
        "overall_score": overall,
        "risk_level": level,
        "explanation": explanation,
        "module_indicators": module_indicators,
        "threat_intel_hits": ti_hits,
        "email_records": email_records,
        "network_records": network_records,
        "document_records": document_records,
        "geolocation_records": geolocation_records,
        "evidence_records": evidence_records,
        "timeline_events": timeline_events,
        "correlation": correlation,
        "next_steps": next_step_list,
    }
