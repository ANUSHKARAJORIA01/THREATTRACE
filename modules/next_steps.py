"""
next_steps.py
---------------
Conservative, evidence-based "recommended next steps" for an
investigator.

Every suggestion here is triggered by a concrete, checkable condition
in the actual evidence already on file for the case (a missing
evidence type that would help, a genuine threat-intelligence match, a
real correlation_engine finding, a high overall score) — never generic
filler, and never a suggestion for an evidence type this particular
case has no reason to need (see the platform's identity/document
module notes: identity checks are only suggested when the email
itself makes an impersonation-style claim worth checking, not for
every case by default).
"""


def recommend_next_steps(compiled_investigation, recalc_summary, correlation_result=None):
    """
    compiled_investigation: dict shaped like forensic_engine.compile_investigation().
    recalc_summary: dict with at least "module_scores" and "overall_score"
        (a full risk_engine.recalculate_case_risk() result works fine).
    correlation_result: optional dict from correlation_engine.find_related_investigations().

    Returns a list of {"step": str, "reason": str} dicts, in priority order.
    """
    if not compiled_investigation:
        return []

    recalc_summary = recalc_summary or {}
    module_scores = recalc_summary.get("module_scores") or {}
    steps = []

    has_email = bool(compiled_investigation.get("email"))
    has_network = bool(compiled_investigation.get("network"))
    has_document = bool(compiled_investigation.get("document"))
    has_geo = bool(compiled_investigation.get("geolocation"))
    ti_score = module_scores.get("threat_intelligence")
    overall = recalc_summary.get("overall_score")

    if has_email and not has_network:
        steps.append({
            "step": "Request email server / firewall logs for the sender's connection to "
                    "corroborate the email evidence with network-level indicators.",
            "reason": "Email evidence is present but no network evidence has been added to this case.",
        })

    if has_email and not has_document:
        # Only suggested when the email itself makes an impersonation-style claim —
        # identity checks stay an optional, evidence-triggered step, not a default
        # ask on every case (per the platform's own identity-module guidance).
        for email in compiled_investigation.get("email", []):
            if (email.get("classification") or "").upper() in ("PHISHING", "SCAM", "IMPERSONATION"):
                steps.append({
                    "step": "If the sender claims to represent a real person or organization, "
                            "request a supporting identity document for screening.",
                    "reason": f"Email was classified as {email.get('classification')}, which often "
                              f"involves an impersonation claim worth checking.",
                })
                break

    if ti_score is not None and ti_score >= 60:
        steps.append({
            "step": "Escalate to a threat-intelligence analyst to check the matched "
                    "indicator(s) against additional external feeds.",
            "reason": f"A local threat-intelligence match was found (module score {ti_score}/100).",
        })

    if has_network and not has_geo:
        steps.append({
            "step": "Run a geolocation lookup on the destination IP(s) for additional "
                    "supporting context.",
            "reason": "Network evidence is present but no geolocation lookup has been recorded.",
        })

    if overall is not None and overall >= 70:
        steps.append({
            "step": "Preserve all current evidence (export a report) before taking any "
                    "remediation action, in case further investigation is needed.",
            "reason": f"Overall case risk is high ({overall}/100).",
        })

    if correlation_result and correlation_result.get("related"):
        related_ids = ", ".join(f"INV-{i:04d}" for i in correlation_result["related_investigation_ids"])
        steps.append({
            "step": f"Cross-reference this case with {related_ids} — they share exact "
                    f"indicator(s) with this investigation.",
            "reason": f"{correlation_result.get('label')}: {correlation_result.get('explanation', '')}",
        })

    if not steps:
        steps.append({
            "step": "No further evidence-based next steps identified from the current "
                    "evidence — continue monitoring or add more evidence as it becomes available.",
            "reason": "No specific evidence gaps or high-risk signals were detected.",
        })

    return steps
