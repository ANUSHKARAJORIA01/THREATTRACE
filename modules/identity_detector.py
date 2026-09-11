"""
identity_detector.py
---------------------
Identity consistency engine.

Compares identity information found in email evidence, document
evidence, and investigator-supplied investigation context, and flags
mismatches. Produces an identity_consistency_score (0-100) — higher is
more consistent. This module screens for inconsistencies; it does NOT
make definitive claims about a person's real-world identity.
"""

import re
from difflib import SequenceMatcher


def _normalize_name(name):
    if not name:
        return ""
    return re.sub(r'[^a-z ]', '', name.lower()).strip()


def _similar(a, b):
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


def compare_identities(email_identity: dict, document_identity: dict, case_context: dict = None):
    """
    email_identity: {"name": ..., "organization": ..., "email": ...}
    document_identity: {"name": ..., "address": ..., "document_number": ...}
    case_context: optional dict with additional investigator-supplied fields

    Returns dict with matches, mismatches, and identity_consistency_score.
    """
    case_context = case_context or {}
    matches = []
    mismatches = []

    email_name = _normalize_name(email_identity.get("name", ""))
    doc_name = _normalize_name(document_identity.get("name", ""))

    if email_name and doc_name:
        similarity = _similar(email_name, doc_name)
        if similarity >= 0.85:
            matches.append(f"Email name and document name are consistent "
                            f"('{email_identity.get('name')}' ≈ '{document_identity.get('name')}')")
        else:
            mismatches.append(f"Email name ('{email_identity.get('name')}') does not closely match "
                               f"document name ('{document_identity.get('name')}')")

    email_org = (email_identity.get("organization") or "").strip().lower()
    doc_org = (case_context.get("expected_organization") or "").strip().lower()
    if email_org and doc_org:
        if email_org == doc_org:
            matches.append(f"Organization referenced in email matches expected organization ({email_org})")
        else:
            mismatches.append(f"Email organization ('{email_org}') differs from expected "
                               f"organization ('{doc_org}')")

    email_addr = (case_context.get("claimed_address") or "").strip().lower()
    doc_addr = (document_identity.get("address") or "").strip().lower()
    if email_addr and doc_addr:
        sim = _similar(email_addr, doc_addr)
        if sim >= 0.6:
            matches.append("Claimed address is broadly consistent with document address")
        else:
            mismatches.append("Claimed address differs substantially from document address")

    total_checks = len(matches) + len(mismatches)
    if total_checks == 0:
        consistency_score = 60  # neutral — insufficient data to compare
    else:
        consistency_score = round((len(matches) / total_checks) * 100)

    return {
        "matches": matches,
        "mismatches": mismatches,
        "identity_consistency_score": consistency_score,
    }
