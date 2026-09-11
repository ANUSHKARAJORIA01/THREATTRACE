"""
correlation_engine.py
------------------------
Conservative, cross-investigation "related activity" / "campaign
pattern" detection.

Design principles (intentional, do not relax):

1. EXACT MATCH ONLY. This module never uses fuzzy matching, string
   similarity, or NLP — only a literal, case-insensitive match on a
   sender email address, a domain, a full URL, or an IP address counts
   as "shared." A false positive here (claiming two unrelated cases are
   connected) is worse than a false negative, so when in doubt this
   module reports nothing.
2. RISK AND CONFIDENCE STAY SEPARATE. This module never reads or
   averages any detector's risk_score or confidence value. Its own
   "confidence" describes only how much *exact indicator overlap* was
   found (how many indicators, across how many other cases) — never a
   blend of email/network/document confidences.
3. LABELS ARE EARNED, NOT DEFAULT. "Possible Related Activity" and
   "Potential Campaign Pattern" are only ever returned when at least
   one exact shared indicator was actually found. No shared indicator
   -> a plain "not related" result, never a soft warning.
"""

import re

_URL_RE = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)
_DOMAIN_STRIP_RE = re.compile(r'^(https?://)?(www\.)?', re.IGNORECASE)
_IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
_TI_INDICATOR_RE = re.compile(r"Local threat intelligence match:\s*([^\s—]+)")


def _domain_from_url(url):
    stripped = _DOMAIN_STRIP_RE.sub('', url.strip())
    return stripped.split('/')[0].split('?')[0].lower().strip()


def _extract_indicators(compiled_investigation):
    """
    Extract a set of *exact* indicators from one investigation's
    compiled evidence dict (the same shape forensic_engine.
    compile_investigation returns): sender email addresses, sender
    domains, URLs, domains extracted from URLs, and IP addresses
    (from network flows, geolocation lookups, and threat-intelligence
    evidence entries).

    Returns {(indicator_type, indicator_value): source_description}.
    Nothing here is guessed — every value is copied verbatim from a
    stored field.
    """
    indicators = {}

    for email in compiled_investigation.get("email", []) or []:
        subject = email.get("subject") or "untitled"
        sender = (email.get("sender") or "").strip().lower()
        if sender and "@" in sender:
            indicators.setdefault(("sender_email", sender), f"Email sender ({subject})")
            domain = sender.split("@")[-1].strip("> ")
            if domain:
                indicators.setdefault(("domain", domain), f"Email sender domain ({subject})")

        text_blob = " ".join(filter(None, [email.get("indicators"), subject]))
        for url in _URL_RE.findall(text_blob or ""):
            url_l = url.lower()
            indicators.setdefault(("url", url_l), f"URL referenced in email ({subject})")
            domain = _domain_from_url(url_l)
            if domain:
                indicators.setdefault(("domain", domain), f"Domain extracted from email URL ({subject})")

    for net in compiled_investigation.get("network", []) or []:
        dest_ip = (net.get("destination_ip") or "").strip()
        if dest_ip:
            indicators.setdefault(("ip", dest_ip), "Network destination IP")

    for geo in compiled_investigation.get("geolocation", []) or []:
        ip = (geo.get("ip_address") or "").strip()
        if ip:
            indicators.setdefault(("ip", ip), "Geolocation lookup IP")

    for ev in compiled_investigation.get("evidence", []) or []:
        # Threat-intelligence evidence descriptions embed the raw indicator
        # text as "Local threat intelligence match: <indicator> — ...".
        desc = ev.get("description") or ""
        m = _TI_INDICATOR_RE.match(desc)
        if not m:
            continue
        raw = m.group(1).strip().lower()
        if not raw:
            continue
        if raw.startswith("http"):
            indicators.setdefault(("url", raw), "Threat intelligence evidence")
            domain = _domain_from_url(raw)
            if domain:
                indicators.setdefault(("domain", domain), "Threat intelligence evidence")
        elif _IP_RE.match(raw):
            indicators.setdefault(("ip", raw), "Threat intelligence evidence")
        else:
            indicators.setdefault(("domain", raw), "Threat intelligence evidence")

    return indicators


def _empty_result():
    return {
        "related": False,
        "level": "NONE",
        "label": None,
        "confidence": None,
        "shared_indicators": [],
        "related_investigation_ids": [],
        "explanation": "No shared indicators found with any other investigation.",
    }


def find_related_investigations(investigation_id, compiled_investigation, all_investigation_ids=None):
    """
    Compare this investigation's exact indicators against every other
    investigation in the database. Conservative by construction: only
    literal indicator matches count, and the result is always
    "NONE"/related=False unless a real match was found.

    compiled_investigation: the dict for THIS investigation, in the
        same shape forensic_engine.compile_investigation() returns.
    all_investigation_ids: optional pre-fetched list of other
        investigation ids to compare against (as returned by
        db.list_investigations()); if not provided, this module fetches
        them itself. Callers that already listed investigations (e.g.
        risk_engine) can pass this to avoid a duplicate query.
    """
    # Local imports avoid a module-load-time circular import, since
    # forensic_engine and database are both imported by many modules.
    from database import database as db
    from modules import forensic_engine

    if not compiled_investigation:
        return _empty_result()

    my_indicators = _extract_indicators(compiled_investigation)
    if not my_indicators:
        return _empty_result()

    if all_investigation_ids is None:
        all_investigation_ids = [i["id"] for i in db.list_investigations()]

    matches = []
    other_ids_involved = set()

    for other_id in all_investigation_ids:
        if other_id == investigation_id:
            continue
        other_compiled = forensic_engine.compile_investigation(other_id)
        if not other_compiled:
            continue
        other_indicators = _extract_indicators(other_compiled)

        shared_keys = set(my_indicators.keys()) & set(other_indicators.keys())
        for (ind_type, ind_value) in shared_keys:
            matches.append({
                "indicator_type": ind_type,
                "indicator_value": ind_value,
                "other_investigation_id": other_id,
                "other_case_name": other_compiled["investigation"]["case_name"],
            })
            other_ids_involved.add(other_id)

    if not matches:
        return _empty_result()

    distinct_indicator_values = {(m["indicator_type"], m["indicator_value"]) for m in matches}
    distinct_types = {m["indicator_type"] for m in matches}
    num_other_cases = len(other_ids_involved)

    # Confidence is a plain function of overlap breadth/depth found above —
    # never borrowed or averaged from any detector's own score.
    if num_other_cases >= 2 or (len(distinct_indicator_values) >= 2 and len(distinct_types) >= 2):
        level = "POTENTIAL_CAMPAIGN_PATTERN"
        label = "Potential Campaign Pattern"
        confidence = "HIGH" if len(distinct_indicator_values) >= 3 else "MEDIUM"
    else:
        level = "POSSIBLE_RELATED_ACTIVITY"
        label = "Possible Related Activity"
        confidence = "LOW" if len(distinct_indicator_values) == 1 else "MEDIUM"

    return {
        "related": True,
        "level": level,
        "label": label,
        "confidence": confidence,
        "shared_indicators": matches,
        "related_investigation_ids": sorted(other_ids_involved),
        "explanation": (
            f"{len(distinct_indicator_values)} exact indicator(s) shared with "
            f"{num_other_cases} other investigation(s)."
        ),
    }
