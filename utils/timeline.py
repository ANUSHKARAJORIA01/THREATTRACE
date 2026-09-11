"""
timeline.py
-----------
Builds a chronological forensic timeline for an investigation by
merging events from all evidence tables and, when applicable, generic
evidence log entries.

UPGRADE 10: timestamp parsing previously assumed exactly the
"%Y-%m-%d %H:%M:%S" format the app itself writes, silently sorting any
other format (ISO strings, datetime objects, timestamps with
microseconds/timezone suffixes, or missing values) to the very
beginning of the timeline. _parse_timestamp() below tries several
strategies and always returns *something* sortable — a safe fallback,
never a crash.
"""

from datetime import datetime
import pandas as pd

try:
    from dateutil import parser as dateutil_parser
    DATEUTIL_AVAILABLE = True
except Exception:
    DATEUTIL_AVAILABLE = False

# Common exact formats to try before falling back to the more lenient
# (but slower) dateutil parser.
_KNOWN_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%d",
]


def _parse_timestamp(value):
    """
    Best-effort parse of a timestamp value into a datetime for sorting.
    Handles: real datetime objects, ISO-8601 strings (with or without
    'T', microseconds, or a timezone suffix), the app's own
    "%Y-%m-%d %H:%M:%S" format, and missing/unparseable values (falls
    back to datetime.min so they sort first rather than raising).
    """
    if value is None or value == "":
        return datetime.min

    if isinstance(value, datetime):
        # Strip tzinfo for consistent comparison against naive datetimes
        return value.replace(tzinfo=None) if value.tzinfo else value

    value_str = str(value).strip()

    for fmt in _KNOWN_FORMATS:
        try:
            return datetime.strptime(value_str, fmt)
        except ValueError:
            continue

    if DATEUTIL_AVAILABLE:
        try:
            parsed = dateutil_parser.parse(value_str)
            return parsed.replace(tzinfo=None) if parsed.tzinfo else parsed
        except Exception:
            pass

    return datetime.min


def build_timeline(email_records, network_records, document_records,
                    geolocation_records, evidence_records):
    """
    Combine timestamped events from every module into one sorted list
    of dicts: {"time": datetime, "event": str, "category": str, "risk": float}
    """
    events = []

    for r in email_records:
        events.append({
            "time": r.get("timestamp"),
            "event": f"Email analyzed — sender: {r.get('sender') or 'unknown'} "
                      f"→ classification: {r.get('classification')}",
            "category": "Email",
            "risk": r.get("risk_score") or 0,
        })

    for r in network_records:
        events.append({
            "time": r.get("timestamp"),
            "event": f"Network flow analyzed — {r.get('source_ip')} → {r.get('destination_ip')} "
                      f"→ classification: {r.get('classification')}",
            "category": "Network",
            "risk": r.get("risk_score") or 0,
        })

    for r in document_records:
        events.append({
            "time": r.get("timestamp"),
            "event": f"Document screened — {r.get('document_name')} "
                      f"(authenticity score: {r.get('authenticity_score')})",
            "category": "Document",
            "risk": r.get("risk_score") or 0,
        })

    for r in geolocation_records:
        events.append({
            "time": r.get("timestamp"),
            "event": f"Geolocation analyzed — {r.get('ip_address')} "
                      f"→ {r.get('city')}, {r.get('country')}",
            "category": "Geolocation",
            "risk": r.get("risk_score") or 0,
        })

    for r in evidence_records:
        events.append({
            "time": r.get("timestamp"),
            "event": r.get("description"),
            "category": r.get("evidence_type") or "Evidence",
            "risk": r.get("risk_score") or 0,
        })

    # Sort chronologically using the robust parser — never raises, missing
    # or malformed timestamps fall back to sorting first rather than crashing.
    events.sort(key=lambda e: _parse_timestamp(e["time"]))
    return events


def timeline_to_dataframe(events):
    if not events:
        return pd.DataFrame(columns=["time", "event", "category", "risk"])
    return pd.DataFrame(events)
