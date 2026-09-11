"""
threat_intelligence.py
------------------------
Local, offline threat-intelligence lookup service.

Loads a synthetic demo dataset (data/threat_data.csv) of fictional
indicators (IPs, domains, URLs) and exposes lookup functions. External
threat-intel API integration is optional and never required for the
application to function.

UPGRADE NOTE: check_url() previously used naive substring matching
(`known_domain in url`), which produced false positives — e.g. a known
domain "evil.com" would incorrectly match "notevil.com" because the
substring "evil.com" appears inside it. This version parses the actual
hostname out of the URL via urllib.parse and compares it (or its
registrable suffix) exactly against known domains instead.
"""

import os
import re
from urllib.parse import urlparse
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
THREAT_DATA_PATH = os.path.join(BASE_DIR, "data", "threat_data.csv")

_cache = None


def _load_data():
    global _cache
    if _cache is not None:
        return _cache
    if os.path.exists(THREAT_DATA_PATH):
        _cache = pd.read_csv(THREAT_DATA_PATH)
    else:
        _cache = pd.DataFrame(columns=["indicator", "indicator_type", "threat_type",
                                        "severity", "description"])
    return _cache


def _lookup(value, indicator_type):
    df = _load_data()
    if df.empty or not value:
        return None
    matches = df[(df["indicator"].str.lower() == value.lower()) &
                 (df["indicator_type"] == indicator_type)]
    if matches.empty:
        return None
    row = matches.iloc[0]
    return {
        "indicator": row["indicator"],
        "indicator_type": row["indicator_type"],
        "threat_type": row["threat_type"],
        "severity": row["severity"],
        "description": row["description"],
        "status": "known threat",
    }


def _extract_hostname(url_or_domain):
    """Return a lowercased hostname for either a bare domain or a full URL."""
    value = (url_or_domain or "").strip()
    if not value:
        return ""
    if "://" not in value:
        value = "http://" + value  # let urlparse split host from path reliably
    try:
        host = urlparse(value).hostname or ""
    except Exception:
        host = ""
    return host.lower()


def _domain_matches(known_domain, hostname):
    """
    Exact-or-subdomain match only — NOT substring match.
    'secure-verify-account.com' matches hostname 'secure-verify-account.com'
    and 'login.secure-verify-account.com', but NOT 'notsecure-verify-account.com'
    or 'secure-verify-account.com.evil.net'.
    """
    known_domain = (known_domain or "").strip().lower()
    if not known_domain or not hostname:
        return False
    return hostname == known_domain or hostname.endswith("." + known_domain)


def check_ip(ip_address):
    result = _lookup(ip_address, "ip")
    if result:
        return result
    return {"indicator": ip_address, "indicator_type": "ip", "status": "unknown",
            "severity": None, "threat_type": None, "description": None}


def check_domain(domain):
    result = _lookup(domain, "domain")
    if result:
        return result

    hostname = _extract_hostname(domain)
    df = _load_data()
    if not df.empty and hostname:
        known_domains = df[df["indicator_type"] == "domain"]
        for _, row in known_domains.iterrows():
            if _domain_matches(row["indicator"], hostname):
                return {
                    "indicator": domain, "indicator_type": "domain", "status": "known threat",
                    "severity": row["severity"], "threat_type": row["threat_type"],
                    "description": f"Hostname matches known flagged domain ({row['indicator']}).",
                }

    # light heuristic fallback for unseen domains — clearly labeled as heuristic, not a TI match
    suspicious_kw = ["secure", "verify", "update", "login", "account", "confirm"]
    if any(kw in domain.lower() for kw in suspicious_kw) and "-" in domain:
        return {"indicator": domain, "indicator_type": "domain", "status": "suspicious",
                "severity": "MEDIUM", "threat_type": "possible_phishing",
                "description": "Domain matches common phishing naming patterns (heuristic — not "
                               "a known threat intelligence match)."}
    return {"indicator": domain, "indicator_type": "domain", "status": "unknown",
            "severity": None, "threat_type": None, "description": None}


def check_url(url):
    """
    Look up a URL against the local TI dataset. Fixed to parse the actual
    hostname instead of doing raw substring matching on the URL string,
    which previously caused false positives (e.g. 'evil.com' incorrectly
    matching inside 'notevil.com').
    """
    result = _lookup(url, "url")
    if result:
        return result

    hostname = _extract_hostname(url)
    df = _load_data()
    if not df.empty and hostname:
        known_domains = df[df["indicator_type"] == "domain"]
        for _, row in known_domains.iterrows():
            if _domain_matches(row["indicator"], hostname):
                return {"indicator": url, "indicator_type": "url", "status": "suspicious",
                        "severity": row["severity"], "threat_type": row["threat_type"],
                        "description": f"URL hostname matches a known flagged domain "
                                       f"({row['indicator']})."}
    return {"indicator": url, "indicator_type": "url", "status": "unknown",
            "severity": None, "threat_type": None, "description": None}


def correlate_evidence_indicators(email_urls=None, email_sender=None,
                                   network_destination_ips=None):
    """
    UPGRADE 1 helper: given raw indicators pulled from evidence (email
    sender domain, email URLs, network destination IPs), run them through
    the actual TI lookup functions and return only genuine hits — i.e.
    status in ('known threat', 'suspicious'). Never fabricates a match;
    an indicator only appears here if check_ip/check_domain/check_url
    actually returned a non-'unknown' status.
    """
    hits = []

    if email_sender:
        sender_domain = email_sender.split("@")[-1].strip("> ") if "@" in email_sender else None
        if sender_domain:
            hit = check_domain(sender_domain)
            if hit.get("status") != "unknown":
                hits.append(hit)

    for url in (email_urls or []):
        hit = check_url(url)
        if hit.get("status") != "unknown":
            hits.append(hit)

    for ip in (network_destination_ips or []):
        hit = check_ip(ip)
        if hit.get("status") != "unknown":
            hits.append(hit)

    return hits


def search_indicator(query):
    """Free-text search across the whole threat intel dataset for the UI search box."""
    df = _load_data()
    if df.empty or not query:
        return []
    mask = df.apply(lambda row: query.lower() in str(row.values).lower(), axis=1)
    return df[mask].to_dict("records")


def get_all_indicators():
    return _load_data().to_dict("records")


def get_stats():
    df = _load_data()
    if df.empty:
        return {"total": 0, "by_type": {}, "by_severity": {}}
    return {
        "total": len(df),
        "by_type": df["indicator_type"].value_counts().to_dict(),
        "by_severity": df["severity"].value_counts().to_dict(),
    }

    """Free-text search across the whole threat intel dataset for the UI search box."""
    df = _load_data()
    if df.empty or not query:
        return []
    mask = df.apply(lambda row: query.lower() in str(row.values).lower(), axis=1)
    return df[mask].to_dict("records")


def get_all_indicators():
    return _load_data().to_dict("records")


def get_stats():
    df = _load_data()
    if df.empty:
        return {"total": 0, "by_type": {}, "by_severity": {}}
    return {
        "total": len(df),
        "by_type": df["indicator_type"].value_counts().to_dict(),
        "by_severity": df["severity"].value_counts().to_dict(),
    }
