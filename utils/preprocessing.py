"""
preprocessing.py
-----------------
Shared text/data preprocessing helpers used across modules.
"""

import re
import string


URL_REGEX = re.compile(r'(https?://[^\s<>"\']+|www\.[^\s<>"\']+)', re.IGNORECASE)
IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')

URGENT_WORDS = [
    "urgent", "immediately", "verify your account", "act now", "suspended",
    "click here", "limited time", "final notice", "confirm your identity",
    "unusual activity", "within 24 hours", "your account will be", "locked",
    "expire", "expires", "expired", "winner", "congratulations", "wire transfer",
    "gift card", "social security", "bank details", "password expires",
    "security alert", "restore access", "temporarily limited", "unrecognized device",
    "sign-in from", "storage is almost full", "avoid interruption", "avoid losing",
    "as soon as possible", "re-verification", "permanently disabled", "outstanding fee",
    "outstanding balance", "settle the", "unlock it", "confirm your credentials",
    "session has expired", "policy violation", "failure to respond", "48 hours",
    "increase your limit", "end of day", "avoid disruption", "immediately due to",
    "confirm your payment", "flagged for review", "restore normal", "about to lapse",
    "renew now", "avoid legal action", "pay immediately", "confirm your card",
    "confirm your details", "resolve it", "remote access", "critical vulnerability",
    "keep this between us", "confidential", "release your package", "confirm your address",
    "cash prize", "inheritance", "handling fee", "guaranteed returns", "limited spots",
    "unclaimed prize", "earn thousands", "no experience required", "processing fee",
    "guaranteed", "small deposit", "get in early", "commission", "grand prize",
    "registration fee", "grant", "overseas", "please respond promptly",
]


def clean_text(text: str) -> str:
    """Lowercase, strip punctuation-heavy noise, collapse whitespace."""
    if not text:
        return ""
    text = text.lower()
    text = re.sub(r'\s+', ' ', text)
    text = text.strip()
    return text


def extract_urls(text: str):
    if not text:
        return []
    return list(dict.fromkeys(URL_REGEX.findall(text)))


def extract_ips(text: str):
    if not text:
        return []
    return list(dict.fromkeys(IP_REGEX.findall(text)))


def extract_emails(text: str):
    if not text:
        return []
    return list(dict.fromkeys(EMAIL_REGEX.findall(text)))


def count_urgent_language(text: str):
    """Return the list of urgency/social-engineering phrases found in text."""
    if not text:
        return []
    lowered = text.lower()
    return [phrase for phrase in URGENT_WORDS if phrase in lowered]


def suspicious_domain_indicators(url: str):
    """Very lightweight heuristic checks on a single URL string."""
    indicators = []
    if IP_REGEX.search(url):
        indicators.append("URL uses a raw IP address instead of a domain name")
    if url.count('-') >= 3:
        indicators.append("Domain contains an unusually high number of hyphens")
    shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co/", "is.gd", "buff.ly"]
    if any(shortener in url.lower() for shortener in shorteners):
        indicators.append("URL uses a link-shortening service")
    if re.search(r'(secure|verify|update|confirm|account|login)-', url, re.IGNORECASE):
        indicators.append("Domain uses suspicious keyword patterns common in phishing")
    if url.lower().startswith("http://"):
        indicators.append("URL does not use HTTPS")
    return indicators


def normalize_field(value: str) -> str:
    if value is None:
        return ""
    return str(value).strip()
