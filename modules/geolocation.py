"""
geolocation.py
---------------
IP-based geolocation intelligence.

Supports an optional external lookup API (e.g. ip-api.com) when network
access is available, but always falls back to a local synthetic demo
dataset so the application works fully offline / without an API key.

IMPORTANT: IP geolocation is APPROXIMATE INFRASTRUCTURE INTELLIGENCE.
It does not represent the precise physical location of a person.

UPGRADE 8 NOTES:
- Private/reserved-range detection now uses Python's `ipaddress` module
  instead of a handful of string prefixes, which previously missed large
  swaths of RFC1918/RFC3927 space (e.g. 172.17.x-172.31.x, 169.254.x.x,
  0.0.0.0/8, etc.).
- Demo fallback locations are explicitly labeled as synthetic in the
  returned result so the UI can never present them as real intelligence.
- Country-based scoring is deliberately capped low — geography is a weak
  supporting signal here, never a standalone "this is malicious" flag.
"""

import re
import ipaddress

IP_REGEX = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')

# Local fallback demo dataset keyed by IP prefix pattern -> location info.
# This keeps the app fully functional without any external API calls.
# ALL entries here are fictional/synthetic — see is_private/source="demo_fallback".
_DEMO_LOCATIONS = [
    {"country": "United States", "region": "California", "city": "San Francisco",
     "latitude": 37.7749, "longitude": -122.4194, "isp": "Demo Cloud Hosting Inc."},
    {"country": "Germany", "region": "Berlin", "city": "Berlin",
     "latitude": 52.5200, "longitude": 13.4050, "isp": "Demo Telecom GmbH"},
    {"country": "Russia", "region": "Moscow", "city": "Moscow",
     "latitude": 55.7558, "longitude": 37.6173, "isp": "Demo Networks LLC"},
    {"country": "Netherlands", "region": "North Holland", "city": "Amsterdam",
     "latitude": 52.3676, "longitude": 4.9041, "isp": "Demo VPS Provider"},
    {"country": "Singapore", "region": "Singapore", "city": "Singapore",
     "latitude": 1.3521, "longitude": 103.8198, "isp": "Demo Data Center Ltd."},
    {"country": "Brazil", "region": "São Paulo", "city": "São Paulo",
     "latitude": -23.5505, "longitude": -46.6333, "isp": "Demo Comms S.A."},
    {"country": "India", "region": "Delhi", "city": "New Delhi",
     "latitude": 28.6139, "longitude": 77.2090, "isp": "Demo Broadband Services"},
    {"country": "China", "region": "Guangdong", "city": "Shenzhen",
     "latitude": 22.5431, "longitude": 114.0579, "isp": "Demo Hosting Co."},
    {"country": "United Kingdom", "region": "England", "city": "London",
     "latitude": 51.5074, "longitude": -0.1278, "isp": "Demo Internet Ltd."},
    {"country": "Nigeria", "region": "Lagos", "city": "Lagos",
     "latitude": 6.5244, "longitude": 3.3792, "isp": "Demo ISP Networks"},
]


def is_valid_ip(ip_address: str) -> bool:
    if not ip_address:
        return False
    match = IP_REGEX.match(ip_address.strip())
    if not match:
        return False
    return all(0 <= int(octet) <= 255 for octet in match.groups())


def _is_private_or_reserved(ip_address: str) -> bool:
    """
    Accurate private/reserved-range detection via the stdlib `ipaddress`
    module (covers full RFC1918 private space, RFC3927 link-local,
    loopback, and other reserved/special-use ranges) instead of a small
    hardcoded set of string prefixes.
    """
    try:
        addr = ipaddress.ip_address(ip_address)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        return False


def _deterministic_demo_location(ip_address: str):
    """Pick a demo location deterministically based on the IP string so the
    same IP always maps to the same demo result within a session."""
    seed = sum(ord(c) for c in ip_address)
    idx = seed % len(_DEMO_LOCATIONS)
    return _DEMO_LOCATIONS[idx]


def lookup_ip(ip_address: str, use_external_api: bool = False):
    """
    Look up geolocation info for an IP address.

    If use_external_api is True, an external API call is attempted (best
    effort); on any failure, or when False, the local demo dataset is used.
    Always returns a dict, never raises.
    """
    ip_address = (ip_address or "").strip()
    if not is_valid_ip(ip_address):
        return {
            "ip_address": ip_address,
            "valid": False,
            "error": "Invalid IPv4 address format.",
        }

    location = None
    source = "demo_fallback"

    if use_external_api:
        try:
            import requests
            resp = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=3)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    location = {
                        "country": data.get("country", "Unknown"),
                        "region": data.get("regionName", "Unknown"),
                        "city": data.get("city", "Unknown"),
                        "latitude": data.get("lat", 0.0),
                        "longitude": data.get("lon", 0.0),
                        "isp": data.get("isp", "Unknown"),
                    }
                    source = "external_api"
        except Exception:
            location = None

    if location is None:
        location = _deterministic_demo_location(ip_address)
        source = "demo_fallback"  # ensure this is set even if an API attempt failed above

    is_private = _is_private_or_reserved(ip_address)

    indicators = []
    if is_private:
        indicators.append("IP address is within a private/reserved range — geolocation not applicable")

    return {
        "ip_address": ip_address,
        "valid": True,
        "is_private": is_private,
        "country": location["country"] if not is_private else "Private Network",
        "region": location["region"] if not is_private else "N/A",
        "city": location["city"] if not is_private else "N/A",
        "latitude": location["latitude"] if not is_private else None,
        "longitude": location["longitude"] if not is_private else None,
        "isp": location["isp"] if not is_private else "N/A",
        "source": source,
        "is_synthetic": source == "demo_fallback" and not is_private,
        "indicators": indicators,
        "disclaimer": ("IP-based geolocation is approximate infrastructure intelligence and "
                        "should not be interpreted as the exact physical location of a person."
                        + (" This result uses the OFFLINE SYNTHETIC DEMO dataset, not a real "
                           "geolocation lookup." if source == "demo_fallback" and not is_private else "")),
    }


def score_geolocation_risk(geo_result, high_risk_countries=None):
    """
    Assign a simple demo risk score. Geography is treated as a WEAK
    supporting signal only — country alone is deliberately capped at a
    modest contribution and never pushes a case into HIGH/CRITICAL by
    itself, consistent with the principle that location is not proof of
    intent.
    """
    if not geo_result.get("valid"):
        return 0, []

    high_risk_countries = high_risk_countries or ["Russia", "China", "Nigeria"]
    indicators = list(geo_result.get("indicators", []))
    score = 10

    if geo_result.get("country") in high_risk_countries:
        indicators.append(
            f"Infrastructure location ({geo_result.get('country')}) falls within a region flagged "
            f"in this demo's watch-list — a weak supporting signal only, not evidence of wrongdoing "
            f"on its own."
        )
        score += 20  # deliberately modest — was 35; geography alone should stay a minor contributor

    if geo_result.get("is_synthetic"):
        indicators.append("Location data shown is from the offline synthetic demo dataset, not a "
                           "real-world lookup.")

    if geo_result.get("is_private"):
        score = 5

    return min(score, 100), indicators
