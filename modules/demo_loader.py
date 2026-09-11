"""
demo_loader.py
----------------
Creates a complete fictional demo investigation with pre-populated
email, network, document, identity, geolocation, and threat-intelligence
evidence so the platform can be demonstrated end-to-end without requiring
any uploads.

UPGRADE NOTES (Upgrades 3, 4, 14):
- The demo document is now run through the REAL document_detector.
  screen_document() pipeline (synthetic image -> OCR -> field extraction
  -> heuristics -> ML structural model) instead of manually computing an
  authenticity_score.
- The demo identity check now actually calls identity_detector.
  compare_identities() against a fictional reference identity, instead of
  storing a hardcoded identity_consistency_score.
- Threat intelligence hits are now produced by real
  threat_intelligence.check_domain()/check_url()/check_ip() lookups
  against the demo email/network data, instead of a generic evidence note.
- Overall risk is calculated via the single centralized
  risk_engine.recalculate_case_risk() helper (Upgrade 6) so the demo uses
  exactly the same scoring path as manually-built investigations.
"""
import io
from datetime import datetime

from database import database as db
from modules import (
    email_detector, network_detector, document_detector,
    identity_detector, geolocation as geo_module, threat_intelligence,
    risk_engine
)
def _build_synthetic_document_image():
    """
    Render a synthetic identity-document-style image (via PIL) containing
    a DELIBERATE structural inconsistency (expiry date before issue date),
    so the real OCR + document_detector pipeline has something genuine to
    catch. Returns PNG bytes, or None if PIL isn't available.
    """
    try:
        from PIL import Image, ImageDraw
    except Exception:
        return None

    img = Image.new("RGB", (600, 260), color="white")
    d = ImageDraw.Draw(img)
    lines = [
        "NAME: John A Carter",
        "DATE OF BIRTH: 1985-04-12",
        "DOCUMENT NUMBER: A1234567",
        "ISSUE DATE: 2021-03-01",
        "EXPIRY DATE: 2019-03-01",   # deliberately BEFORE issue date -> genuine inconsistency
    ]
    for i, line in enumerate(lines):
        d.text((20, 20 + i * 40), line, fill="black")

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _load_demo_related_email_investigation():
    """
    Companion demo investigation used only to give correlation_engine a real,
    exact-match indicator to find: a different fictional target receiving a
    phishing email from the SAME sender domain as the main demo investigation
    (secure-verify-account.com), but a different mailbox, recipient, and
    subject line. This is genuine, literal overlap — not a fabricated
    "campaign" flag — so the Possible Related Activity / Potential Campaign
    Pattern feature has something real to demonstrate.
    """
    case_name = f"Demo Investigation (Related) — Vendor Portal — {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    investigation_id = db.create_investigation(case_name)

    demo_email_text = (
        "Subject: Your Vendor Portal Access Will Expire\n\n"
        "Dear Partner, your vendor portal access will expire today unless you re-authenticate "
        "at http://secure-verify-account.com/vendor-login immediately."
    )
    parsed = email_detector.parse_plain_text(
        demo_email_text, sender="support@secure-verify-account.com",
        receiver="partner@anothercorp.com", subject="Your Vendor Portal Access Will Expire"
    )
    email_result = email_detector.analyze_email(parsed)
    db.insert_email_analysis(
        investigation_id, email_result["sender"], email_result["receiver"], email_result["subject"],
        email_result["classification"], email_result["risk_score"], "; ".join(email_result["indicators"])
    )

    ti_hits = threat_intelligence.correlate_evidence_indicators(
        email_urls=["http://secure-verify-account.com/vendor-login"],
        email_sender="support@secure-verify-account.com",
    )
    for hit in ti_hits:
        db.insert_evidence(
            investigation_id, "Threat Intelligence",
            f"Local threat intelligence match: {hit['indicator']} — {hit.get('threat_type') or hit['status']} "
            f"(severity: {hit.get('severity') or 'n/a'}). {hit.get('description') or ''}".strip(),
            {"LOW": 25, "MEDIUM": 55, "HIGH": 80, "CRITICAL": 95}.get(hit.get("severity"), 45)
        )

    risk_engine.recalculate_case_risk(investigation_id)
    return investigation_id


def _load_demo_related_network_investigation():
    """
    Second companion demo investigation: a different organization's network
    log showing a flow to the SAME destination IP used in the main demo
    investigation (91.219.237.100) — again genuine, literal overlap for
    correlation_engine to find, not a fabricated flag.
    """
    case_name = f"Demo Investigation (Related) — Partner Network Log — {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    investigation_id = db.create_investigation(case_name)

    demo_flows = network_detector.load_demo_data(5)
    ti_demo_flow = network_detector.analyze_flows(
        demo_flows.head(1).assign(destination_ip="91.219.237.100", destination_port=4444)
    )
    for _, row in ti_demo_flow.iterrows():
        db.insert_network_analysis(
            investigation_id, row["source_ip"], row["destination_ip"], row["protocol"],
            row["classification"], row["risk_score"], row["indicators"]
        )

    ti_hits = threat_intelligence.correlate_evidence_indicators(network_destination_ips=["91.219.237.100"])
    for hit in ti_hits:
        db.insert_evidence(
            investigation_id, "Threat Intelligence",
            f"Local threat intelligence match: {hit['indicator']} — {hit.get('threat_type') or hit['status']} "
            f"(severity: {hit.get('severity') or 'n/a'}). {hit.get('description') or ''}".strip(),
            {"LOW": 25, "MEDIUM": 55, "HIGH": 80, "CRITICAL": 95}.get(hit.get("severity"), 45)
        )

    risk_engine.recalculate_case_risk(investigation_id)
    return investigation_id


def load_demo_investigation():
    """Create a new investigation and populate it with fictional demo evidence,
    exercising the real detection/screening pipelines throughout. Returns the
    new investigation's ID."""

    case_name = f"Demo Investigation — {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    investigation_id = db.create_investigation(case_name)

    # ---- Demo email evidence (real email_detector pipeline) ----
    demo_email_text = (
        "Subject: Urgent Account Verification Required\n\n"
        "Dear Customer, we detected unusual activity on your account. Your account has been "
        "suspended. Verify your identity immediately at http://secure-verify-account.com/login "
        "or you will lose access within 24 hours. This is urgent, please act now."
    )
    parsed = email_detector.parse_plain_text(
        demo_email_text, sender="alerts@secure-verify-account.com",
        receiver="employee@examplecorp.com", subject="Urgent Account Verification Required"
    )
    email_result = email_detector.analyze_email(parsed)
    db.insert_email_analysis(
        investigation_id, email_result["sender"], email_result["receiver"], email_result["subject"],
        email_result["classification"], email_result["risk_score"], "; ".join(email_result["indicators"])
    )

    # ---- Demo network evidence (real network_detector pipeline) ----
    demo_flows = network_detector.load_demo_data(15)
    analyzed = network_detector.analyze_flows(demo_flows)
    for _, row in analyzed.iterrows():
        db.insert_network_analysis(
            investigation_id, row["source_ip"], row["destination_ip"], row["protocol"],
            row["classification"], row["risk_score"], row["indicators"]
        )
    # Force one flow to a known fictional TI IP so the TI correlation demo has a
    # guaranteed real hit to show — inserted as an additional genuine flow, not
    # a fabricated evidence note.
    ti_demo_flow = network_detector.analyze_flows(
        demo_flows.head(1).assign(destination_ip="91.219.237.100", destination_port=4444)
    )
    for _, row in ti_demo_flow.iterrows():
        db.insert_network_analysis(
            investigation_id, row["source_ip"], row["destination_ip"], row["protocol"],
            row["classification"], row["risk_score"], row["indicators"]
        )

    # ---- Demo document evidence (real document_detector pipeline) ----
    doc_bytes = _build_synthetic_document_image()
    if doc_bytes is not None:
        screening = document_detector.screen_document(doc_bytes, "demo_identity_document.png", "ID_CARD")
    else:
        # PIL unavailable — degrade gracefully rather than crash the demo
        screening = {
            "document_name": "demo_identity_document.png", "document_type": "ID_CARD",
            "ocr_text": "", "extracted_fields": {"Name": "John A Carter", "Address": None},
            "indicators": ["Image rendering unavailable in this environment — demo document "
                           "screening skipped."],
            "authenticity_score": 50, "risk_level": "MEDIUM RISK", "risk_score": 50,
        }

    # ---- Demo identity consistency check (real identity_detector pipeline) ----
    # Fictional reference identity representing what the "email sender" claims,
    # compared against what the document screening actually extracted.
    email_identity = {"name": "John A Carter", "organization": "Example Corp"}
    document_identity = {
        "name": screening["extracted_fields"].get("Name"),
        "address": screening["extracted_fields"].get("Address"),
    }
    case_context = {"expected_organization": "Example Corp", "claimed_address": None}
    consistency = identity_detector.compare_identities(email_identity, document_identity, case_context)

    db.insert_document_analysis(
        investigation_id, screening["document_name"], screening["document_type"],
        screening.get("ocr_text", ""), screening["authenticity_score"],
        consistency["identity_consistency_score"], screening["risk_score"],
        "; ".join(screening["indicators"] + consistency["mismatches"])
    )

    # ---- Demo geolocation evidence (real geolocation pipeline) ----
    geo_result = geo_module.lookup_ip("91.219.237.100")
    geo_risk, geo_indicators = geo_module.score_geolocation_risk(geo_result)
    db.insert_geolocation_analysis(
        investigation_id, geo_result["ip_address"], geo_result.get("country"),
        geo_result.get("region"), geo_result.get("city"), geo_result.get("latitude"),
        geo_result.get("longitude"), geo_risk, "; ".join(geo_indicators)
    )

    # ---- Demo threat intelligence evidence (real TI lookups, not a canned note) ----
    ti_hits = threat_intelligence.correlate_evidence_indicators(
        email_urls=["http://secure-verify-account.com/login"],
        email_sender="alerts@secure-verify-account.com",
        network_destination_ips=["91.219.237.100"],
    )
    for hit in ti_hits:
        db.insert_evidence(
            investigation_id, "Threat Intelligence",
            f"Local threat intelligence match: {hit['indicator']} — {hit.get('threat_type') or hit['status']} "
            f"(severity: {hit.get('severity') or 'n/a'}). {hit.get('description') or ''}".strip(),
            {"LOW": 25, "MEDIUM": 55, "HIGH": 80, "CRITICAL": 95}.get(hit.get("severity"), 45)
        )

    # ---- Companion demo investigations sharing genuine indicators, so the
    # correlation/campaign-detection feature (correlation_engine.py) has real,
    # literal overlap to find — never fabricated for demo effect. ----
    _load_demo_related_email_investigation()
    _load_demo_related_network_investigation()

    # ---- Centralized risk correlation (Upgrade 6 — single source of truth) ----
    # Recalculated after the companions above exist, so this investigation's
    # own correlation_engine result already reflects them.
    result = risk_engine.recalculate_case_risk(investigation_id)
    db.insert_evidence(
        investigation_id, "Correlation",
        f"AI correlation engine executed across all evidence types. Overall risk: "
        f"{result['overall_score']}/100 ({result['risk_level']}).",
        result["overall_score"]
    )

    return investigation_id
