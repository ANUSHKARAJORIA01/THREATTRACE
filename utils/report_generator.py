"""
report_generator.py
---------------------
Generates a professional PDF investigation report using ReportLab.

UPGRADE 11 NOTES:
- generate_report_from_recalc() is a new thin wrapper that takes the dict
  returned by risk_engine.recalculate_case_risk() directly, so app.py
  never has to re-derive or duplicate the risk/evidence/explanation the
  dashboard already computed — the report is guaranteed to match what's
  on screen because it's built from the exact same object.
- Long text fields (event descriptions, indicators, subjects) are now
  wrapped inside table cells using ReportLab Paragraphs instead of being
  hard-truncated with `[:30]`/`[:70]`, so information isn't silently lost.
"""

import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(BASE_DIR, "generated_reports")


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", fontSize=20, leading=24,
                               spaceAfter=12, textColor=colors.HexColor("#0b3d91")))
    styles.add(ParagraphStyle(name="SectionHeading", fontSize=14, leading=18,
                               spaceBefore=14, spaceAfter=8, textColor=colors.HexColor("#0b3d91")))
    styles.add(ParagraphStyle(name="BodySmall", fontSize=9.5, leading=13))
    styles.add(ParagraphStyle(name="CellText", fontSize=7.5, leading=9.5))
    styles.add(ParagraphStyle(name="CellHeader", fontSize=8, leading=10, textColor=colors.white))
    return styles


def _risk_color(level):
    return {
        "LOW": colors.HexColor("#2e7d32"),
        "MEDIUM": colors.HexColor("#f9a825"),
        "HIGH": colors.HexColor("#ef6c00"),
        "CRITICAL": colors.HexColor("#c62828"),
    }.get(level, colors.grey)


def _cell(text, styles, header=False):
    """Wrap text in a Paragraph so long content wraps across lines inside
    a table cell instead of being hard-truncated."""
    style = styles["CellHeader"] if header else styles["CellText"]
    return Paragraph(str(text) if text is not None else "—", style)


def generate_report_from_recalc(recalc_result, output_filename=None):
    """
    UPGRADE 6 + 11 convenience wrapper: build the PDF report directly from
    the dict returned by risk_engine.recalculate_case_risk(), so the report
    always reflects EXACTLY the same risk/evidence/explanation shown on the
    dashboard — no separate recalculation happens here.

    Also pulls the (additive, non-scoring) "correlation" and "next_steps"
    fields risk_engine now attaches, plus the typed evidence-relationship
    graph, for the new report sections below. None of this touches the
    risk number itself.
    """
    from modules import forensic_engine  # local import avoids a module-load-time
                                          # circular import between utils and modules

    investigation_id = recalc_result["investigation"]["id"]
    compiled = forensic_engine.compile_investigation(investigation_id)
    graph = forensic_engine.build_evidence_graph(compiled) if compiled else {"relationship_edges": []}

    return generate_investigation_report(
        investigation=recalc_result["investigation"],
        email_records=recalc_result["email_records"],
        network_records=recalc_result["network_records"],
        document_records=recalc_result["document_records"],
        geolocation_records=recalc_result["geolocation_records"],
        threat_intel_hits=recalc_result["threat_intel_hits"],
        timeline_events=recalc_result.get("timeline_events", []),
        explanation_lines=recalc_result["explanation"],
        relationship_edges=graph.get("relationship_edges", []),
        correlation=recalc_result.get("correlation"),
        next_steps=recalc_result.get("next_steps"),
        output_filename=output_filename,
    )


def generate_investigation_report(investigation, email_records, network_records,
                                   document_records, geolocation_records,
                                   threat_intel_hits, timeline_events, explanation_lines,
                                   relationship_edges=None, correlation=None, next_steps=None,
                                   output_filename=None):
    """
    Build a full PDF investigation report and return its file path.

    IMPORTANT: this function does NOT recalculate risk — it only renders
    whatever overall_risk/risk_level is already present on the passed-in
    `investigation` dict (and whatever evidence/explanation is passed in),
    so it can never silently diverge from the dashboard's numbers as long
    as callers pass a freshly-recalculated investigation (see
    generate_report_from_recalc above, which guarantees this).

    relationship_edges, correlation, and next_steps are all optional and
    additive — omitting them (as any caller written before this upgrade
    would) renders the report exactly as before, just without those three
    newer sections / with the original static next-steps list.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    if not output_filename:
        output_filename = f"INV-{investigation['id']:04d}_report.pdf"
    filepath = os.path.join(OUTPUT_DIR, output_filename)

    styles = _styles()
    doc = SimpleDocTemplate(filepath, pagesize=A4,
                             topMargin=2 * cm, bottomMargin=2 * cm,
                             leftMargin=2 * cm, rightMargin=2 * cm)
    story = []

    # ---- Header ----
    story.append(Paragraph("AI-Powered Forensic Investigation Report", styles["ReportTitle"]))
    story.append(Paragraph(f"Investigation ID: INV-{investigation['id']:04d}", styles["Normal"]))
    story.append(Paragraph(f"Case Name: {investigation.get('case_name')}", styles["Normal"]))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
    story.append(Paragraph(f"Overall Risk: {investigation.get('overall_risk')} "
                            f"({investigation.get('risk_level')})", styles["Normal"]))
    story.append(Spacer(1, 0.5 * cm))

    # ---- Executive Summary ----
    story.append(Paragraph("Executive Summary", styles["SectionHeading"]))
    summary_text = (
        f"This report summarizes the automated, AI-assisted analysis performed for investigation "
        f"INV-{investigation['id']:04d} ('{investigation.get('case_name')}'). The platform analyzed "
        f"{len(email_records)} email item(s), {len(network_records)} network flow record(s), "
        f"{len(document_records)} document(s) (including identity consistency checks), "
        f"{len(geolocation_records)} geolocation lookup(s), and correlated "
        f"{len(threat_intel_hits)} threat-intelligence indicator match(es). "
        f"The overall prototype risk score is {investigation.get('overall_risk')}/100, classified as "
        f"{investigation.get('risk_level')}."
    )
    story.append(Paragraph(summary_text, styles["BodySmall"]))

    # ---- Email Analysis ----
    story.append(Paragraph("Email Analysis", styles["SectionHeading"]))
    if email_records:
        data = [[_cell("Sender", styles, True), _cell("Subject", styles, True),
                 _cell("Classification", styles, True), _cell("Risk", styles, True)]]
        for r in email_records:
            data.append([_cell(r.get("sender"), styles), _cell(r.get("subject"), styles),
                         _cell(r.get("classification"), styles), _cell(r.get("risk_score"), styles)])
        story.append(_make_table(data, col_widths=[4.5 * cm, 5 * cm, 3 * cm, 2 * cm]))
    else:
        story.append(Paragraph("No email evidence recorded for this investigation.", styles["BodySmall"]))

    # ---- Network Analysis ----
    story.append(Paragraph("Network Analysis", styles["SectionHeading"]))
    if network_records:
        data = [[_cell("Source IP", styles, True), _cell("Destination IP", styles, True),
                 _cell("Classification", styles, True), _cell("Risk", styles, True)]]
        for r in network_records:
            data.append([_cell(r.get("source_ip"), styles), _cell(r.get("destination_ip"), styles),
                         _cell(r.get("classification"), styles), _cell(r.get("risk_score"), styles)])
        story.append(_make_table(data, col_widths=[4 * cm, 4 * cm, 3.5 * cm, 2 * cm]))
    else:
        story.append(Paragraph("No network evidence recorded for this investigation.", styles["BodySmall"]))

    # ---- Document / Identity Analysis ----
    story.append(Paragraph("Identity & Document Analysis", styles["SectionHeading"]))
    if document_records:
        data = [[_cell("Document", styles, True), _cell("Authenticity", styles, True),
                 _cell("Identity Consistency", styles, True), _cell("Risk", styles, True),
                 _cell("Indicators", styles, True)]]
        for r in document_records:
            data.append([_cell(r.get("document_name"), styles), _cell(r.get("authenticity_score"), styles),
                         _cell(r.get("identity_consistency_score"), styles), _cell(r.get("risk_score"), styles),
                         _cell(r.get("indicators"), styles)])
        story.append(_make_table(data, col_widths=[2.5 * cm, 2 * cm, 2.5 * cm, 1.5 * cm, 5 * cm]))
        story.append(Paragraph(
            "Note: document screening flags potential inconsistencies for manual verification — "
            "it is not a definitive determination of forgery or identity fraud.", styles["BodySmall"]))
    else:
        story.append(Paragraph("No document evidence recorded for this investigation.", styles["BodySmall"]))

    # ---- Geolocation Analysis ----
    story.append(Paragraph("Geolocation Analysis", styles["SectionHeading"]))
    if geolocation_records:
        data = [[_cell("IP Address", styles, True), _cell("Country", styles, True),
                 _cell("City", styles, True), _cell("Risk", styles, True)]]
        for r in geolocation_records:
            data.append([_cell(r.get("ip_address"), styles), _cell(r.get("country"), styles),
                         _cell(r.get("city"), styles), _cell(r.get("risk_score"), styles)])
        story.append(_make_table(data, col_widths=[4 * cm, 4.5 * cm, 4 * cm, 2 * cm]))
        story.append(Paragraph(
            "Note: IP geolocation reflects approximate infrastructure location, not a person's "
            "precise physical location, and may be drawn from an offline synthetic demo dataset.",
            styles["BodySmall"]))
    else:
        story.append(Paragraph("No geolocation evidence recorded for this investigation.", styles["BodySmall"]))

    # ---- Threat Intelligence ----
    story.append(Paragraph("Threat Intelligence", styles["SectionHeading"]))
    if threat_intel_hits:
        data = [[_cell("Indicator", styles, True), _cell("Type", styles, True),
                 _cell("Status", styles, True), _cell("Severity", styles, True),
                 _cell("Description", styles, True)]]
        for h in threat_intel_hits:
            data.append([_cell(h.get("indicator"), styles), _cell(h.get("indicator_type"), styles),
                         _cell(h.get("status"), styles), _cell(h.get("severity"), styles),
                         _cell(h.get("description"), styles)])
        story.append(_make_table(data, col_widths=[3.5 * cm, 1.8 * cm, 2.2 * cm, 1.8 * cm, 5.2 * cm]))
        story.append(Paragraph(
            "These matches are against a local, fictional/synthetic demo threat-intelligence "
            "dataset — they do not reflect real-world threat intelligence.", styles["BodySmall"]))
    else:
        story.append(Paragraph("No threat intelligence matches recorded.", styles["BodySmall"]))

    # ---- Evidence Relationships (typed) ----
    story.append(Paragraph("Evidence Relationships", styles["SectionHeading"]))
    if relationship_edges:
        data = [[_cell("Source", styles, True), _cell("Relationship", styles, True),
                 _cell("Target", styles, True)]]
        for rel in relationship_edges:
            data.append([_cell(rel.get("source"), styles),
                         _cell((rel.get("relationship") or "").replace("_", " "), styles),
                         _cell(rel.get("target"), styles)])
        story.append(_make_table(data, col_widths=[5.5 * cm, 4 * cm, 5.5 * cm]))
        story.append(Paragraph(
            "These relationships describe how the collected evidence connects (e.g. an email "
            "leading to a sender domain matched against threat intelligence) — they are derived "
            "directly from stored evidence, not inferred beyond it.", styles["BodySmall"]))
    else:
        story.append(Paragraph("No evidence relationships identified for this investigation.",
                                styles["BodySmall"]))

    # ---- Related Activity / Campaign Analysis ----
    story.append(Paragraph("Related Activity / Campaign Analysis", styles["SectionHeading"]))
    if correlation and correlation.get("related"):
        story.append(Paragraph(
            f"<b>{correlation.get('label')}</b> (confidence: {correlation.get('confidence')})",
            styles["BodySmall"]))
        story.append(Paragraph(correlation.get("explanation", ""), styles["BodySmall"]))
        data = [[_cell("Indicator Type", styles, True), _cell("Indicator", styles, True),
                 _cell("Also Seen In", styles, True)]]
        for m in correlation.get("shared_indicators", []):
            data.append([_cell(m.get("indicator_type"), styles), _cell(m.get("indicator_value"), styles),
                         _cell(f"INV-{m.get('other_investigation_id'):04d} — {m.get('other_case_name')}", styles)])
        story.append(_make_table(data, col_widths=[3 * cm, 6 * cm, 6 * cm]))
        story.append(Paragraph(
            "This reflects exact, literal indicator overlap with other investigations in the "
            "system only — it is not a confirmed link between cases and does not factor into the "
            "overall risk score above; it is provided as a lead for the investigator to review.",
            styles["BodySmall"]))
    else:
        story.append(Paragraph(
            "No shared indicators were found with any other investigation in the system at "
            "the time this report was generated.", styles["BodySmall"]))

    # ---- Forensic Timeline ----
    story.append(PageBreak())
    story.append(Paragraph("Forensic Timeline", styles["SectionHeading"]))
    if timeline_events:
        data = [[_cell("Time", styles, True), _cell("Category", styles, True), _cell("Event", styles, True)]]
        for e in timeline_events:
            data.append([_cell(e.get("time"), styles), _cell(e.get("category"), styles),
                         _cell(e.get("event"), styles)])
        story.append(_make_table(data, col_widths=[3.5 * cm, 2.5 * cm, 8.5 * cm]))
    else:
        story.append(Paragraph("No timeline events recorded.", styles["BodySmall"]))

    # ---- Risk Factors / AI Explanation ----
    story.append(Paragraph("Risk Factors & AI Explanation", styles["SectionHeading"]))
    for line in explanation_lines:
        story.append(Paragraph(line, styles["BodySmall"]))

    # ---- Recommended Next Steps ----
    story.append(Paragraph("Recommended Next Steps", styles["SectionHeading"]))
    if next_steps:
        # Evidence-based steps from modules/next_steps.py — each one is tied to a
        # concrete condition found in this case's actual evidence (see "reason").
        for item in next_steps:
            story.append(Paragraph(f"• {item.get('step')}", styles["BodySmall"]))
            reason = item.get("reason")
            if reason:
                story.append(Paragraph(f"   <i>Why: {reason}</i>", styles["BodySmall"]))
    else:
        # Backward-compatible fallback for any caller that doesn't pass next_steps.
        default_next_steps = [
            "Review all flagged indicators with a qualified human analyst before taking action.",
            "Independently verify any identity or document inconsistencies through official channels.",
            "Corroborate network findings with additional logging/monitoring data where available.",
            "Escalate CRITICAL or HIGH risk findings according to your organization's incident response policy.",
        ]
        for step in default_next_steps:
            story.append(Paragraph(f"• {step}", styles["BodySmall"]))

    # ---- Disclaimer ----
    story.append(Paragraph("Disclaimer", styles["SectionHeading"]))
    disclaimer = (
        "This report was generated by an educational/research prototype AI system. Risk scores, "
        "classifications, and screening results are heuristic and machine-learning based estimates, "
        "not definitive findings of fraud, malicious intent, or identity. IP geolocation is "
        "approximate. Threat intelligence matches are against a local synthetic demo dataset. "
        "This report is not a substitute for professional forensic, legal, or security "
        "investigation and should not be used as the sole basis for decisions affecting real "
        "individuals or systems."
    )
    story.append(Paragraph(disclaimer, styles["BodySmall"]))

    doc.build(story)
    return filepath


def _make_table(data, col_widths=None):
    table = Table(data, repeatRows=1, hAlign="LEFT", colWidths=col_widths)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b3d91")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f2f2")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table
