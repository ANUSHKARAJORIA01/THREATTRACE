"""
forensic_engine.py
--------------------
Collects all evidence belonging to one investigation into a unified
structure and builds a simple evidence relationship graph description
that the Forensic Investigation page can render.
"""

from database import database as db


def compile_investigation(investigation_id):
    """Gather every evidence type for an investigation into one dict."""
    investigation = db.get_investigation(investigation_id)
    if not investigation:
        return None

    return {
        "investigation": investigation,
        "email": db.get_email_analysis(investigation_id),
        "network": db.get_network_analysis(investigation_id),
        "document": db.get_document_analysis(investigation_id),
        "geolocation": db.get_geolocation_analysis(investigation_id),
        "evidence": db.get_evidence(investigation_id),
    }


def build_evidence_graph(compiled_investigation):
    """
    Build a node/edge representation of evidence relationships.

    Returns:
      {
        "nodes": [...],
        "edges": [(source, target), ...],       # UNCHANGED shape/order — the
                                                  # Forensic Investigation page
                                                  # in app.py unpacks this as
                                                  # `for src, tgt in graph["edges"]`,
                                                  # so this stays a plain 2-tuple list.
        "relationship_edges": [                  # NEW, purely additive.
            {"source": ..., "target": ..., "relationship": ...}, ...
        ],
      }

    "relationship_edges" mirrors "edges" exactly (same pairs, same
    order) but attaches a typed relationship label to each one, for
    consumers that want more than an untyped arrow (report_generator,
    correlation_engine). Nothing about "edges" itself changes.
    """
    nodes = []
    edges = []
    relationship_edges = []

    def add_edge(src, tgt, relationship):
        edges.append((src, tgt))
        relationship_edges.append({"source": src, "target": tgt, "relationship": relationship})

    inv_node = f"Investigation #{compiled_investigation['investigation']['id']}"
    nodes.append(inv_node)

    for i, email in enumerate(compiled_investigation.get("email", [])):
        email_node = f"Email: {email.get('subject') or 'Untitled'}"
        nodes.append(email_node)
        add_edge(inv_node, email_node, "has_evidence")

        sender_node = None
        if email.get("sender"):
            sender_node = f"Sender: {email['sender']}"
            nodes.append(sender_node)
            add_edge(email_node, sender_node, "sent_by")

        for url_or_ind in (email.get("indicators") or "").split(";")[:3]:
            if url_or_ind.strip():
                ind_node = f"Indicator: {url_or_ind.strip()[:40]}"
                nodes.append(ind_node)
                add_edge(email_node, ind_node, "contains_indicator")

        # UPGRADE 9: link TI evidence entries whose description references this
        # email's sender domain, so the graph shows Email -> Sender -> TI Match.
        sender_domain = email.get("sender", "").split("@")[-1].strip("> ") if email.get("sender") else None
        if sender_domain:
            for ev in compiled_investigation.get("evidence", []):
                if ev.get("evidence_type") == "Threat Intelligence" and sender_domain.lower() in (ev.get("description") or "").lower():
                    ti_node = f"TI Match: {sender_domain}"
                    nodes.append(ti_node)
                    add_edge(sender_node or email_node, ti_node, "matches_threat_intelligence")

    for doc in compiled_investigation.get("document", []):
        doc_node = f"Document: {doc.get('document_name')}"
        nodes.append(doc_node)
        add_edge(inv_node, doc_node, "has_evidence")
        id_node = f"Identity check (score {doc.get('identity_consistency_score')})"
        nodes.append(id_node)
        add_edge(doc_node, id_node, "screened_for_identity_consistency")

    for net in compiled_investigation.get("network", []):
        net_node = f"Network: {net.get('source_ip')} → {net.get('destination_ip')}"
        nodes.append(net_node)
        add_edge(inv_node, net_node, "has_evidence")

        for geo in compiled_investigation.get("geolocation", []):
            if geo.get("ip_address") == net.get("destination_ip"):
                geo_node = f"Geolocation: {geo.get('city')}, {geo.get('country')}"
                nodes.append(geo_node)
                add_edge(net_node, geo_node, "resolves_to_location")

        # UPGRADE 9: link TI evidence entries referencing this destination IP.
        dest_ip = net.get("destination_ip")
        if dest_ip:
            for ev in compiled_investigation.get("evidence", []):
                if ev.get("evidence_type") == "Threat Intelligence" and dest_ip in (ev.get("description") or ""):
                    ti_node = f"TI Match: {dest_ip}"
                    nodes.append(ti_node)
                    add_edge(net_node, ti_node, "matches_threat_intelligence")

    # De-duplicate while preserving order
    seen = set()
    unique_nodes = []
    for n in nodes:
        if n not in seen:
            seen.add(n)
            unique_nodes.append(n)

    return {"nodes": unique_nodes, "edges": edges, "relationship_edges": relationship_edges}


def evidence_summary_counts(compiled_investigation):
    return {
        "email_count": len(compiled_investigation.get("email", [])),
        "network_count": len(compiled_investigation.get("network", [])),
        "document_count": len(compiled_investigation.get("document", [])),
        "geolocation_count": len(compiled_investigation.get("geolocation", [])),
        "evidence_count": len(compiled_investigation.get("evidence", [])),
    }
