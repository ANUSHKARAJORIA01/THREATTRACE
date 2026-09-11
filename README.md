# AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform

A unified, student-level SOC / digital-forensics prototype built with
Python, scikit-learn, and Streamlit. It is organized around a
**Protection → Investigation** workflow: quick, no-setup threat checks
for everyday inputs (email/URL/file) come first, and a full,
evidence-driven investigation with correlation, an evidence graph, and
an explainable risk score comes second — for the cases that actually
need it.

> ⚠️ **This is an educational/research prototype — not a production
> security product.** Risk scores, classifications, and screening
> results are heuristic/machine-learning estimates, not definitive
> findings of fraud, malicious intent, or identity. All sample data is
> synthetic/fictional.

---

## Project Overview

The platform has two modes, selected from the sidebar:

- **🛡️ Protection Mode** — for a normal user. Paste an email, a URL, or
  upload a file, and immediately get a risk score, a SAFE / SUSPICIOUS /
  DANGEROUS verdict, plain-language reasons, and a recommended action.
  No case or investigation setup required.
- **🔎 Investigation Mode** — for an investigator. Create a case and add
  whatever evidence is actually available for it — email, network flows,
  an identity document, an IP, or any combination; nothing is required.
  Each analysis feeds a central **Risk Correlation Engine**, an evidence
  relationship graph, a forensic timeline, and a downloadable PDF report.

A Protection Mode result that looks concerning can be **escalated** into
a new investigation with one click, carrying its findings over as real,
scored evidence rather than a plain log line.

```
USER / INVESTIGATOR
        ↓
DIGITAL INPUT (Email / URL / File / Evidence)
        ↓
AI THREAT ANALYSIS
        ↓
🛡️ PROTECTION MODE: Risk Score → SAFE / SUSPICIOUS / DANGEROUS → Warning
        ↓ (if it needs a closer look)
🔎 INVESTIGATION MODE: Evidence Extraction → Evidence Correlation →
   Evidence Graph → Explainable Risk Score → Timeline → Forensic Report
```

## Features

- 🛡️ **Protection Mode** — standalone Check Email / Check URL / Check
  File tools built directly on top of the real detection engines below
  (no separate/duplicate scoring logic), so a quick check and a later
  full investigation of the same input never disagree
- 📧 **Email Threat Detection** — TF-IDF + Logistic Regression classifier
  (BENIGN / PHISHING / SCAM / IMPERSONATION) plus heuristic checks
  (urgency language, suspicious URLs, sender/reply-to mismatch, etc.),
  with real-time correlation against the local threat-intelligence dataset
- 🌐 **Network Threat Detection** — Random Forest known-threat classifier
  + Isolation Forest anomaly detection over flow features. The anomaly
  signal alone can never relabel a flow as malicious — it only does so
  when corroborated by at least one rule-based indicator, otherwise it
  surfaces as a clearly-labeled weak signal with a small risk bump
- 🪪 **Identity & Document Screening** — OCR field extraction (pytesseract,
  including rendered PDF pages), rule-based authenticity heuristics
  (date-order consistency, missing fields, image quality), a supplementary
  ML structural-consistency classifier (trained on synthetic data, always
  shown separately from the heuristics — never a standalone verdict), and
  an identity-consistency engine comparing email vs. document vs.
  case-context identity claims
- 🌍 **Geolocation Intelligence** — IP lookups with an offline synthetic
  fallback dataset (works with zero API keys) and interactive map;
  accurate private/reserved-range detection via Python's `ipaddress`
  module; country is treated as a weak supporting signal only, never a
  standalone maliciousness indicator
- 🚨 **Threat Intelligence** — local, offline demo indicator database
  (IPs/domains/URLs) with search, hostname-based matching (not naive
  substring matching, so `evil.com` cannot falsely match `notevil.com`),
  and REAL correlation against email/network evidence that actually
  feeds into the overall risk score
- 🔎 **Forensic Engine** — evidence compilation, relationship graph
  (including threat-intelligence match nodes), and chronological timeline
  per investigation, with robust timestamp parsing (ISO strings, datetime
  objects, missing values)
- 📊 **Explainable AI Risk Scoring** — a single centralized risk-
  recalculation function (`risk_engine.recalculate_case_risk`) is the only
  place overall risk is ever computed, so every page and the PDF report
  always show identical numbers for the same investigation. Evidence
  types are all optional and independently weighted — an investigation
  with only an email and a URL, for example, produces a real,
  proportionally-weighted score without requiring network, identity, or
  geolocation evidence
- 📄 **PDF Reports** — full investigation report generated with ReportLab,
  built directly from the same centralized risk calculation as the
  dashboard (never recomputed independently), with wrapped (not
  truncated) long-text fields
- 🚀 **One-click Demo Mode** — populates a complete fictional
  investigation by actually running it through the real email, network,
  document, identity, geolocation, and threat-intelligence pipelines
  (not hardcoded scores) for instant, genuine end-to-end demonstration

## Architecture

```
Inputs (email / network CSV / documents / IP)
        ↓
Per-module detection engines (ML + heuristics)
        ↓
SQLite evidence storage (per investigation)
        ↓
Forensic Engine (compiles evidence + relationship graph + timeline)
        ↓
Risk Correlation Engine (weighted scoring + explanations)
        ↓
Streamlit SOC Dashboard  +  PDF Report Generator
```

## Folder Structure

```
AI_Forensic_Platform/
├── app.py                     # Streamlit UI — controls navigation only
├── requirements.txt
├── README.md
├── .gitignore
├── modules/
│   ├── email_detector.py
│   ├── network_detector.py
│   ├── identity_detector.py
│   ├── document_detector.py
│   ├── geolocation.py
│   ├── forensic_engine.py
│   ├── risk_engine.py
│   ├── threat_intelligence.py
│   ├── protection_scan.py     # Protection Mode: standalone email/URL/file checks
│   └── demo_loader.py
├── models/                    # Trained .pkl models (auto-created)
├── data/                      # Synthetic sample datasets
├── database/
│   └── database.py            # SQLite schema + reusable CRUD functions
├── utils/
│   ├── preprocessing.py
│   ├── timeline.py
│   └── report_generator.py
├── training/
│   ├── train_email_model.py
│   ├── train_network_model.py
│   └── train_document_model.py
├── uploads/
└── generated_reports/
```

## Installation

### macOS / Linux

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Windows

```bat
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### OCR (Tesseract) setup — optional but recommended

The document screening module uses `pytesseract`, which requires the
Tesseract OCR engine to be installed **separately** on your system:

- **macOS:** `brew install tesseract`
- **Ubuntu/Debian:** `sudo apt-get install tesseract-ocr`
- **Windows:** install from the
  [UB-Mannheim Tesseract build](https://github.com/UB-Mannheim/tesseract/wiki)
  and ensure it is on your `PATH`.

If Tesseract is not installed, the application **still runs** — the
Identity & Document page will show a warning and fall back to
heuristic-only analysis without extracted OCR text.

### PDF document support

PDF uploads on the Identity & Document page are rendered to an image and
then OCR'd automatically. This uses, in order of preference:

1. **PyMuPDF** (`pip install pymupdf`, included in `requirements.txt`) — no
   extra system dependency required.
2. **poppler's `pdftoppm`** command-line tool as a fallback if PyMuPDF isn't
   available (`brew install poppler` / `apt-get install poppler-utils`).
3. If neither is available, PDF screening degrades gracefully with a clear
   warning message rather than crashing — upload a PNG/JPG scan instead.

## Running

```bash
streamlit run app.py
```

The SQLite database (`forensic_platform.db`) and ML models (`models/*.pkl`)
are created automatically on first run if they don't already exist.

## Model Training

Models are trained automatically the first time they're needed, but you
can also train them explicitly:

```bash
python training/train_email_model.py
python training/train_network_model.py
python training/train_document_model.py
```

Each script prints prototype-only accuracy/precision/recall/F1 metrics
computed on the synthetic sample datasets in `data/`.

## Demo Mode

Click **"🚀 Load Demo Investigation"** in the sidebar at any time. This
creates a new investigation and runs it through the actual detection
pipelines (not hardcoded scores): a fictional suspicious email through
the real email classifier, synthetic network flows through the real
network detector, a synthetically-rendered identity document (with a
deliberate expiry-before-issue inconsistency) through the real OCR +
document screening + supplementary ML model, a real identity-consistency
check, a real geolocation lookup, and real threat-intelligence
correlation — then runs the centralized risk-correlation engine so the
full dashboard, timeline, and risk analysis are immediately populated
with genuine (if synthetic) results. From there you can generate a PDF
report that will show the exact same numbers as the dashboard.

## How to Run the Complete Prototype

```bash
python -m venv venv
source venv/bin/activate          # venv\Scripts\activate on Windows
pip install -r requirements.txt
streamlit run app.py
```

Then in the browser UI:
1. Start in **🛡️ Protection Mode** (the default) to check a single email,
   URL, or file — no setup needed. Each result shows a risk score, a
   SAFE / SUSPICIOUS / DANGEROUS verdict, plain-language reasons, and a
   recommended action, with an **Escalate to Investigation** button if
   it needs a closer look.
2. Switch to **🔎 Investigation Mode** in the sidebar. Click **Load Demo
   Investigation** (or create a new investigation and add whatever
   evidence you actually have — evidence types are all optional).
3. Visit each sidebar page (Email, Network, Identity & Documents,
   Geolocation) to see or add evidence — each analysis automatically
   correlates against threat intelligence and refreshes the case's
   overall risk.
4. Visit **Forensic Investigation** to see all evidence, the threat-
   intelligence matches, the relationship graph, and the timeline; the
   **Recalculate Overall Risk** button re-runs the same centralized
   engine used everywhere else.
5. Visit **Risk Analysis** to see the gauge and explainable indicators.
6. Visit **Generate Report** to download a full PDF investigation report
   — it is built from the exact same calculation as the dashboard, so
   the numbers always match.

## Limitations

- **IP geolocation is approximate infrastructure intelligence**, not a
  person's exact physical location; country/region is treated as a weak
  supporting signal only and is deliberately capped so it cannot push a
  case into HIGH/CRITICAL risk by itself.
- **Document screening is not legal identity verification** — both the
  rule-based heuristics and the supplementary ML structural-consistency
  model flag potential inconsistencies for manual, human review only;
  the ML signal is always shown separately and never overrides the
  heuristics or stands alone as a verdict.
- **Threat intelligence matches are against a small local, fictional
  dataset** (16 synthetic indicators) — this is not a real-world threat
  feed, and "no match" only means "not in this demo dataset," not "safe."
- **AI predictions are not guaranteed** — models are trained on small,
  synthetic datasets purpose-built for this prototype; training scripts
  print honest prototype-only metrics and never fabricate performance.
- **Network anomaly detection requires corroboration** — an Isolation
  Forest flag alone (with no supporting rule-based indicator) is
  deliberately kept as a small, clearly-labeled weak signal rather than
  an automatic "malicious" or "anomalous" classification.
- **All sample/demo datasets are entirely synthetic and fictional** — no
  real individuals' data is used anywhere in this project.
- **Prototype risk scores are not production security ratings** and
  should never be the sole basis for a real security, legal, or
  identity-related decision.

## Ethical & Security Design Notes

This is a strictly **defensive** analysis/screening/reporting prototype.
It contains no phishing-generation, malware, exploitation, unauthorized
access, evasion, or surveillance functionality, and all bundled sample
data is synthetic.
