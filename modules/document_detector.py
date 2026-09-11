"""
document_detector.py
---------------------
AI-based document SCREENING (not definitive identity verification).

Performs OCR on uploaded identity-style documents (PNG/JPG/JPEG/PDF),
extracts likely fields (Name, DOB, Document Number, Address, Issue/Expiry
dates), and applies prototype-level authenticity heuristics PLUS an
optional supplementary structural-consistency ML model
(models/document_model.pkl, trained by training/train_document_model.py).

Outputs a risk category (LOW / MEDIUM / HIGH) and a list of indicators
described as "requires verification" rather than definitive fraud claims.

UPGRADE NOTES:
- UPGRADE 2: document_model.pkl is now actually loaded and used as a
  SUPPLEMENTARY signal alongside the rule-based heuristics — it never
  replaces them, and the output clearly separates "ML structural
  consistency", "heuristic indicators", and "OCR quality" so the UI can
  show investigators exactly which signal flagged what.
- UPGRADE 5: PDFs are now actually rendered to an image before OCR
  (PyMuPDF if available, falling back to the poppler `pdftoppm` CLI if
  present) instead of being fed directly to the image OCR path, which
  previously only worked on true image bytes.
"""

import os
import re
import io
import subprocess
import tempfile

try:
    import pytesseract
    from PIL import Image
    OCR_AVAILABLE = True
except Exception:
    OCR_AVAILABLE = False

try:
    import cv2
    import numpy as np
    CV2_AVAILABLE = True
except Exception:
    CV2_AVAILABLE = False

try:
    import joblib
    JOBLIB_AVAILABLE = True
except Exception:
    JOBLIB_AVAILABLE = False

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCUMENT_MODEL_PATH = os.path.join(BASE_DIR, "models", "document_model.pkl")

FIELD_PATTERNS = {
    # Name: non-greedy capture bounded by the next likely field label (or end of
    # string) so OCR'd text with no clean line breaks doesn't get swallowed into
    # one giant match (e.g. "John Carter DATE OF BIRTH..." previously captured
    # "John Carter DATE OF BIRTH" as the name).
    "Name": re.compile(
        r'(?:name|full name)\s*[:\-]?\s*([A-Za-z ,.\'-]{2,60}?)'
        r'(?=\s+(?:DATE|DOB|BIRTH|DOCUMENT|ID\s*NO|ADDRESS|ISSUE|EXPIR|PASSPORT)|$|\d)',
        re.IGNORECASE
    ),
    # Date/label patterns tolerant of OCR concatenating words together
    # (e.g. "ISSUEDATE", "DATEOF BIRTH") via \s* between sub-words instead of
    # requiring a literal space.
    "Date of Birth": re.compile(r'(?:date\s*of\s*birth|dob|birth\s*date)\s*[:\-]?\s*([\d/\-. ]{6,12})', re.IGNORECASE),
    "Document Number": re.compile(r'(?:document\s*(?:no|number)|id\s*(?:no|number)|passport\s*(?:no|number))\s*[:\-]?\s*([A-Za-z0-9]{5,15})', re.IGNORECASE),
    "Address": re.compile(r'(?:address)\s*[:\-]?\s*([A-Za-z0-9 ,.\'-]{5,80})', re.IGNORECASE),
    "Issue Date": re.compile(r'(?:issue\s*date|date\s*of\s*issue|issued)\s*[:\-]?\s*([\d/\-. ]{6,12})', re.IGNORECASE),
    "Expiry Date": re.compile(r'(?:expiry\s*date|date\s*of\s*expiry|expires?|exp)\s*[:\-]?\s*([\d/\-. ]{6,12})', re.IGNORECASE),
}

DATE_REGEX = re.compile(r'(\d{1,4})[/\-.](\d{1,2})[/\-.](\d{1,4})')
COMPACT_DATE_REGEX = re.compile(r'\b(\d{4})(\d{2})(\d{2})\b')  # e.g. OCR-concatenated "20200101"
# OCR sometimes drops just ONE of the two separators (e.g. "2021-0301" instead of
# "2021-03-01"). This permissive pattern makes each separator optional individually
# rather than requiring all-or-nothing, catching those partial cases too.
LOOSE_DATE_REGEX = re.compile(r'\b(\d{4})[/\-.]?(\d{1,2})[/\-.]?(\d{1,2})\b')

_model_cache = None
_model_load_attempted = False


def is_ocr_available():
    return OCR_AVAILABLE


def is_document_model_available():
    return load_document_model() is not None


def load_document_model():
    """Load models/document_model.pkl once and cache it. Returns None (and
    never raises) if the model file is missing or joblib isn't installed —
    callers must treat that as 'ML screening unavailable' and fall back to
    heuristics only, per Upgrade 2 requirement #7."""
    global _model_cache, _model_load_attempted
    if _model_load_attempted:
        return _model_cache
    _model_load_attempted = True
    if not JOBLIB_AVAILABLE or not os.path.exists(DOCUMENT_MODEL_PATH):
        _model_cache = None
        return None
    try:
        _model_cache = joblib.load(DOCUMENT_MODEL_PATH)
    except Exception:
        _model_cache = None
    return _model_cache


# ---------------------------------------------------------------------------
# PDF rendering (Upgrade 5)
# ---------------------------------------------------------------------------

def _render_pdf_to_image_bytes(file_bytes, max_pages=1):
    """
    Render the first page(s) of a PDF to PNG image bytes so the existing
    image-OCR path can process it. Tries PyMuPDF (fitz) first; falls back
    to the poppler `pdftoppm` command-line tool if fitz isn't installed;
    returns (list_of_png_bytes, warning_or_None). Never raises.
    """
    # --- Attempt 1: PyMuPDF ---
    try:
        import fitz  # PyMuPDF
        doc = fitz.open(stream=file_bytes, filetype="pdf")
        if doc.page_count == 0:
            doc.close()
            return [], "Uploaded PDF has no pages."
        images = []
        for i in range(min(max_pages, doc.page_count)):
            pix = doc[i].get_pixmap(dpi=200)
            images.append(pix.tobytes("png"))
        doc.close()
        return images, None
    except ImportError:
        pass  # fall through to poppler fallback
    except Exception as e:
        return [], f"PyMuPDF failed to render the PDF ({e}); attempting fallback renderer."

    # --- Attempt 2: poppler `pdftoppm` CLI fallback (no extra Python dependency) ---
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            pdf_path = os.path.join(tmpdir, "input.pdf")
            with open(pdf_path, "wb") as f:
                f.write(file_bytes)
            out_prefix = os.path.join(tmpdir, "page")
            subprocess.run(
                ["pdftoppm", "-png", "-r", "200", "-f", "1", "-l", str(max_pages), pdf_path, out_prefix],
                check=True, capture_output=True, timeout=25
            )
            images = []
            for fname in sorted(os.listdir(tmpdir)):
                if fname.startswith("page") and fname.endswith(".png"):
                    with open(os.path.join(tmpdir, fname), "rb") as imgf:
                        images.append(imgf.read())
            if images:
                return images, None
            return [], "PDF rendering produced no pages — the file may be empty or corrupted."
    except FileNotFoundError:
        return [], ("PDF rendering is unavailable in this environment (neither PyMuPDF nor the "
                     "poppler 'pdftoppm' tool is installed). Upload a PNG/JPG scan instead, or "
                     "install PyMuPDF (`pip install pymupdf`) for PDF support.")
    except subprocess.TimeoutExpired:
        return [], "PDF rendering timed out — the file may be too large or complex."
    except Exception as e:
        return [], f"Could not render PDF for OCR: {e}"


def is_pdf_bytes(file_bytes):
    return bool(file_bytes) and file_bytes[:5] == b"%PDF-"


# ---------------------------------------------------------------------------
# OCR
# ---------------------------------------------------------------------------

def run_ocr(file_bytes, filename=""):
    """
    Run OCR on an image, or (Upgrade 5) on a rendered PDF page. Returns
    (ocr_text, ocr_confidence, warning). Never raises — all failure modes
    degrade to an empty result with an explanatory warning string so the
    UI can show it rather than crashing.
    """
    if not OCR_AVAILABLE:
        return "", 0.0, "OCR engine unavailable. Using fallback document analysis."

    image_bytes = file_bytes
    is_pdf = is_pdf_bytes(file_bytes) or filename.lower().endswith(".pdf")

    if is_pdf:
        rendered_pages, pdf_warning = _render_pdf_to_image_bytes(file_bytes, max_pages=1)
        if not rendered_pages:
            return "", 0.0, pdf_warning or "Could not render PDF for OCR."
        image_bytes = rendered_pages[0]

    try:
        image = Image.open(io.BytesIO(image_bytes))
        image = image.convert("RGB")
    except Exception as e:
        return "", 0.0, f"Could not read image for OCR: {e}"

    try:
        data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
        words = [w for w in data.get("text", []) if w.strip()]
        confidences = [int(c) for c in data.get("conf", []) if str(c).isdigit() and int(c) >= 0]
        text = " ".join(words)
        avg_conf = round(sum(confidences) / len(confidences), 1) if confidences else 0.0
        return text, avg_conf, None
    except Exception as e:
        return "", 0.0, f"OCR engine unavailable ({e}). Using fallback document analysis."


def extract_fields(ocr_text):
    """Extract likely identity fields from raw OCR text using regex heuristics."""
    fields = {}
    for field_name, pattern in FIELD_PATTERNS.items():
        match = pattern.search(ocr_text or "")
        fields[field_name] = match.group(1).strip() if match else None
    return fields


def _check_image_quality(file_bytes):
    """Lightweight image-region / quality heuristic using OpenCV, if available."""
    indicators = []
    if not CV2_AVAILABLE or is_pdf_bytes(file_bytes):
        return indicators
    try:
        arr = np.frombuffer(file_bytes, dtype=np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if img is None:
            return indicators
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        laplacian_var = cv2.Laplacian(gray, cv2.CV_64F).var()
        if laplacian_var < 50:
            indicators.append("Image appears unusually blurry (low sharpness score) — "
                               "may hinder reliable verification")
        mean_brightness = gray.mean()
        if mean_brightness < 40 or mean_brightness > 220:
            indicators.append("Image brightness is outside a typical readable range")
    except Exception:
        pass
    return indicators


def _parse_year(date_str):
    m = DATE_REGEX.search(date_str or "")
    if m:
        parts = [int(p) for p in m.groups()]
        return max(parts)  # crude year detection
    m2 = COMPACT_DATE_REGEX.search(date_str or "")
    if m2:
        return int(m2.group(1))
    m3 = LOOSE_DATE_REGEX.search(date_str or "")
    if m3:
        return int(m3.group(1))
    return None


def _validate_dates(fields):
    indicators = []
    issue = fields.get("Issue Date")
    expiry = fields.get("Expiry Date")
    dob = fields.get("Date of Birth")

    issue_year = _parse_year(issue)
    expiry_year = _parse_year(expiry)
    dob_year = _parse_year(dob)

    if issue_year and expiry_year and expiry_year <= issue_year:
        indicators.append("Expiry date is not later than issue date — inconsistent date sequence")
    if dob_year and issue_year and (issue_year - dob_year) < 0:
        indicators.append("Issue date appears to precede date of birth — inconsistent record")

    return indicators


# ---------------------------------------------------------------------------
# Supplementary ML structural-consistency model (Upgrade 2)
# ---------------------------------------------------------------------------

def _build_model_features(fields):
    """
    Reproduce EXACTLY the six features training/train_document_model.py
    derives from a document record, so inference matches training:
        name_len, address_len, doc_num_len,
        issue_before_expiry, dob_before_issue, validity_years
    """
    name_len = len(fields.get("Name") or "")
    address_len = len(fields.get("Address") or "")
    doc_num_len = len(fields.get("Document Number") or "")

    issue_year = _parse_year(fields.get("Issue Date")) or 0
    expiry_year = _parse_year(fields.get("Expiry Date")) or 0
    dob_year = _parse_year(fields.get("Date of Birth")) or 0

    issue_before_expiry = int(expiry_year > issue_year)
    dob_before_issue = int(issue_year > dob_year)
    validity_years = expiry_year - issue_year

    return {
        "name_len": name_len,
        "address_len": address_len,
        "doc_num_len": doc_num_len,
        "issue_before_expiry": issue_before_expiry,
        "dob_before_issue": dob_before_issue,
        "validity_years": validity_years,
    }


def run_document_model(fields):
    """
    Run the supplementary structural-consistency classifier if available.
    Returns a dict {available, prediction, confidence, features} — never
    raises. If the model is missing, `available` is False and callers
    must clearly indicate ML screening was skipped (Upgrade 2 requirement #7).
    """
    bundle = load_document_model()
    if bundle is None:
        return {"available": False, "prediction": None, "confidence": None, "features": None}

    try:
        feature_dict = _build_model_features(fields)
        feature_order = bundle.get("features") or list(feature_dict.keys())
        import pandas as pd
        row = pd.DataFrame([[feature_dict[f] for f in feature_order]], columns=feature_order)

        clf = bundle["classifier"]
        pred = clf.predict(row)[0]
        proba = clf.predict_proba(row)[0]
        confidence = round(float(max(proba)) * 100, 1)

        return {
            "available": True,
            "prediction": pred,
            "confidence": confidence,
            "features": feature_dict,
        }
    except Exception as e:
        return {"available": False, "prediction": None, "confidence": None,
                "features": None, "error": str(e)}


# ---------------------------------------------------------------------------
# Main screening entry point
# ---------------------------------------------------------------------------

def screen_document(file_bytes, filename, document_type="ID_CARD"):
    """
    Full document screening pipeline:
        OCR (image or rendered PDF page)
          -> field extraction
          -> rule-based heuristic checks (dates, missing fields, OCR quality, image quality)
          -> supplementary ML structural-consistency model (if available)
          -> combined screening result

    Returns a dict summarizing the screening outcome. The original keys
    are all preserved for backward compatibility with app.py; new keys
    (`ml_screening`, `heuristic_indicators`) are additive.
    """
    ocr_text, ocr_confidence, ocr_warning = run_ocr(file_bytes, filename)
    fields = extract_fields(ocr_text)

    heuristic_indicators = []
    if ocr_warning:
        heuristic_indicators.append(ocr_warning)

    missing_fields = [k for k, v in fields.items() if not v]
    if len(missing_fields) >= 4:
        heuristic_indicators.append(f"Several expected fields could not be identified: "
                                     f"{', '.join(missing_fields)} — document requires manual verification")

    if ocr_confidence and ocr_confidence < 50:
        heuristic_indicators.append(f"Low OCR confidence ({ocr_confidence}%) — text extraction may be unreliable")

    if ocr_text and len(ocr_text.strip()) < 20:
        heuristic_indicators.append("Very little readable text was extracted — unusual text structure "
                                     "for this document type")

    heuristic_indicators.extend(_check_image_quality(file_bytes))
    heuristic_indicators.extend(_validate_dates(fields))

    # --- Supplementary ML structural-consistency signal ---
    ml_result = run_document_model(fields)
    ml_indicators = []
    if ml_result["available"]:
        if ml_result["prediction"] == "INCONSISTENT_DEMO":
            ml_indicators.append(
                f"ML structural-consistency model flagged this document as potentially inconsistent "
                f"(confidence {ml_result['confidence']}%) — supplementary signal, not a standalone "
                f"determination."
            )
    else:
        heuristic_indicators.append("ML structural screening unavailable (model not found) — "
                                     "relying on rule-based heuristics only.")

    all_indicators = heuristic_indicators + ml_indicators

    # Authenticity score: start high, subtract for each indicator found.
    # ML flag counts as one heuristic-weighted signal, not a dominant override.
    authenticity_score = max(0, 100 - len(all_indicators) * 15)

    if authenticity_score >= 75:
        risk_level = "LOW RISK"
    elif authenticity_score >= 45:
        risk_level = "MEDIUM RISK"
    else:
        risk_level = "HIGH RISK"

    recommendation = ("Document appears consistent — routine verification recommended."
                       if risk_level == "LOW RISK" else
                       "Potential inconsistencies detected — manual verification recommended.")

    risk_score = 100 - authenticity_score

    return {
        "document_name": filename,
        "document_type": document_type,
        "ocr_text": ocr_text,
        "ocr_confidence": ocr_confidence,
        "extracted_fields": fields,
        "indicators": all_indicators,               # combined — kept for backward compatibility
        "heuristic_indicators": heuristic_indicators,  # rule-based only, clearly separated
        "ml_screening": ml_result,                   # ML structural-consistency signal, clearly separated
        "authenticity_score": authenticity_score,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "recommendation": recommendation,
    }
