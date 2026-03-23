"""
PhishGuard SOC - PDF Analyzer
Inspects PDF files for suspicious actions, JavaScript, embedded objects.
SAFE: static analysis only — no JavaScript execution.
"""
import re
from typing import Optional

try:
    from pypdf import PdfReader
    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False


# PDF object keywords that are suspicious
SUSPICIOUS_PDF_ACTIONS = ["/JS", "/JavaScript", "/Launch", "/SubmitForm", "/ImportData"]
SUSPICIOUS_PDF_OBJECTS = ["/EmbeddedFile", "/EmbeddedFiles", "/RichMedia", "/Flash", "/XFA"]


def analyze_pdf(file_bytes: bytes) -> dict:
    """
    Perform static PDF analysis.
    Returns triggered rules and details.
    """
    result = {
        "triggered_rules": [],
        "details": [],
        "suspicious_actions": [],
        "suspicious_objects": [],
        "page_count": 0,
        "metadata": {},
    }

    # Raw byte-level checks (fast, works even for malformed PDFs)
    _raw_pdf_scan(file_bytes, result)

    # High-level checks with pypdf
    if PYPDF_AVAILABLE:
        _pypdf_scan(file_bytes, result)
    else:
        result["details"].append("pypdf not installed — some PDF checks skipped")

    return result


def _raw_pdf_scan(file_bytes: bytes, result: dict):
    """Scan raw PDF bytes for suspicious keywords."""
    content = file_bytes.decode("latin-1", errors="ignore")

    for action in SUSPICIOUS_PDF_ACTIONS:
        if action.lower() in content.lower():
            result["suspicious_actions"].append(action)

    for obj in SUSPICIOUS_PDF_OBJECTS:
        if obj.lower() in content.lower():
            result["suspicious_objects"].append(obj)

    if result["suspicious_actions"]:
        result["triggered_rules"].append("suspicious_pdf_action")
        result["details"].append(f"Suspicious PDF actions: {result['suspicious_actions']}")

    if result["suspicious_objects"]:
        result["triggered_rules"].append("suspicious_pdf_object")
        result["details"].append(f"Suspicious PDF objects: {result['suspicious_objects']}")

    # Check for embedded URIs with suspicious patterns
    uri_pattern = re.compile(r'/URI\s*\(([^)]+)\)', re.IGNORECASE)
    uris = uri_pattern.findall(content)
    if uris:
        result["details"].append(f"URIs in PDF: {uris[:5]}")


def _pypdf_scan(file_bytes: bytes, result: dict):
    """Use pypdf for higher-level PDF metadata and structure inspection."""
    import io
    try:
        reader = PdfReader(io.BytesIO(file_bytes))
        result["page_count"] = len(reader.pages)

        meta = reader.metadata
        if meta:
            result["metadata"] = {
                "title": str(meta.get("/Title", "")),
                "author": str(meta.get("/Author", "")),
                "creator": str(meta.get("/Creator", "")),
                "producer": str(meta.get("/Producer", "")),
            }

        # Check for JavaScript in page annotations
        for page in reader.pages[:10]:  # check first 10 pages
            if "/AA" in page or "/JS" in str(page):
                if "suspicious_pdf_action" not in result["triggered_rules"]:
                    result["triggered_rules"].append("suspicious_pdf_action")
                result["details"].append("JavaScript action found in page annotations")
                break

    except Exception as e:
        result["details"].append(f"pypdf error: {e}")
