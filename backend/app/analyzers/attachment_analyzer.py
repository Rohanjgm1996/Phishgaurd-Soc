"""
PhishGuard SOC - Attachment Analyzer
Orchestrates file type detection, macro analysis, archive analysis,
PDF analysis, YARA scan, and ClamAV scan for a single file.
"""
from pathlib import Path

from app.core.utils import compute_hashes, has_double_extension, MACRO_EXTENSIONS, ARCHIVE_EXTENSIONS
from app.analyzers.file_type import detect_file_type
from app.analyzers.macro_analyzer import analyze_macros
from app.analyzers.archive_analyzer import analyze_archive
from app.analyzers.pdf_analyzer import analyze_pdf
from app.analyzers.yara_scanner import yara_scan
from app.analyzers.clamav_scanner import clamav_scan


def analyze_attachment(file_bytes: bytes, filename: str) -> dict:
    """
    Full analysis pipeline for a single file/attachment.
    Returns all sub-results merged into one dict.
    """
    ext = Path(filename).suffix.lower()
    hashes = compute_hashes(file_bytes)
    file_type_info = detect_file_type(file_bytes, filename)

    all_triggered = []
    all_details = []
    sub_results = {
        "hashes": hashes,
        "file_type": file_type_info,
        "filename": filename,
        "size": len(file_bytes),
        "macro_result": {},
        "archive_result": {},
        "pdf_result": {},
        "yara_result": {},
        "clamav_result": {},
    }

    # ── Double extension ───────────────────────────────────────────────────────
    if has_double_extension(filename):
        all_triggered.append("double_extension")
        all_details.append(f"Double extension detected: {filename}")

    # ── Macro analysis (Office files) ─────────────────────────────────────────
    if ext in MACRO_EXTENSIONS or "office" in file_type_info.get("magic_description", "").lower():
        macro_result = analyze_macros(file_bytes, filename)
        sub_results["macro_result"] = macro_result
        all_triggered.extend(macro_result.get("triggered_rules", []))
        all_details.extend(macro_result.get("details", []))
    elif ext in {".docx", ".xlsx", ".pptx"}:
        # OOXML — check for macro streams anyway
        macro_result = analyze_macros(file_bytes, filename)
        sub_results["macro_result"] = macro_result
        all_triggered.extend(macro_result.get("triggered_rules", []))
        all_details.extend(macro_result.get("details", []))

    # ── Archive analysis ───────────────────────────────────────────────────────
    if ext in ARCHIVE_EXTENSIONS or "zip" in file_type_info.get("mime_type", "").lower() or "rar" in file_type_info.get("mime_type", "").lower():
        archive_result = analyze_archive(file_bytes, filename)
        sub_results["archive_result"] = archive_result
        all_triggered.extend(archive_result.get("triggered_rules", []))
        all_details.extend(archive_result.get("details", []))

    # ── PDF analysis ───────────────────────────────────────────────────────────
    if ext == ".pdf" or "pdf" in file_type_info.get("mime_type", "").lower():
        pdf_result = analyze_pdf(file_bytes)
        sub_results["pdf_result"] = pdf_result
        all_triggered.extend(pdf_result.get("triggered_rules", []))
        all_details.extend(pdf_result.get("details", []))

    # ── YARA scan ─────────────────────────────────────────────────────────────
    yara_result = yara_scan(file_bytes)
    sub_results["yara_result"] = yara_result
    all_triggered.extend(yara_result.get("triggered_rules", []))
    all_details.extend(yara_result.get("details", []))

    # ── ClamAV scan ───────────────────────────────────────────────────────────
    clamav_result = clamav_scan(file_bytes)
    sub_results["clamav_result"] = clamav_result
    all_triggered.extend(clamav_result.get("triggered_rules", []))
    all_details.extend(clamav_result.get("details", []))

    # Deduplicate triggered rules
    sub_results["triggered_rules"] = list(set(all_triggered))
    sub_results["details"] = all_details

    # IOCs from attachment
    sub_results["iocs"] = {
        "hashes": hashes,
        "filename": filename,
    }

    return sub_results
