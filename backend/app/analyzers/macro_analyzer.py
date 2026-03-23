"""
PhishGuard SOC - Macro Analyzer
Uses oletools to inspect VBA macros in Office documents.
SAFE: reads and inspects only, never executes macros.
"""
import io
import re
from typing import Optional

# oletools imports — gracefully handle if not installed
try:
    from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML
    OLETOOLS_AVAILABLE = True
except ImportError:
    OLETOOLS_AVAILABLE = False


# Suspicious VBA keywords that often appear in malicious macros
SUSPICIOUS_VBA_KEYWORDS = [
    "Shell", "CreateObject", "WScript", "PowerShell", "cmd.exe",
    "http://", "https://", "ftp://",
    "AutoOpen", "Document_Open", "Auto_Open", "Workbook_Open",
    "CreateTextFile", "Open For Output", "WriteLine",
    "URLDownloadToFile", "WinHttp", "XMLHTTP",
    "environ", "GetObject", "CallByName",
    "Chr(", "ChrW(", "Asc(", "Mid(",
    "Hidden", "vbHide", "SW_HIDE",
]

AUTO_EXEC_KEYWORDS = [
    "AutoOpen", "Document_Open", "Auto_Open", "Workbook_Open",
    "AutoClose", "Document_Close", "Auto_Close",
    "AutoExec", "AutoNew",
]

OBFUSCATION_PATTERNS = [
    r'Chr\(\d+\)',                # Chr(72) style char encoding
    r'"\s*&\s*"',                 # string concatenation used to hide keywords
    r'[A-Za-z]\s*=\s*[A-Za-z]\s*\+', # incremental string building
    r'Dim\s+\w+\s+As\s+String.*\n.*=.*&', # multi-line string building
]


def analyze_macros(file_bytes: bytes, filename: str) -> dict:
    """
    Analyse Office file for VBA macros.
    Returns triggered rules and details.
    Never executes the macros.
    """
    result = {
        "triggered_rules": [],
        "details": [],
        "macros_found": False,
        "macro_count": 0,
        "auto_exec": [],
        "suspicious_keywords": [],
        "obfuscation_indicators": [],
        "macro_source_preview": [],
    }

    if not OLETOOLS_AVAILABLE:
        result["details"].append("oletools not installed — macro analysis skipped")
        return result

    try:
        vba_parser = VBA_Parser(filename, data=file_bytes)
    except Exception as e:
        result["details"].append(f"Could not open file for macro analysis: {e}")
        return result

    try:
        if not vba_parser.detect_vba_macros():
            result["details"].append("No VBA macros detected")
            return result

        result["macros_found"] = True

        for (vba_filename, stream_path, vba_code) in vba_parser.extract_macros():
            if not vba_code:
                continue
            result["macro_count"] += 1

            # Preview (first 500 chars)
            preview = vba_code[:500].strip()
            result["macro_source_preview"].append({
                "stream": stream_path,
                "preview": preview,
            })

            # Check auto-exec
            for kw in AUTO_EXEC_KEYWORDS:
                if re.search(rf"\b{re.escape(kw)}\b", vba_code, re.IGNORECASE):
                    if kw not in result["auto_exec"]:
                        result["auto_exec"].append(kw)

            # Check suspicious keywords
            for kw in SUSPICIOUS_VBA_KEYWORDS:
                if kw.lower() in vba_code.lower():
                    if kw not in result["suspicious_keywords"]:
                        result["suspicious_keywords"].append(kw)

            # Check obfuscation
            for pat in OBFUSCATION_PATTERNS:
                if re.search(pat, vba_code, re.IGNORECASE):
                    if pat not in result["obfuscation_indicators"]:
                        result["obfuscation_indicators"].append(pat)

        # ── Determine triggered scoring rules ─────────────────────────────────
        triggered = []
        if result["macros_found"]:
            triggered.append("macro_enabled_office")
            result["details"].append(f"VBA macros found in {result['macro_count']} stream(s)")

        if result["auto_exec"]:
            triggered.append("auto_exec_macro")
            result["details"].append(f"Auto-executing macros: {result['auto_exec']}")

        if result["suspicious_keywords"]:
            triggered.append("suspicious_vba_keywords")
            result["details"].append(f"Suspicious keywords: {result['suspicious_keywords'][:8]}")

        if result["obfuscation_indicators"]:
            triggered.append("obfuscated_vba")
            result["details"].append("Obfuscation patterns detected in VBA code")

        result["triggered_rules"] = triggered

    except Exception as e:
        result["details"].append(f"Macro analysis error: {e}")
    finally:
        try:
            vba_parser.close()
        except Exception:
            pass

    return result
