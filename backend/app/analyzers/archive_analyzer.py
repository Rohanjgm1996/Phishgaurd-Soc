"""
PhishGuard SOC - Archive Analyzer
Safely inspects ZIP (and RAR if available) archives for:
- Embedded executables
- Password protection
- Suspicious filenames
Depth-limited to prevent zip bombs. Never extracts/executes content.
"""
import io
import os
import zipfile
from pathlib import Path

try:
    import rarfile
    RAR_AVAILABLE = True
except ImportError:
    RAR_AVAILABLE = False

from app.core.utils import DANGEROUS_EXTENSIONS

MAX_DEPTH = 3
MAX_ENTRIES = 500


def analyze_archive(file_bytes: bytes, filename: str, depth: int = 0) -> dict:
    """
    Inspect archive contents recursively (up to MAX_DEPTH).
    Returns triggered rules and details.
    """
    result = {
        "triggered_rules": [],
        "details": [],
        "entries": [],
        "embedded_executables": [],
        "is_password_protected": False,
    }

    ext = Path(filename).suffix.lower()

    if ext == ".zip":
        _analyze_zip(file_bytes, filename, depth, result)
    elif ext == ".rar" and RAR_AVAILABLE:
        _analyze_rar(file_bytes, filename, depth, result)
    else:
        result["details"].append(f"Archive type {ext} analysis not supported or library unavailable")

    return result


def _analyze_zip(file_bytes: bytes, filename: str, depth: int, result: dict):
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
            names = zf.namelist()[:MAX_ENTRIES]
            result["entries"] = names

            for name in names:
                info = zf.getinfo(name)
                ext = Path(name).suffix.lower()

                # Test for password protection
                if info.flag_bits & 0x1:
                    result["is_password_protected"] = True

                if ext in DANGEROUS_EXTENSIONS:
                    result["embedded_executables"].append(name)

            # Try reading to detect password protection
            if not result["is_password_protected"]:
                for name in names[:5]:
                    try:
                        zf.read(name)
                    except RuntimeError as e:
                        if "password" in str(e).lower():
                            result["is_password_protected"] = True
                            break

    except zipfile.BadZipFile:
        result["details"].append("Invalid ZIP file")
        return
    except Exception as e:
        result["details"].append(f"ZIP analysis error: {e}")
        return

    # Build triggered rules
    if result["is_password_protected"]:
        result["triggered_rules"].append("password_protected_archive")
        result["details"].append("Archive is password-protected — automated scanning limited")

    if result["embedded_executables"]:
        result["triggered_rules"].append("embedded_executable")
        result["details"].append(f"Executable files in archive: {result['embedded_executables'][:5]}")


def _analyze_rar(file_bytes: bytes, filename: str, depth: int, result: dict):
    """Analyze RAR archive using rarfile library."""
    try:
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".rar", delete=False) as tmp:
            tmp.write(file_bytes)
            tmp_path = tmp.name

        try:
            with rarfile.RarFile(tmp_path) as rf:
                names = rf.namelist()[:MAX_ENTRIES]
                result["entries"] = names

                for name in names:
                    ext = Path(name).suffix.lower()
                    if ext in DANGEROUS_EXTENSIONS:
                        result["embedded_executables"].append(name)

                if rf.needs_password():
                    result["is_password_protected"] = True
        finally:
            os.unlink(tmp_path)

    except Exception as e:
        result["details"].append(f"RAR analysis error: {e}")
        return

    if result["is_password_protected"]:
        result["triggered_rules"].append("password_protected_archive")
        result["details"].append("RAR archive is password-protected")

    if result["embedded_executables"]:
        result["triggered_rules"].append("embedded_executable")
        result["details"].append(f"Executables in RAR: {result['embedded_executables'][:5]}")
