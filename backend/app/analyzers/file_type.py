"""
PhishGuard SOC - File Type Detector
Uses magic bytes (python-magic) with fallback to extension guessing.
"""
from pathlib import Path

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

# Magic bytes -> type mapping (fallback)
MAGIC_BYTES = {
    b"\x4d\x5a": "PE executable (EXE/DLL)",
    b"\x50\x4b\x03\x04": "ZIP archive",
    b"\xd0\xcf\x11\xe0": "Microsoft Office (OLE)",
    b"\x25\x50\x44\x46": "PDF document",
    b"\x52\x61\x72\x21": "RAR archive",
    b"\x7f\x45\x4c\x46": "ELF executable (Linux)",
    b"\xca\xfe\xba\xbe": "Mach-O binary (macOS)",
}

EXTENSION_MAP = {
    ".eml": "RFC 822 email",
    ".msg": "Microsoft Outlook email",
    ".pdf": "PDF document",
    ".doc": "Microsoft Word (OLE)",
    ".docx": "Microsoft Word (OOXML)",
    ".docm": "Microsoft Word with macros",
    ".xls": "Microsoft Excel (OLE)",
    ".xlsx": "Microsoft Excel (OOXML)",
    ".xlsm": "Microsoft Excel with macros",
    ".zip": "ZIP archive",
    ".rar": "RAR archive",
    ".exe": "Windows executable",
    ".dll": "Windows DLL",
    ".vbs": "VBScript",
    ".ps1": "PowerShell script",
    ".js": "JavaScript",
    ".html": "HTML document",
    ".htm": "HTML document",
    ".lnk": "Windows shortcut",
    ".bat": "Batch script",
    ".cmd": "Windows command script",
}


def detect_file_type(file_bytes: bytes, filename: str) -> dict:
    """
    Return detected MIME type and human-readable description.
    Tries python-magic first, falls back to extension + magic bytes.
    """
    mime = None
    description = "Unknown"

    # python-magic detection
    if MAGIC_AVAILABLE:
        try:
            mime = magic.from_buffer(file_bytes, mime=True)
            description = magic.from_buffer(file_bytes)
        except Exception:
            mime = None

    # Magic bytes fallback
    if not mime:
        for magic_sig, desc in MAGIC_BYTES.items():
            if file_bytes.startswith(magic_sig):
                description = desc
                break

    # Extension fallback
    ext = Path(filename).suffix.lower()
    ext_description = EXTENSION_MAP.get(ext, "")

    # Detect extension spoofing
    spoofed = False
    if mime:
        spoofed = _check_extension_mismatch(mime, ext)

    return {
        "mime_type": mime or f"application/{ext.lstrip('.') or 'octet-stream'}",
        "magic_description": description,
        "extension": ext,
        "extension_description": ext_description,
        "extension_spoofed": spoofed,
    }


def _check_extension_mismatch(mime: str, ext: str) -> bool:
    """
    Check if the detected MIME type contradicts the file extension.
    e.g. file.pdf that is actually a PE executable.
    """
    MIME_EXT_MAP = {
        "application/x-dosexec": {".exe", ".dll", ".com", ".scr"},
        "application/zip": {".zip", ".docx", ".xlsx", ".pptx"},
        "application/pdf": {".pdf"},
        "application/x-rar": {".rar"},
        "application/vnd.ms-office": {".doc", ".xls", ".ppt"},
        "text/html": {".html", ".htm"},
    }

    for expected_mime, expected_exts in MIME_EXT_MAP.items():
        if expected_mime in mime and ext not in expected_exts:
            return True
    return False
