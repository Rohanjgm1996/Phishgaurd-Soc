"""
PhishGuard SOC - Utility Functions
File hashing, safe temp directories, extension helpers, etc.
"""
import hashlib
import os
import re
import socket
import tempfile
import uuid
from pathlib import Path
from typing import Optional


# ── Hashing ────────────────────────────────────────────────────────────────────
def compute_hashes(data: bytes) -> dict:
    """Return MD5, SHA1, SHA256 for raw bytes."""
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


# ── File helpers ───────────────────────────────────────────────────────────────
ALLOWED_EXTENSIONS = {
    ".eml", ".msg",
    ".pdf", ".doc", ".docm", ".docx",
    ".xls", ".xlsm", ".xlsx",
    ".zip", ".rar", ".7z",
    ".html", ".htm",
    ".js", ".vbs", ".ps1",
    ".exe", ".dll", ".lnk",
    ".txt", ".csv",
}

DANGEROUS_EXTENSIONS = {".exe", ".dll", ".vbs", ".ps1", ".lnk", ".bat", ".cmd", ".scr", ".com", ".pif"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz"}
OFFICE_EXTENSIONS = {".doc", ".docm", ".docx", ".xls", ".xlsm", ".xlsx", ".ppt", ".pptx", ".pptm"}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".doc", ".xls", ".ppt"}


def is_allowed_extension(filename: str) -> bool:
    ext = Path(filename).suffix.lower()
    return ext in ALLOWED_EXTENSIONS


def has_double_extension(filename: str) -> bool:
    """Detect double-extension tricks like invoice.pdf.exe"""
    parts = filename.lower().split(".")
    if len(parts) >= 3:
        last = f".{parts[-1]}"
        second_last = f".{parts[-2]}"
        if last in DANGEROUS_EXTENSIONS and second_last in {".pdf", ".doc", ".docx", ".jpg", ".png", ".txt"}:
            return True
    return False


def safe_filename(filename: str) -> str:
    """Sanitize filename for disk storage."""
    basename = os.path.basename(filename)
    safe = re.sub(r"[^\w\.\-]", "_", basename)
    return safe[:200] or "unknown"


def generate_analysis_id() -> str:
    return str(uuid.uuid4())


def create_safe_temp_dir() -> str:
    """Create a temporary directory for analysis. Caller must clean up."""
    return tempfile.mkdtemp(prefix="phishguard_")


# ── URL helpers ────────────────────────────────────────────────────────────────
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl",
    "rb.gy", "cutt.ly", "short.io", "is.gd", "v.gd",
    "buff.ly", "dlvr.it", "su.pr", "tiny.cc", "lnkd.in",
}

URL_PATTERN = re.compile(
    r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?::\d+)?(?:/[^\s<>\"']*)?",
    re.IGNORECASE,
)

IP_IN_URL = re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}")
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_urls(text: str) -> list[str]:
    if not text:
        return []
    return list(set(URL_PATTERN.findall(text)))


def is_ip_url(url: str) -> bool:
    return bool(IP_IN_URL.match(url))


def is_shortened_url(url: str) -> bool:
    from urllib.parse import urlparse
    try:
        host = urlparse(url).netloc.lower().lstrip("www.")
        return host in URL_SHORTENERS
    except Exception:
        return False


def extract_domain(url: str) -> Optional[str]:
    from urllib.parse import urlparse
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return None


def extract_ip_addresses(text: str) -> list[str]:
    if not text:
        return []

    found = IPV4_PATTERN.findall(text)
    valid = []

    for ip in found:
        parts = ip.split(".")
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            valid.append(ip)

    return list(dict.fromkeys(valid))


def extract_ips_from_urls(urls: list) -> list[str]:
    from urllib.parse import urlparse

    results = []

    for item in urls or []:
        if isinstance(item, dict):
            url = item.get("url", "")
        else:
            url = str(item)

        try:
            host = urlparse(url).hostname or ""
        except Exception:
            host = ""

        if host and IPV4_PATTERN.fullmatch(host):
            parts = host.split(".")
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                results.append(host)

    return list(dict.fromkeys(results))


def resolve_domains_to_ips(domains: list[str]) -> dict[str, list[str]]:
    results = {}

    for domain in domains or []:
        try:
            clean = domain.replace("http://", "").replace("https://", "").split("/")[0].strip().lower()
            if not clean:
                continue
            _, _, ips = socket.gethostbyname_ex(clean)
            results[clean] = list(dict.fromkeys(ips))
        except Exception:
            results[clean] = []

    return results


# ── Text helpers ───────────────────────────────────────────────────────────────
URGENCY_KEYWORDS = [
    "urgent", "immediately", "account suspended", "verify now",
    "click here", "limited time", "act now", "your account",
    "security alert", "unauthorized access", "confirm your",
    "update your", "expires today", "last chance", "warning",
    "alert", "suspended", "locked", "compromised",
]

CREDENTIAL_KEYWORDS = [
    "password", "username", "login", "sign in", "credentials",
    "social security", "credit card", "bank account", "ssn",
    "verify your identity", "confirm identity", "two-factor",
    "reset password", "change password",
]


def detect_urgency(text: str) -> list[str]:
    text_lower = text.lower()
    return [kw for kw in URGENCY_KEYWORDS if kw in text_lower]


def detect_credential_theft(text: str) -> list[str]:
    text_lower = text.lower()
    return [kw for kw in CREDENTIAL_KEYWORDS if kw in text_lower]