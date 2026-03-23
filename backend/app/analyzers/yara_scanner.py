"""
PhishGuard SOC - YARA Scanner
Compiles all .yar rules from the rules directory and scans file bytes.
SAFE: read-only memory scan, no execution.
"""
import os
import glob
from typing import Optional

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

from app.core.config import settings

_compiled_rules = None  # cached compiled ruleset


def _load_rules() -> Optional[object]:
    """Compile all YARA rules from the rules directory."""
    global _compiled_rules
    if _compiled_rules is not None:
        return _compiled_rules

    if not YARA_AVAILABLE:
        return None

    rule_files = glob.glob(os.path.join(settings.YARA_RULES_DIR, "*.yar"))
    rule_files += glob.glob(os.path.join(settings.YARA_RULES_DIR, "**/*.yar"), recursive=True)

    if not rule_files:
        return None

    sources = {}
    for path in rule_files:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                sources[os.path.basename(path)] = f.read()
        except Exception:
            continue

    if not sources:
        return None

    try:
        _compiled_rules = yara.compile(sources=sources)
        return _compiled_rules
    except yara.SyntaxError as e:
        print(f"[YARA] Rule compilation error: {e}")
        return None


def yara_scan(file_bytes: bytes) -> dict:
    """
    Scan file_bytes against compiled YARA rules.
    Returns triggered rules and details.
    """
    result = {
        "triggered_rules": [],
        "details": [],
        "matches": [],
    }

    if not YARA_AVAILABLE:
        result["details"].append("yara-python not installed — YARA scan skipped")
        return result

    rules = _load_rules()
    if rules is None:
        result["details"].append("No YARA rules loaded")
        return result

    try:
        matches = rules.match(data=file_bytes, timeout=30)
        for m in matches:
            result["matches"].append({
                "rule": m.rule,
                "namespace": m.namespace,
                "tags": list(m.tags),
                "strings": [
                    {"identifier": s.identifier, "offset": s.instances[0].offset if s.instances else 0}
                    for s in m.strings
                ][:5],
            })

        if result["matches"]:
            result["triggered_rules"].append("yara_match")
            rule_names = [m["rule"] for m in result["matches"]]
            result["details"].append(f"YARA rules matched: {rule_names}")

    except yara.TimeoutError:
        result["details"].append("YARA scan timed out")
    except Exception as e:
        result["details"].append(f"YARA scan error: {e}")

    return result


def reload_rules():
    """Force reload of YARA rules (e.g. after updating rule files)."""
    global _compiled_rules
    _compiled_rules = None
    return _load_rules() is not None
