"""
PhishGuard SOC - Weighted Scoring Engine
Calculates phishing risk score and verdict from analysis findings.
"""
from dataclasses import dataclass, field
from typing import Optional

# ── Score weight table ─────────────────────────────────────────────────────────
SCORE_WEIGHTS = {
    "spf_fail":                  15,
    "dkim_fail":                 10,
    "dmarc_fail":                10,
    "reply_to_mismatch":         10,
    "display_name_spoof":        15,
    "suspicious_domain":         15,
    "credential_theft_wording":  10,
    "urgency_wording":            5,
    "url_uses_ip":               20,
    "link_text_mismatch":        15,
    "shortened_url":             10,
    "suspicious_html_form":      20,
    "macro_enabled_office":      20,
    "auto_exec_macro":           30,
    "suspicious_vba_keywords":   20,
    "obfuscated_vba":            25,
    "embedded_executable":       35,
    "password_protected_archive":20,
    "double_extension":          25,
    "suspicious_pdf_action":     20,
    "suspicious_pdf_object":     15,
    "yara_match":                50,
    "clamav_hit":                70,
    "pe_suspicious":             30,
}

# ── Verdict thresholds ────────────────────────────────────────────────────────
def score_to_verdict(score: int) -> str:
    if score >= 80:
        return "Malicious"
    elif score >= 50:
        return "Likely Phishing"
    elif score >= 25:
        return "Suspicious"
    else:
        return "Benign"


def verdict_color(verdict: str) -> str:
    mapping = {
        "Malicious": "red",
        "Likely Phishing": "orange",
        "Suspicious": "yellow",
        "Benign": "green",
    }
    return mapping.get(verdict, "gray")


# ── MITRE ATT&CK mapping ──────────────────────────────────────────────────────
MITRE_MAP = {
    "spf_fail":                  ("T1566.001", "Spearphishing Attachment"),
    "reply_to_mismatch":         ("T1566.002", "Spearphishing Link"),
    "display_name_spoof":        ("T1036",     "Masquerading"),
    "credential_theft_wording":  ("T1056",     "Input Capture"),
    "url_uses_ip":               ("T1566.002", "Spearphishing Link"),
    "macro_enabled_office":      ("T1566.001", "Spearphishing Attachment"),
    "auto_exec_macro":           ("T1059.005", "Visual Basic"),
    "obfuscated_vba":            ("T1027",     "Obfuscated Files or Information"),
    "embedded_executable":       ("T1027.002", "Software Packing"),
    "yara_match":                ("T1566",     "Phishing"),
    "clamav_hit":                ("T1566",     "Phishing"),
    "pe_suspicious":             ("T1204.002", "Malicious File"),
    "suspicious_pdf_action":     ("T1566.001", "Spearphishing Attachment"),
    "double_extension":          ("T1036.007", "Double File Extension"),
}


# ── Score dataclass ────────────────────────────────────────────────────────────
@dataclass
class ScoreResult:
    total: int = 0
    verdict: str = "Benign"
    breakdown: dict = field(default_factory=dict)
    explanations: list[str] = field(default_factory=list)
    mitre_techniques: list[dict] = field(default_factory=list)
    verdict_color: str = "green"


def calculate_score(triggered_rules: list[str], multipliers: Optional[dict] = None) -> ScoreResult:
    """
    triggered_rules: list of keys from SCORE_WEIGHTS that fired.
    multipliers: optional per-key multipliers (e.g., {"yara_match": 2}).
    Returns a ScoreResult with full breakdown.
    """
    breakdown = {}
    explanations = []
    mitre_seen = set()
    mitre_techniques = []
    total = 0

    for rule in triggered_rules:
        base = SCORE_WEIGHTS.get(rule, 0)
        if base == 0:
            continue
        mult = (multipliers or {}).get(rule, 1)
        pts = min(base * mult, 100)  # cap single rule at 100
        breakdown[rule] = pts
        total += pts
        explanations.append(_explain(rule, pts))

        if rule in MITRE_MAP:
            tech_id, tech_name = MITRE_MAP[rule]
            if tech_id not in mitre_seen:
                mitre_seen.add(tech_id)
                mitre_techniques.append({"id": tech_id, "name": tech_name, "triggered_by": rule})

    total = min(total, 100)  # cap at 100
    verdict = score_to_verdict(total)

    return ScoreResult(
        total=total,
        verdict=verdict,
        breakdown=breakdown,
        explanations=explanations,
        mitre_techniques=mitre_techniques,
        verdict_color=verdict_color(verdict),
    )


def _explain(rule: str, pts: int) -> str:
    EXPLANATIONS = {
        "spf_fail":                  f"SPF check failed, indicating possible email spoofing (+{pts})",
        "dkim_fail":                 f"DKIM signature failed or missing (+{pts})",
        "dmarc_fail":                f"DMARC policy failed (+{pts})",
        "reply_to_mismatch":         f"Reply-To address differs from sender — common phishing technique (+{pts})",
        "display_name_spoof":        f"Display name does not match sender domain (+{pts})",
        "suspicious_domain":         f"Sender domain shows signs of spoofing or lookalike domain (+{pts})",
        "credential_theft_wording":  f"Email body contains credential-harvesting language (+{pts})",
        "urgency_wording":           f"Email uses urgency-inducing language to pressure the recipient (+{pts})",
        "url_uses_ip":               f"URL contains a raw IP address instead of a domain name (+{pts})",
        "link_text_mismatch":        f"Hyperlink display text differs from actual destination URL (+{pts})",
        "shortened_url":             f"URL shortener detected — hides true destination (+{pts})",
        "suspicious_html_form":      f"HTML form present — may harvest credentials (+{pts})",
        "macro_enabled_office":      f"Office file with macro support detected (+{pts})",
        "auto_exec_macro":           f"Auto-executing macro found — runs on open (+{pts})",
        "suspicious_vba_keywords":   f"Suspicious VBA keywords detected in macro (+{pts})",
        "obfuscated_vba":            f"VBA code appears obfuscated to evade detection (+{pts})",
        "embedded_executable":       f"Executable embedded in archive (+{pts})",
        "password_protected_archive":f"Password-protected archive — prevents automated scanning (+{pts})",
        "double_extension":          f"Double extension detected (e.g. invoice.pdf.exe) — extension spoofing (+{pts})",
        "suspicious_pdf_action":     f"PDF contains suspicious /JS or /Launch actions (+{pts})",
        "suspicious_pdf_object":     f"PDF contains suspicious embedded objects (+{pts})",
        "yara_match":                f"YARA rule matched known phishing/malware pattern (+{pts})",
        "clamav_hit":                f"ClamAV detected a known malware signature (+{pts})",
        "pe_suspicious":             f"PE executable has suspicious characteristics (+{pts})",
    }
    return EXPLANATIONS.get(rule, f"Suspicious indicator detected: {rule} (+{pts})")
