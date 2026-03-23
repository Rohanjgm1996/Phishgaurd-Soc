"""
PhishGuard SOC - Email Header Analyzer
Checks SPF/DKIM/DMARC, reply-to mismatches, display-name spoofing.
"""
import re
from app.core.utils import extract_domain


def analyze_headers(headers: dict) -> dict:
    """
    Analyse extracted email headers for phishing indicators.
    Returns a dict with triggered rules and details.
    """
    triggered = []
    details = []

    from_email = headers.get("from_email", "").lower()
    reply_to = headers.get("reply_to", "").lower()
    return_path = headers.get("return_path", "").lower()
    from_name = headers.get("from_name", "")
    spf = headers.get("spf", "none")
    dkim = headers.get("dkim", "none")
    dmarc = headers.get("dmarc", "none")

    # ── SPF / DKIM / DMARC ────────────────────────────────────────────────────
    if spf in ("fail", "softfail", "neutral"):
        triggered.append("spf_fail")
        details.append(f"SPF result: {spf}")

    if dkim in ("fail", "none"):
        triggered.append("dkim_fail")
        details.append(f"DKIM result: {dkim}")

    if dmarc in ("fail", "none"):
        triggered.append("dmarc_fail")
        details.append(f"DMARC result: {dmarc}")

    # ── Reply-To mismatch ─────────────────────────────────────────────────────
    if reply_to and from_email:
        from_domain = extract_domain(f"mailto://{from_email}") or from_email.split("@")[-1]
        reply_domain = extract_domain(f"mailto://{reply_to}") or reply_to.split("@")[-1]
        if from_domain and reply_domain and from_domain != reply_domain:
            triggered.append("reply_to_mismatch")
            details.append(f"From domain ({from_domain}) != Reply-To domain ({reply_domain})")

    # ── Display name spoofing ──────────────────────────────────────────────────
    # e.g. display name says "PayPal Support" but email is from random domain
    trusted_brands = [
        "paypal", "amazon", "microsoft", "apple", "google", "facebook",
        "netflix", "bank", "chase", "wells fargo", "irs", "fedex", "ups",
        "dhl", "usps", "dropbox", "linkedin",
    ]
    from_name_lower = from_name.lower()
    if any(brand in from_name_lower for brand in trusted_brands):
        # check if the actual email domain matches the brand
        from_email_domain = from_email.split("@")[-1] if "@" in from_email else ""
        brand_match = any(brand in from_email_domain for brand in trusted_brands)
        if not brand_match:
            triggered.append("display_name_spoof")
            details.append(
                f"Display name '{from_name}' impersonates a trusted brand "
                f"but actual sender is <{from_email}>"
            )

    # ── Suspicious domain (lookalike) ─────────────────────────────────────────
    lookalike_patterns = [
        r"paypa1\.", r"arnazon\.", r"micosoft\.", r"g00gle\.",
        r"app1e\.", r"secure-.*\.", r"login-.*\.", r"update-.*\.",
        r".*-support\.", r".*-security\.",
    ]
    for pat in lookalike_patterns:
        if re.search(pat, from_email):
            triggered.append("suspicious_domain")
            details.append(f"Sender domain appears to be a lookalike domain: {from_email}")
            break

    return {
        "triggered_rules": triggered,
        "details": details,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
    }
