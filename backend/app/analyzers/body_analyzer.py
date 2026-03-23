"""
PhishGuard SOC - Body & URL Analyzer
Detects credential-theft language, urgency wording, suspicious URLs,
link mismatches, suspicious HTML forms.
"""
from bs4 import BeautifulSoup
from app.core.utils import detect_urgency, detect_credential_theft


def analyze_body(body_text: str, body_html: str) -> dict:
    """
    Scan email body (plain text + HTML) for phishing indicators.
    """
    triggered = []
    details = []
    combined = (body_text + " " + body_html).strip()

    # ── Credential theft wording ──────────────────────────────────────────────
    cred_hits = detect_credential_theft(combined)
    if cred_hits:
        triggered.append("credential_theft_wording")
        details.append(f"Credential-related keywords found: {', '.join(cred_hits[:5])}")

    # ── Urgency wording ───────────────────────────────────────────────────────
    urgency_hits = detect_urgency(combined)
    if urgency_hits:
        triggered.append("urgency_wording")
        details.append(f"Urgency keywords found: {', '.join(urgency_hits[:5])}")

    # ── HTML form detection ───────────────────────────────────────────────────
    if body_html:
        soup = BeautifulSoup(body_html, "lxml")
        forms = soup.find_all("form")
        if forms:
            triggered.append("suspicious_html_form")
            details.append(f"HTML form(s) detected in email body — may harvest credentials ({len(forms)} form(s))")

    return {
        "triggered_rules": triggered,
        "details": details,
        "urgency_keywords": urgency_hits,
        "credential_keywords": cred_hits,
    }


def analyze_urls(url_list: list[dict], link_mismatches: list[dict]) -> dict:
    """
    Analyze extracted URLs for phishing indicators.
    url_list: output from email_parser._extract_all_urls
    link_mismatches: output from email_parser._find_link_mismatches
    """
    triggered = []
    details = []

    ip_urls = [u["url"] for u in url_list if u.get("is_ip_url")]
    if ip_urls:
        triggered.append("url_uses_ip")
        details.append(f"IP-based URLs found: {ip_urls[:3]}")

    short_urls = [u["url"] for u in url_list if u.get("is_shortened")]
    if short_urls:
        triggered.append("shortened_url")
        details.append(f"URL shorteners detected: {short_urls[:3]}")

    if link_mismatches:
        triggered.append("link_text_mismatch")
        details.append(f"Link text vs. href mismatches: {len(link_mismatches)} found")

    # Collect IOC domains
    ioc_domains = list({u.get("domain") for u in url_list if u.get("domain")})
    ioc_urls = [u["url"] for u in url_list]

    return {
        "triggered_rules": triggered,
        "details": details,
        "ioc_urls": ioc_urls,
        "ioc_domains": ioc_domains,
        "ip_urls": ip_urls,
        "short_urls": short_urls,
        "link_mismatches": link_mismatches,
    }
