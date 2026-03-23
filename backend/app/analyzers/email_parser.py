"""
PhishGuard SOC - Email Parser
Parses .eml files using mail-parser. Extracts headers, body, URLs,
IP addresses, transmission hops, and attachment metadata.
"""

import re
from typing import Optional
import mailparser

from app.core.utils import (
    extract_urls,
    is_ip_url,
    is_shortened_url,
    extract_domain,
    extract_ip_addresses,
    extract_ips_from_urls,
    resolve_domains_to_ips,
)


def parse_eml(raw_bytes: bytes) -> dict:
    try:
        mail = mailparser.parse_from_bytes(raw_bytes)
    except Exception as e:
        return {
            "error": str(e),
            "headers": {},
            "body_text": "",
            "body_html": "",
            "urls": [],
            "ip_addresses": [],
            "attachments": [],
            "raw_attachments": [],
            "subject": "",
            "link_mismatches": [],
            "resolved_domain_ips": {},
            "transmission_hops": [],
        }

    headers = _extract_headers(mail)
    body_text = mail.body or ""
    body_html = "\n".join(
        (p if isinstance(p, str) else p.get("payload", ""))
        for p in (mail.text_html or [])
    ) if mail.text_html else ""

    urls = _extract_all_urls(body_text, body_html)

    domains = list(dict.fromkeys(
        item.get("domain", "")
        for item in urls
        if isinstance(item, dict) and item.get("domain")
    ))

    resolved_domain_ips = resolve_domains_to_ips(domains)

    received_data = headers.get("received", [])
    if isinstance(received_data, str):
        received_headers = [received_data]
    elif isinstance(received_data, list):
        received_headers = received_data
    else:
        received_headers = []

    received_text = "\n".join(str(x) for x in received_headers)

    ip_addresses = []
    ip_addresses.extend(extract_ip_addresses(body_text))
    ip_addresses.extend(extract_ip_addresses(body_html))
    ip_addresses.extend(extract_ip_addresses(received_text))
    ip_addresses.extend(extract_ips_from_urls(urls))

    for _, ips in resolved_domain_ips.items():
        ip_addresses.extend(ips)

    ip_addresses = list(dict.fromkeys(ip_addresses))

    transmission_hops = _parse_received_hops(received_headers)

    link_mismatches = _find_link_mismatches(body_html)
    attachments = _extract_attachment_meta(mail)

    return {
        "headers": headers,
        "body_text": body_text,
        "body_html": body_html,
        "subject": mail.subject or "",
        "urls": urls,
        "ip_addresses": ip_addresses,
        "resolved_domain_ips": resolved_domain_ips,
        "link_mismatches": link_mismatches,
        "attachments": attachments,
        "raw_attachments": mail.attachments or [],
        "transmission_hops": transmission_hops,
    }


def _extract_headers(mail) -> dict:
    from_addr = mail.from_[0] if mail.from_ else []
    to_addr = mail.to[0] if mail.to else []

    def addr_str(addr):
        if isinstance(addr, (list, tuple)) and len(addr) == 2:
            return addr[1] or addr[0]
        return str(addr)

    def display_name(addr):
        if isinstance(addr, (list, tuple)) and len(addr) == 2:
            return addr[0] or ""
        return ""

    from_email = addr_str(from_addr) if from_addr else ""
    from_name = display_name(from_addr) if from_addr else ""
    to_email = addr_str(to_addr) if to_addr else ""

    reply_to_list = mail.reply_to or []
    reply_to = addr_str(reply_to_list[0]) if reply_to_list else ""

    return_path = _get_header_value(mail, "Return-Path") or ""
    message_id = _get_header_value(mail, "Message-ID") or ""
    received = _get_all_header_values(mail, "Received")
    x_mailer = _get_header_value(mail, "X-Mailer") or ""

    spf = _extract_auth_result(mail, "spf")
    dkim = _extract_auth_result(mail, "dkim")
    dmarc = _extract_auth_result(mail, "dmarc")

    return {
        "from_email": from_email,
        "from_name": from_name,
        "to": to_email,
        "subject": mail.subject or "",
        "reply_to": reply_to,
        "return_path": return_path,
        "message_id": message_id,
        "received": received,
        "x_mailer": x_mailer,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "date": str(mail.date) if mail.date else "",
    }


def _get_header_value(mail, name: str) -> Optional[str]:
    headers_dict = mail.headers
    if isinstance(headers_dict, dict):
        for k, v in headers_dict.items():
            if k.lower() == name.lower():
                if isinstance(v, list):
                    return str(v[0]) if v else ""
                return str(v)
    return None


def _get_all_header_values(mail, name: str) -> list[str]:
    values = []
    headers_dict = mail.headers

    if isinstance(headers_dict, dict):
        for k, v in headers_dict.items():
            if k.lower() == name.lower():
                if isinstance(v, list):
                    values.extend(str(x) for x in v)
                else:
                    values.append(str(v))

    return values


def _extract_auth_result(mail, auth_type: str) -> str:
    ar = _get_header_value(mail, "Authentication-Results") or ""
    ar_lower = ar.lower()
    pattern = rf"{auth_type}=(\w+)"
    match = re.search(pattern, ar_lower)
    if match:
        return match.group(1)
    return "none"


def _extract_all_urls(text: str, html: str) -> list[dict]:
    all_urls = set()

    for u in extract_urls(text):
        all_urls.add(u)
    for u in extract_urls(html):
        all_urls.add(u)

    results = []
    for url in all_urls:
        results.append({
            "url": url,
            "domain": extract_domain(url),
            "is_ip_url": is_ip_url(url),
            "is_shortened": is_shortened_url(url),
        })
    return results


def _find_link_mismatches(html: str) -> list[dict]:
    if not html:
        return []

    pattern = re.compile(
        r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>\s*(.*?)\s*</a>',
        re.IGNORECASE | re.DOTALL
    )

    mismatches = []
    for match in pattern.finditer(html):
        href = match.group(1).strip()
        text = re.sub(r"<[^>]+>", "", match.group(2)).strip()

        if text.startswith("http") and not text.startswith(href[:20]):
            mismatches.append({"display": text, "actual_href": href})
        elif href.startswith("http") and text and extract_domain(href) not in text.lower():
            if len(text) > 5 and not text.startswith("http"):
                mismatches.append({"display": text, "actual_href": href})

    return mismatches[:20]


def _extract_attachment_meta(mail) -> list[dict]:
    results = []
    for att in (mail.attachments or []):
        payload = att.get("payload", b"") or b""
        if isinstance(payload, str):
            payload = payload.encode(errors="ignore")

        results.append({
            "filename": att.get("filename", "unknown"),
            "content_type": att.get("mail_content_type", ""),
            "size": len(payload),
        })
    return results


def _parse_received_hops(received_headers: list[str]) -> list[dict]:
    hops = []

    for idx, raw in enumerate(received_headers, start=1):
        header = str(raw).replace("\n", " ").replace("\r", " ").strip()

        from_value = ""
        by_value = ""
        date_value = ""
        ip_addresses = []

        from_match = re.search(r"\bfrom\s+(.+?)(?=\s+by\s+|\s+with\s+|\s+id\s+|;|$)", header, re.IGNORECASE)
        if from_match:
            from_value = from_match.group(1).strip()

        by_match = re.search(r"\bby\s+(.+?)(?=\s+with\s+|\s+id\s+|;|$)", header, re.IGNORECASE)
        if by_match:
            by_value = by_match.group(1).strip()

        date_match = re.search(r";\s*(.+)$", header)
        if date_match:
            date_value = date_match.group(1).strip()

        ipv4s = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", header)
        ipv6s = re.findall(r"\b(?:[A-Fa-f0-9:]+:+)+[A-Fa-f0-9]+\b", header)

        seen = set()
        for ip in ipv4s + ipv6s:
            if ip not in seen:
                seen.add(ip)
                ip_addresses.append(ip)

        hops.append({
            "hop": idx,
            "date": date_value,
            "received_from": from_value,
            "received_by": by_value,
            "ip_addresses": ip_addresses,
            "raw": header,
        })

    return hops