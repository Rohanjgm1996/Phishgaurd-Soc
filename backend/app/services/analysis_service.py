"""
PhishGuard SOC - Analysis Service
Orchestrates the full analysis pipeline for emails and standalone files.
Persists results to the database and writes report files.
"""
import json
import os
import shutil

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.utils import compute_hashes, generate_analysis_id, safe_filename, create_safe_temp_dir
from app.core.scoring import calculate_score
from app.analyzers.email_parser import parse_eml
from app.analyzers.header_analyzer import analyze_headers
from app.analyzers.body_analyzer import analyze_body, analyze_urls
from app.analyzers.attachment_analyzer import analyze_attachment
from app.models.database import Analysis
from app.reports.json_report import build_json_report
from app.reports.html_report import build_html_report


async def run_email_analysis(
    file_bytes: bytes,
    filename: str,
    db: AsyncSession,
    user_id: int = None,
) -> Analysis:
    analysis_id = generate_analysis_id()
    hashes = compute_hashes(file_bytes)
    temp_dir = create_safe_temp_dir()

    try:
        parsed = parse_eml(file_bytes)
        headers = parsed.get("headers", {})
        urls = parsed.get("urls", [])
        ip_addresses = parsed.get("ip_addresses", [])
        resolved_domain_ips = parsed.get("resolved_domain_ips", {})
        link_mismatches = parsed.get("link_mismatches", [])
        body_text = parsed.get("body_text", "")
        body_html = parsed.get("body_html", "")
        raw_attachments = parsed.get("raw_attachments", [])
        transmission_hops = parsed.get("transmission_hops", [])

        header_result = analyze_headers(headers)
        body_result = analyze_body(body_text, body_html)
        url_result = analyze_urls(urls, link_mismatches)

        all_triggered = []
        all_triggered.extend(header_result.get("triggered_rules", []))
        all_triggered.extend(body_result.get("triggered_rules", []))
        all_triggered.extend(url_result.get("triggered_rules", []))

        all_findings = _collect_findings("Email Header Analysis", header_result.get("details", []))
        all_findings += _collect_findings("Body Analysis", body_result.get("details", []))
        all_findings += _collect_findings("URL Analysis", body_result.get("details", []))

        attachment_summaries = []
        ioc_hashes = []

        for att in raw_attachments:
            att_bytes = att.get("payload")
            att_name = att.get("filename", "attachment")
            if not att_bytes:
                continue

            if isinstance(att_bytes, str):
                try:
                    import base64
                    att_bytes = base64.b64decode(att_bytes)
                except Exception:
                    att_bytes = att_bytes.encode("latin-1", errors="ignore")

            att_result = analyze_attachment(att_bytes, att_name)
            all_triggered.extend(att_result.get("triggered_rules", []))
            all_findings += _collect_findings(f"Attachment: {att_name}", att_result.get("details", []))

            attachment_summaries.append({
                "filename": att_name,
                "size": att_result.get("size", 0),
                "hashes": att_result.get("hashes", {}),
                "file_type": att_result.get("file_type", {}),
                "triggered_rules": att_result.get("triggered_rules", []),
                "yara_matches": att_result.get("yara_result", {}).get("matches", []),
                "clamav": att_result.get("clamav_result", {}).get("verdict", "unknown"),
            })
            ioc_hashes.append(att_result.get("hashes", {}))

        score_result = calculate_score(list(set(all_triggered)))

        ioc_domains = list(dict.fromkeys(
            [d for d in url_result.get("ioc_domains", []) if d] +
            [u.get("domain") for u in urls if isinstance(u, dict) and u.get("domain")]
        ))

        ioc_ips = list(dict.fromkeys(
            [ip for ip in ip_addresses if ip] +
            [u.replace("http://", "").replace("https://", "").split("/")[0]
             for u in url_result.get("ip_urls", [])]
        ))

        iocs = {
            "urls": url_result.get("ioc_urls", []),
            "domains": ioc_domains,
            "ips": ioc_ips,
            "ip_addresses": ioc_ips,
            "resolved_domain_ips": resolved_domain_ips,
            "emails": [headers.get("from_email", ""), headers.get("reply_to", "")],
            "hashes": ioc_hashes,
        }
        iocs["emails"] = [e for e in iocs["emails"] if e]

        analysis = Analysis(
            analysis_id=analysis_id,
            original_filename=safe_filename(filename),
            sample_type="email",
            file_size=len(file_bytes),
            md5=hashes["md5"],
            sha1=hashes["sha1"],
            sha256=hashes["sha256"],
            score=score_result.total,
            verdict=score_result.verdict,
            verdict_color=score_result.verdict_color,
            findings_json=json.dumps(all_findings),
            iocs_json=json.dumps(iocs),
            score_breakdown_json=json.dumps(score_result.breakdown),
            explanations_json=json.dumps(score_result.explanations),
            mitre_json=json.dumps(score_result.mitre_techniques),
            headers_json=json.dumps(headers),
            urls_json=json.dumps([u.get("url") for u in urls if isinstance(u, dict) and u.get("url")]),
            attachments_json=json.dumps(attachment_summaries),
            user_id=user_id,
        )
        db.add(analysis)
        await db.flush()

        report_data = _build_report_data(
            analysis,
            score_result,
            iocs,
            all_findings,
            attachment_summaries,
            transmission_hops,
        )
        json_path, html_path = _write_reports(analysis_id, report_data)

        analysis.report_json_path = json_path
        analysis.report_html_path = html_path
        await db.commit()
        await db.refresh(analysis)
        return analysis

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


async def run_file_analysis(
    file_bytes: bytes,
    filename: str,
    db: AsyncSession,
    user_id: int = None,
) -> Analysis:
    analysis_id = generate_analysis_id()
    hashes = compute_hashes(file_bytes)

    att_result = analyze_attachment(file_bytes, filename)
    all_triggered = att_result.get("triggered_rules", [])
    all_findings = _collect_findings("Attachment Analysis", att_result.get("details", []))

    score_result = calculate_score(list(set(all_triggered)))

    iocs = {
        "urls": [],
        "domains": [],
        "ips": [],
        "ip_addresses": [],
        "resolved_domain_ips": {},
        "emails": [],
        "hashes": [hashes],
    }

    attachment_summaries = [{
        "filename": filename,
        "size": len(file_bytes),
        "hashes": hashes,
        "file_type": att_result.get("file_type", {}),
        "triggered_rules": all_triggered,
        "yara_matches": att_result.get("yara_result", {}).get("matches", []),
        "clamav": att_result.get("clamav_result", {}).get("verdict", "unknown"),
    }]

    analysis = Analysis(
        analysis_id=analysis_id,
        original_filename=safe_filename(filename),
        sample_type="attachment",
        file_size=len(file_bytes),
        md5=hashes["md5"],
        sha1=hashes["sha1"],
        sha256=hashes["sha256"],
        score=score_result.total,
        verdict=score_result.verdict,
        verdict_color=score_result.verdict_color,
        findings_json=json.dumps(all_findings),
        iocs_json=json.dumps(iocs),
        score_breakdown_json=json.dumps(score_result.breakdown),
        explanations_json=json.dumps(score_result.explanations),
        mitre_json=json.dumps(score_result.mitre_techniques),
        headers_json=json.dumps({}),
        urls_json=json.dumps([]),
        attachments_json=json.dumps(attachment_summaries),
        user_id=user_id,
    )
    db.add(analysis)
    await db.flush()

    report_data = _build_report_data(
        analysis,
        score_result,
        iocs,
        all_findings,
        attachment_summaries,
        [],
    )
    json_path, html_path = _write_reports(analysis_id, report_data)

    analysis.report_json_path = json_path
    analysis.report_html_path = html_path
    await db.commit()
    await db.refresh(analysis)
    return analysis


def _collect_findings(section: str, details: list[str]) -> list[dict]:
    return [{"section": section, "detail": d} for d in details if d]


def _build_report_data(
    analysis: Analysis,
    score_result,
    iocs: dict,
    findings: list,
    attachments: list,
    transmission_hops: list,
) -> dict:
    return {
        "analysis_id": analysis.analysis_id,
        "filename": analysis.original_filename,
        "original_filename": analysis.original_filename,
        "sample_type": analysis.sample_type,
        "upload_time": analysis.upload_time.isoformat() if analysis.upload_time else "",
        "file_size": analysis.file_size,
        "md5": analysis.md5,
        "sha1": analysis.sha1,
        "sha256": analysis.sha256,
        "score": score_result.total,
        "verdict": score_result.verdict,
        "verdict_color": score_result.verdict_color,
        "score_breakdown": score_result.breakdown,
        "explanations": score_result.explanations,
        "mitre": score_result.mitre_techniques,
        "iocs": iocs,
        "findings": findings,
        "attachments": attachments,
        "headers": json.loads(analysis.headers_json) if analysis.headers_json else {},
        "transmission_hops": transmission_hops,
        "analyst_notes": analysis.analyst_notes or "",
    }


def _write_reports(analysis_id: str, data: dict) -> tuple[str, str]:
    os.makedirs(settings.REPORTS_DIR, exist_ok=True)
    json_path = os.path.join(settings.REPORTS_DIR, f"{analysis_id}.json")
    html_path = os.path.join(settings.REPORTS_DIR, f"{analysis_id}.html")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(build_json_report(data), f, indent=2)

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(build_html_report(data))

    return json_path, html_path