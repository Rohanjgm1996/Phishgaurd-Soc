"""
PhishGuard SOC - Analyze API Router
POST /api/analyze/email
POST /api/analyze/file
POST /api/analyze/virustotal-search
POST /api/analyze/anyrun
"""
import os
import base64
import requests

from dotenv import load_dotenv
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import get_current_user
from app.models.database import get_db
from app.services.analysis_service import run_email_analysis, run_file_analysis

load_dotenv()

router = APIRouter(prefix="/api/analyze", tags=["analyze"])


class VTSearchRequest(BaseModel):
    query_type: str
    query: str


class HashLookupRequest(BaseModel):
    hash: str


async def _read_file(upload: UploadFile) -> bytes:
    data = await upload.read()
    if len(data) > settings.max_file_size_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum allowed size of {settings.MAX_FILE_SIZE_MB} MB",
        )
    return data


def _summary(analysis) -> dict:
    return {
        "analysis_id": analysis.analysis_id,
        "filename": analysis.original_filename,
        "sample_type": analysis.sample_type,
        "score": analysis.score,
        "verdict": analysis.verdict,
        "verdict_color": analysis.verdict_color,
        "md5": analysis.md5,
        "sha256": analysis.sha256,
    }


def _vt_headers() -> dict:
    api_key = os.getenv("VT_API_KEY") or settings.VT_API_KEY
    if not api_key:
        raise HTTPException(status_code=500, detail="VT_API_KEY not found in backend .env")
    return {"x-apikey": api_key}


def _vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")


def _build_cia_mitre_killchain(query_type: str, attributes: dict, stats: dict) -> dict:
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    tags = [str(tag).lower() for tag in (attributes.get("tags") or [])]

    cia = {
        "confidentiality": "Low",
        "integrity": "Low",
        "availability": "Low",
    }

    mitre_attack = []
    cyber_kill_chain = []

    if query_type == "url":
        cyber_kill_chain = ["Delivery"]
        mitre_attack.append({"id": "T1566", "name": "Phishing"})

    elif query_type == "domain":
        cyber_kill_chain = ["Delivery", "Command and Control"]
        mitre_attack.append({"id": "T1566", "name": "Phishing"})
        mitre_attack.append({"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols"})

    elif query_type == "ip":
        cyber_kill_chain = ["Command and Control"]
        mitre_attack.append({"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols"})

    elif query_type == "hash":
        cyber_kill_chain = ["Exploitation", "Installation", "Actions on Objectives"]
        mitre_attack.append({"id": "T1204", "name": "User Execution"})
        mitre_attack.append({"id": "T1059", "name": "Command and Scripting Interpreter"})

    if malicious > 0:
        cia["confidentiality"] = "High"
        cia["integrity"] = "High"
        cia["availability"] = "Medium"

        if {"phishing", "phish", "login", "credential"}.intersection(tags):
            mitre_attack.append({"id": "T1566", "name": "Phishing"})
            mitre_attack.append({"id": "T1056", "name": "Input Capture"})
            cyber_kill_chain = ["Reconnaissance", "Weaponization", "Delivery", "Exploitation"]

        if query_type == "hash":
            mitre_attack.append({"id": "T1105", "name": "Ingress Tool Transfer"})
            mitre_attack.append({"id": "T1055", "name": "Process Injection"})

    elif suspicious > 0:
        cia["confidentiality"] = "Medium"
        cia["integrity"] = "Medium"
        cia["availability"] = "Low"

        if "Delivery" not in cyber_kill_chain:
            cyber_kill_chain.append("Delivery")

    # de-duplicate
    unique_mitre = []
    seen_mitre = set()
    for item in mitre_attack:
        key = (item["id"], item["name"])
        if key not in seen_mitre:
            seen_mitre.add(key)
            unique_mitre.append(item)

    unique_kill_chain = []
    seen_kc = set()
    for stage in cyber_kill_chain:
        if stage not in seen_kc:
            seen_kc.add(stage)
            unique_kill_chain.append(stage)

    return {
        "cia": cia,
        "mitre_attack": unique_mitre,
        "cyber_kill_chain": unique_kill_chain,
    }


def _normalize_vt_result(query_type: str, query: str, raw: dict) -> dict:
    data = raw.get("data", {}) if isinstance(raw, dict) else {}
    attributes = data.get("attributes", {}) if isinstance(data, dict) else {}

    stats = attributes.get("last_analysis_stats", {}) or {}
    results = attributes.get("last_analysis_results", {}) or {}

    harmless = int(stats.get("harmless", 0) or 0)
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)
    timeout = int(stats.get("timeout", 0) or 0)

    total = harmless + malicious + suspicious + undetected + timeout
    detection_score = malicious + suspicious

    if malicious > 0:
        verdict = "Malicious"
    elif suspicious > 0:
        verdict = "Suspicious"
    else:
        verdict = "Clean"

    vendors = []
    if isinstance(results, dict):
        for vendor_name, vendor_data in results.items():
            category = vendor_data.get("category", "undetected")
            result_value = vendor_data.get("result")
            engine_name = vendor_data.get("engine_name", vendor_name)

            if category == "malicious":
                status = "Malicious"
            elif category == "suspicious":
                status = "Suspicious"
            elif category == "harmless":
                status = "Clean"
            else:
                status = "Undetected"

            vendors.append({
                "vendor": engine_name,
                "status": status,
                "result": result_value,
                "category": category,
            })

    vendors = sorted(
        vendors,
        key=lambda x: (
            0 if x["status"] == "Malicious" else
            1 if x["status"] == "Suspicious" else
            2 if x["status"] == "Clean" else
            3
        )
    )

    enrichment = _build_cia_mitre_killchain(query_type, attributes, stats)

    return {
        "query_type": query_type,
        "query": query,
        "id": data.get("id"),
        "type": data.get("type"),
        "verdict": verdict,
        "stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "timeout": timeout,
            "total": total,
            "score": detection_score,
        },
        "summary": {
            "title": query,
            "community_score": attributes.get("reputation", 0),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "creation_date": attributes.get("creation_date"),
            "registrar": attributes.get("registrar"),
            "whois_date": attributes.get("whois_date"),
            "country": attributes.get("country"),
            "network": attributes.get("network"),
            "as_owner": attributes.get("as_owner"),
            "asn": attributes.get("asn"),
            "tags": attributes.get("tags", []),
            "categories": attributes.get("categories", {}),
            "meaningful_name": attributes.get("meaningful_name"),
            "type_description": attributes.get("type_description"),
            "times_submitted": attributes.get("times_submitted"),
            "size": attributes.get("size"),
            "popular_threat_classification": attributes.get("popular_threat_classification"),
            "last_modification_date": attributes.get("last_modification_date"),
        },
        "vendors": vendors,
        "cia": enrichment["cia"],
        "mitre_attack": enrichment["mitre_attack"],
        "cyber_kill_chain": enrichment["cyber_kill_chain"],
        "raw": raw,
    }


def _search_vt(query_type: str, query: str) -> dict:
    headers = _vt_headers()
    query_type = query_type.lower().strip()
    query = query.strip()

    try:
        if query_type == "url":
            url_id = _vt_url_id(query)
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            response = requests.get(endpoint, headers=headers, timeout=30)

        elif query_type == "domain":
            endpoint = f"https://www.virustotal.com/api/v3/domains/{query}"
            response = requests.get(endpoint, headers=headers, timeout=30)

        elif query_type == "ip":
            endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{query}"
            response = requests.get(endpoint, headers=headers, timeout=30)

        elif query_type == "hash":
            endpoint = f"https://www.virustotal.com/api/v3/files/{query}"
            response = requests.get(endpoint, headers=headers, timeout=30)

        else:
            raise HTTPException(status_code=400, detail="query_type must be one of: url, domain, ip, hash")

        if response.status_code >= 400:
            return {
                "error": f"VirusTotal request failed with status {response.status_code}",
                "details": response.text,
            }

        raw = response.json()
        return _normalize_vt_result(query_type, query, raw)

    except HTTPException:
        raise
    except Exception as exc:
        return {"error": f"VirusTotal failed: {str(exc)}"}


def _check_anyrun(hash_value: str) -> dict:
    api_key = os.getenv("ANYRUN_API_KEY") or settings.ANYRUN_API_KEY
    if not api_key:
        return {"error": "ANYRUN_API_KEY not found in backend .env"}

    try:
        endpoint = f"https://api.any.run/v1/analysis/{hash_value}"
        headers = {"Authorization": f"API-Key {api_key}"}
        response = requests.get(endpoint, headers=headers, timeout=25)

        if response.status_code >= 400:
            return {
                "error": f"ANY.RUN request failed with status {response.status_code}",
                "details": response.text,
            }

        return response.json()
    except Exception as exc:
        return {"error": f"ANY.RUN failed: {str(exc)}"}


@router.post("/email")
async def analyze_email(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files accepted for email analysis")

    data = await _read_file(file)
    analysis = await run_email_analysis(data, file.filename, db, user_id=current_user.id)
    return _summary(analysis)


@router.post("/file")
async def analyze_file(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    data = await _read_file(file)
    analysis = await run_file_analysis(data, file.filename, db, user_id=current_user.id)
    return _summary(analysis)


@router.post("/virustotal-search")
async def virustotal_search(
    payload: VTSearchRequest,
    current_user=Depends(get_current_user),
):
    if not payload.query.strip():
        raise HTTPException(status_code=400, detail="Query is required")

    return _search_vt(payload.query_type, payload.query)


@router.post("/anyrun")
async def analyze_anyrun(
    payload: HashLookupRequest,
    current_user=Depends(get_current_user),
):
    hash_value = payload.hash.strip()
    if not hash_value:
        raise HTTPException(status_code=400, detail="Hash is required")

    result = _check_anyrun(hash_value)
    return {
        "tool": "ANY.RUN",
        "query": hash_value,
        "result": result,
    }