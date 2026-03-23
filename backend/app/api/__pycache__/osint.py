from fastapi import APIRouter, Query
import requests
import socket
import whois
from datetime import datetime

router = APIRouter()

VT_API_KEY = "PASTE_YOUR_VT_API_KEY"

@router.get("/domain")
def analyze_domain(q: str = Query(...)):
    result = {
        "query": q,
        "type": "domain",
        "verdict": "unknown",
        "communityScore": 0,
        "riskScore": 0,
        "stats": {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0
        },
        "whois": {},
        "dns": {},
        "ssl": {},
        "intel": {}
    }

    # ---------------- VIRUSTOTAL ----------------
    try:
        vt_url = f"https://www.virustotal.com/api/v3/domains/{q}"
        headers = {"x-apikey": VT_API_KEY}
        vt = requests.get(vt_url, headers=headers).json()

        stats = vt["data"]["attributes"]["last_analysis_stats"]

        result["stats"] = stats

        result["communityScore"] = stats["harmless"]
        result["riskScore"] = stats["malicious"] * 10 + stats["suspicious"] * 5

        if stats["malicious"] > 0:
            result["verdict"] = "malicious"
        elif stats["suspicious"] > 0:
            result["verdict"] = "suspicious"
        else:
            result["verdict"] = "clean"

    except Exception as e:
        print("VT error:", e)

    # ---------------- DNS ----------------
    try:
        ip = socket.gethostbyname(q)
        result["resolvedIp"] = ip
        result["dns"]["a"] = [ip]
    except:
        pass

    # ---------------- WHOIS ----------------
    try:
        w = whois.whois(q)
        result["whois"] = {
            "registrar": w.registrar,
            "created": str(w.creation_date),
            "expires": str(w.expiration_date)
        }
    except:
        pass

    return result