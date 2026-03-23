import os
import requests
from dotenv import load_dotenv
import base64

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ANYRUN_API_KEY = os.getenv("ANYRUN_API_KEY")


def vt_url_id(url: str) -> str:
    url_bytes = url.encode("utf-8")
    return base64.urlsafe_b64encode(url_bytes).decode().strip("=")


def check_virustotal_url(url: str):
    if not VT_API_KEY:
        return {"error": "VT_API_KEY not found in .env"}

    try:
        url_id = vt_url_id(url)
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(endpoint, headers=headers, timeout=20)
        return response.json()
    except Exception as e:
        return {"error": f"VirusTotal failed: {str(e)}"}


def check_ip_abuse(ip: str):
    if not ABUSEIPDB_API_KEY:
        return {"error": "ABUSEIPDB_API_KEY not found in .env"}

    try:
        endpoint = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": True
        }
        response = requests.get(endpoint, headers=headers, params=params, timeout=20)
        return response.json()
    except Exception as e:
        return {"error": f"AbuseIPDB failed: {str(e)}"}


def check_anyrun(hash_value: str):
    if not ANYRUN_API_KEY:
        return {"error": "ANYRUN_API_KEY not found in .env"}

    try:
        endpoint = f"https://api.any.run/v1/analysis/{hash_value}"
        headers = {"Authorization": f"API-Key {ANYRUN_API_KEY}"}
        response = requests.get(endpoint, headers=headers, timeout=20)
        return response.json()
    except Exception as e:
        return {"error": f"ANY.RUN failed: {str(e)}"}