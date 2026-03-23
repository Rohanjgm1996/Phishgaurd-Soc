"""
PhishGuard SOC - ClamAV Scanner
Submits file bytes to local ClamAV daemon via clamd socket.
If ClamAV is not running or disabled, returns a safe "skipped" result.
"""
import socket
import struct
from app.core.config import settings


def clamav_scan(file_bytes: bytes) -> dict:
    """
    Stream file bytes to ClamAV daemon (INSTREAM protocol).
    Returns triggered rules and verdict.
    """
    result = {
        "triggered_rules": [],
        "details": [],
        "verdict": "clean",
        "signature": None,
    }

    if not settings.CLAMAV_ENABLED:
        result["details"].append("ClamAV disabled in config — scan skipped")
        return result

    try:
        raw_result = _clamd_instream(
            file_bytes,
            host=settings.CLAMAV_HOST,
            port=settings.CLAMAV_PORT,
        )

        if raw_result.startswith("stream: OK"):
            result["verdict"] = "clean"
            result["details"].append("ClamAV: No threats detected")
        elif "FOUND" in raw_result:
            result["verdict"] = "infected"
            sig = raw_result.split("FOUND")[0].replace("stream:", "").strip()
            result["signature"] = sig
            result["triggered_rules"].append("clamav_hit")
            result["details"].append(f"ClamAV FOUND: {sig}")
        else:
            result["details"].append(f"ClamAV response: {raw_result}")

    except ConnectionRefusedError:
        result["details"].append(
            f"ClamAV daemon not reachable at {settings.CLAMAV_HOST}:{settings.CLAMAV_PORT} — scan skipped"
        )
    except Exception as e:
        result["details"].append(f"ClamAV scan error: {e}")

    return result


def _clamd_instream(data: bytes, host: str = "localhost", port: int = 3310) -> str:
    """
    Low-level INSTREAM scan via TCP socket.
    Sends data in chunks with 4-byte big-endian length prefix.
    """
    CHUNK_SIZE = 4096
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(30)
        sock.connect((host, port))
        sock.sendall(b"zINSTREAM\0")

        for i in range(0, len(data), CHUNK_SIZE):
            chunk = data[i : i + CHUNK_SIZE]
            size = struct.pack("!I", len(chunk))
            sock.sendall(size + chunk)

        # Send zero-length chunk to signal end of stream
        sock.sendall(struct.pack("!I", 0))

        response = b""
        while True:
            part = sock.recv(1024)
            if not part:
                break
            response += part
            if b"\0" in part:
                break

    return response.replace(b"\0", b"").decode("utf-8", errors="replace").strip()
