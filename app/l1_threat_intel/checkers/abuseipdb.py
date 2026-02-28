"""AbuseIPDB checker for suspicious IPs."""

import logging

import httpx

from app.config import settings
from app.schemas import CheckerResult

logger = logging.getLogger(__name__)

_API_URL = "https://api.abuseipdb.com/api/v2/check"


async def check_ip(ip: str) -> CheckerResult:
    """Check an IP address against AbuseIPDB."""
    if not settings.abuseipdb_api_key:
        return CheckerResult(source="abuseipdb", detail="API key not configured")

    headers = {
        "Key": settings.abuseipdb_api_key,
        "Accept": "application/json",
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(_API_URL, headers=headers, params=params)
            resp.raise_for_status()
            data = resp.json().get("data", {})

            abuse_score = data.get("abuseConfidenceScore", 0)
            is_bad = abuse_score >= 50  # 50%+ confidence = malicious

            return CheckerResult(
                source="abuseipdb",
                is_malicious=is_bad,
                detail=f"abuse_score={abuse_score}%, reports={data.get('totalReports', 0)}",
            )
    except Exception as e:
        logger.warning("AbuseIPDB error for %s: %s", ip, e)
        return CheckerResult(source="abuseipdb", detail=f"Error: {e}")

