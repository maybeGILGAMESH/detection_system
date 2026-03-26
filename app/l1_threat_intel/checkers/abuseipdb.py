"""AbuseIPDB checker for suspicious IPs."""

import logging

from app.config import settings
from app.schemas import CheckerResult
from app.l1_threat_intel.checkers.http_client import get_client
from app.l1_threat_intel.checkers import cache

logger = logging.getLogger(__name__)

_API_URL = "https://api.abuseipdb.com/api/v2/check"


async def check_ip(ip: str) -> CheckerResult:
    """Check an IP address against AbuseIPDB."""
    if not settings.abuseipdb_api_key:
        return CheckerResult(source="abuseipdb", detail="API key not configured")

    cached = cache.get(cache.make_key("abuseipdb", ip))
    if cached is not None:
        return cached

    headers = {
        "Key": settings.abuseipdb_api_key,
        "Accept": "application/json",
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        client = get_client()
        resp = await client.get(_API_URL, headers=headers, params=params)
        resp.raise_for_status()
        data = resp.json().get("data", {})

        abuse_score = data.get("abuseConfidenceScore", 0)
        is_bad = abuse_score >= 50

        result = CheckerResult(
            source="abuseipdb",
            is_malicious=is_bad,
            detail=f"abuse_score={abuse_score}%, reports={data.get('totalReports', 0)}",
        )
        cache.put(cache.make_key("abuseipdb", ip), result)
        return result
    except Exception as e:
        logger.warning("AbuseIPDB error for %s: %s", ip, e)
        return CheckerResult(source="abuseipdb", detail=f"Error: {e}")
