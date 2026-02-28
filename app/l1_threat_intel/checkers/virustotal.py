"""VirusTotal URL/domain checker using API v3."""

import base64
import logging

import httpx

from app.config import settings
from app.schemas import CheckerResult

logger = logging.getLogger(__name__)

_VT_URL = "https://www.virustotal.com/api/v3"


async def check_url(url: str) -> CheckerResult:
    """Check a URL against VirusTotal."""
    if not settings.virustotal_api_key:
        return CheckerResult(source="virustotal", detail="API key not configured")

    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    headers = {"x-apikey": settings.virustotal_api_key}

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"{_VT_URL}/urls/{url_id}", headers=headers)

            if resp.status_code == 404:
                return CheckerResult(source="virustotal", detail="URL not found in VT database")

            resp.raise_for_status()
            data = resp.json()

            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            is_bad = (malicious + suspicious) > 0
            return CheckerResult(
                source="virustotal",
                is_malicious=is_bad,
                detail=f"malicious={malicious}, suspicious={suspicious}",
            )
    except httpx.HTTPStatusError as e:
        logger.warning("VirusTotal HTTP error: %s", e)
        return CheckerResult(source="virustotal", detail=f"HTTP error: {e.response.status_code}")
    except Exception as e:
        logger.warning("VirusTotal error: %s", e)
        return CheckerResult(source="virustotal", detail=f"Error: {e}")


async def check_domain(domain: str) -> CheckerResult:
    """Check a domain against VirusTotal."""
    if not settings.virustotal_api_key:
        return CheckerResult(source="virustotal", detail="API key not configured")

    headers = {"x-apikey": settings.virustotal_api_key}

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"{_VT_URL}/domains/{domain}", headers=headers)

            if resp.status_code == 404:
                return CheckerResult(source="virustotal", detail="Domain not found")

            resp.raise_for_status()
            data = resp.json()

            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            is_bad = (malicious + suspicious) > 0
            return CheckerResult(
                source="virustotal",
                is_malicious=is_bad,
                detail=f"domain malicious={malicious}, suspicious={suspicious}",
            )
    except Exception as e:
        logger.warning("VirusTotal domain error: %s", e)
        return CheckerResult(source="virustotal", detail=f"Error: {e}")

