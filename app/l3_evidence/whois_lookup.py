"""WHOIS domain lookup."""

import asyncio
import logging
from datetime import datetime, timezone

from app.schemas import WHOISInfo
from app.utils import extract_domain

logger = logging.getLogger(__name__)


def _lookup_sync(domain: str) -> WHOISInfo:
    """Blocking WHOIS lookup — meant to be called via asyncio.to_thread."""
    info = WHOISInfo()
    try:
        import whois

        w = whois.whois(domain)

        info.registrar = str(w.registrar or "")

        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            info.creation_date = str(creation)
            if isinstance(creation, datetime):
                age = (datetime.now(timezone.utc) - creation.replace(tzinfo=timezone.utc)).days
                info.domain_age_days = max(age, 0)

        expiration = w.expiration_date
        if isinstance(expiration, list):
            expiration = expiration[0]
        if expiration:
            info.expiration_date = str(expiration)

        info.country = str(w.country or "")

    except Exception as e:
        logger.warning("WHOIS lookup failed for %s: %s", domain, e)

    return info


async def lookup(url: str) -> WHOISInfo:
    """Perform WHOIS lookup for the domain of a URL (non-blocking)."""
    domain = extract_domain(url)
    return await asyncio.to_thread(_lookup_sync, domain)
