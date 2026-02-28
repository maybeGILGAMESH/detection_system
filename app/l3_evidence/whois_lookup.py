"""WHOIS domain lookup."""

import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

from app.schemas import WHOISInfo

logger = logging.getLogger(__name__)


def _extract_domain(url: str) -> str:
    """Extract the registrable domain from a URL."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return parsed.netloc or parsed.path.split("/")[0]


async def lookup(url: str) -> WHOISInfo:
    """Perform WHOIS lookup for the domain of a URL."""
    domain = _extract_domain(url)
    info = WHOISInfo()

    try:
        import whois  # python-whois

        w = whois.whois(domain)

        info.registrar = str(w.registrar or "")

        # Creation date
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            info.creation_date = str(creation)
            if isinstance(creation, datetime):
                age = (datetime.now(timezone.utc) - creation.replace(tzinfo=timezone.utc)).days
                info.domain_age_days = max(age, 0)

        # Expiration date
        expiration = w.expiration_date
        if isinstance(expiration, list):
            expiration = expiration[0]
        if expiration:
            info.expiration_date = str(expiration)

        # Country
        info.country = str(w.country or "")

    except Exception as e:
        logger.warning("WHOIS lookup failed for %s: %s", domain, e)

    return info

