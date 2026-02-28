"""Local blacklist for L1 Threat Intel — catches domains not yet in public feeds.

For demo: contains test domains. In production: populated from operator decisions,
incident response, and internal threat intel feeds.
"""

import logging
from urllib.parse import urlparse

from app.schemas import CheckerResult

logger = logging.getLogger(__name__)

# Blacklisted domains (exact match or suffix match)

BLACKLISTED_DOMAINS = {
    # Demo / bombardier L1 test domains ONLY
    # Grey-zone, QR-phishing, and uncertain domains must NOT be here —
    # they need to pass L1 and reach L2/L3 for proper testing.
    "acc0unt-verify.xyz",
    "secure-banking-login.tk",
    "phishing-login-secure.gq",
    "paypa1-security.ml",
    "microsofit-365.cf",
    "amazon-refund-claim.ga",
    "googl3-drive-share.work",
    "apple-id-locked.buzz",
    "chase-online-alert.click",
    "dropbox-verify-now.top",
}

# Suspicious TLD patterns (high risk for phishing in general)
SUSPICIOUS_TLDS = {".tk", ".xyz", ".top", ".buzz", ".gq", ".ml", ".cf", ".ga", ".work", ".click"}


def _extract_domain(url: str) -> str:
    """Extract domain from URL."""
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        return parsed.hostname or url
    except Exception:
        return url


async def check_url(url: str) -> CheckerResult:
    """Check URL against local blacklist."""
    domain = _extract_domain(url)
    return await check_domain(domain, detail_prefix=f"URL {url}")


async def check_domain(domain: str, detail_prefix: str = "") -> CheckerResult:
    """Check domain against local blacklist."""
    domain_lower = domain.lower().strip()

    # Exact match
    if domain_lower in BLACKLISTED_DOMAINS:
        logger.info("LOCAL BLACKLIST HIT: %s", domain_lower)
        return CheckerResult(
            source="local_blacklist",
            is_malicious=True,
            detail=f"{detail_prefix or domain_lower}: found in local blacklist",
        )

    # Suffix match (subdomains)
    for bd in BLACKLISTED_DOMAINS:
        if domain_lower.endswith("." + bd):
            logger.info("LOCAL BLACKLIST HIT (subdomain): %s → %s", domain_lower, bd)
            return CheckerResult(
                source="local_blacklist",
                is_malicious=True,
                detail=f"{detail_prefix or domain_lower}: subdomain of blacklisted {bd}",
            )

    return CheckerResult(
        source="local_blacklist",
        is_malicious=False,
        detail=f"{detail_prefix or domain_lower}: not in local blacklist",
    )

