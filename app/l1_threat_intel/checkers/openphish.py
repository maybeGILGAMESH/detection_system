"""OpenPhish feed checker — downloads and caches the live feed."""

import logging
import time

import httpx

from app.schemas import CheckerResult

logger = logging.getLogger(__name__)

_FEED_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
_CACHE_TTL = 3600  # Refresh every hour

_cached_urls: set[str] = set()
_last_fetch: float = 0.0


async def _refresh_feed() -> None:
    """Download the OpenPhish feed if cache is stale."""
    global _cached_urls, _last_fetch

    if time.time() - _last_fetch < _CACHE_TTL and _cached_urls:
        return

    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            resp = await client.get(_FEED_URL)
            resp.raise_for_status()
            _cached_urls = {
                line.strip().lower()
                for line in resp.text.splitlines()
                if line.strip()
            }
            _last_fetch = time.time()
            logger.info("Refreshed OpenPhish feed: %d URLs", len(_cached_urls))
    except Exception as e:
        logger.warning("Failed to refresh OpenPhish feed: %s", e)


async def check_url(url: str) -> CheckerResult:
    """Check a URL against the OpenPhish live feed."""
    await _refresh_feed()
    normalized = url.lower().strip()
    is_found = normalized in _cached_urls

    return CheckerResult(
        source="openphish",
        is_malicious=is_found,
        detail="Found in OpenPhish feed" if is_found else "Not in OpenPhish feed",
    )

