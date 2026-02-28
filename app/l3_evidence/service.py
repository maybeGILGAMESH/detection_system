"""L3 Evidence Agent — gathers all evidence for a URL in parallel.

Includes timeouts to prevent hanging on unreachable domains.
"""

import asyncio
import logging

from app.schemas import EvidenceBundle
from app.l3_evidence import screenshot, dom_analyzer, whois_lookup, ssl_checker, tranco_check

logger = logging.getLogger(__name__)

# Timeout for entire evidence gathering per URL (seconds)
EVIDENCE_TIMEOUT = 25


async def investigate_url(url: str) -> EvidenceBundle:
    """Gather full evidence bundle for a single URL.

    Runs all tools in parallel, with a global timeout.
    """
    logger.info("L3 Evidence: investigating %s", url)

    try:
        # Run all evidence gathering in parallel with timeout
        results = await asyncio.wait_for(
            asyncio.gather(
                screenshot.capture(url),
                dom_analyzer.analyze(url),
                whois_lookup.lookup(url),
                ssl_checker.check(url),
                tranco_check.check(url),
                return_exceptions=True,
            ),
            timeout=EVIDENCE_TIMEOUT,
        )

        # Unpack results (handle exceptions gracefully)
        screenshot_result = results[0] if not isinstance(results[0], Exception) else ("", [])
        dom_result = results[1] if not isinstance(results[1], Exception) else None
        whois_result = results[2] if not isinstance(results[2], Exception) else None
        ssl_result = results[3] if not isinstance(results[3], Exception) else None
        tranco_result = results[4] if not isinstance(results[4], Exception) else None

        screenshot_b64, redirect_chain = screenshot_result

        bundle = EvidenceBundle(
            url=url,
            screenshot_base64=screenshot_b64,
            dom_analysis=dom_result,
            whois=whois_result,
            ssl=ssl_result,
            tranco_rank=tranco_result,
            redirect_chain=redirect_chain,
        )

        logger.info(
            "L3 Evidence gathered for %s: screenshot=%s, DOM=%s, WHOIS=%s, SSL=%s, tranco=%s",
            url,
            bool(screenshot_b64),
            dom_result is not None,
            whois_result is not None,
            ssl_result is not None,
            tranco_result,
        )
        return bundle

    except asyncio.TimeoutError:
        logger.warning("L3 Evidence timed out for %s after %ds", url, EVIDENCE_TIMEOUT)
        return EvidenceBundle(url=url, error=f"Timed out after {EVIDENCE_TIMEOUT}s")

    except Exception as e:
        logger.error("L3 Evidence failed for %s: %s", url, e)
        return EvidenceBundle(url=url, error=str(e))


async def investigate_urls(urls: list[str]) -> list[EvidenceBundle]:
    """Investigate multiple URLs (sequentially to avoid resource overload)."""
    if not urls:
        return []

    # Process URLs sequentially — each one already runs tools in parallel.
    # This avoids launching too many Playwright instances simultaneously.
    bundles = []
    for url in urls[:3]:  # Limit to 3 URLs
        bundle = await investigate_url(url)
        bundles.append(bundle)

    return bundles
