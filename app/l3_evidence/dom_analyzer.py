"""Playwright-based DOM analysis: forms, password fields, scripts, links, iframes."""

import logging
from urllib.parse import urlparse

from playwright.async_api import async_playwright

from app.schemas import DOMAnalysis

logger = logging.getLogger(__name__)


async def analyze(url: str, timeout_ms: int = 15000) -> DOMAnalysis:
    """Analyze the DOM structure of a page for phishing indicators."""
    result = DOMAnalysis()

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            )
            page = await context.new_page()

            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                await page.wait_for_timeout(1500)

                # Count forms
                result.forms_count = await page.evaluate("document.querySelectorAll('form').length")

                # Check for password fields
                result.has_password_field = await page.evaluate(
                    "document.querySelectorAll('input[type=password]').length > 0"
                )

                # External scripts
                scripts = await page.evaluate("""
                    Array.from(document.querySelectorAll('script[src]'))
                         .map(s => s.src)
                         .filter(s => s.startsWith('http'))
                """)
                page_domain = urlparse(url).netloc
                result.external_scripts = [
                    s for s in scripts if urlparse(s).netloc != page_domain
                ]

                # External links
                links = await page.evaluate("""
                    Array.from(document.querySelectorAll('a[href]'))
                         .map(a => a.href)
                         .filter(h => h.startsWith('http'))
                """)
                result.external_links = [
                    l for l in links if urlparse(l).netloc != page_domain
                ][:20]  # Limit

                # Iframes
                result.iframes_count = await page.evaluate(
                    "document.querySelectorAll('iframe').length"
                )

            except Exception as e:
                logger.warning("DOM analysis navigation error for %s: %s", url, e)

            await browser.close()

    except Exception as e:
        logger.error("DOM analyzer error for %s: %s", url, e)

    return result

