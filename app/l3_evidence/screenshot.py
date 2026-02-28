"""Playwright-based screenshot and redirect chain capture."""

import base64
import logging

from playwright.async_api import async_playwright

logger = logging.getLogger(__name__)


async def capture(url: str, timeout_ms: int = 15000) -> tuple[str, list[str]]:
    """Navigate to URL, take a screenshot, and record the redirect chain.

    Returns:
        (screenshot_base64, redirect_chain)
    """
    screenshot_b64 = ""
    redirect_chain: list[str] = []

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 720},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            )
            page = await context.new_page()

            # Track redirects
            page.on("response", lambda resp: redirect_chain.append(resp.url))

            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                await page.wait_for_timeout(2000)  # Let lazy-loaded content appear

                png_bytes = await page.screenshot(full_page=False)
                screenshot_b64 = base64.b64encode(png_bytes).decode()
            except Exception as e:
                logger.warning("Page navigation error for %s: %s", url, e)

            await browser.close()

    except Exception as e:
        logger.error("Playwright error for %s: %s", url, e)

    return screenshot_b64, redirect_chain

