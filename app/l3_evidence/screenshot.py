"""Playwright-based page visit: screenshot, redirect chain, and DOM analysis.

Performs all browser-based evidence gathering in a single Chromium session
to avoid launching multiple browser instances for the same URL.
"""

import base64
import io
import logging
import re
from pathlib import Path
from urllib.parse import urlparse

from playwright.async_api import async_playwright, TimeoutError as PwTimeout

from app.schemas import DOMAnalysis

logger = logging.getLogger(__name__)

_DEBUG_DIR = Path("debug_screenshots")

_ERROR_INDICATORS = (
    "err_name_not_resolved",
    "err_connection_refused",
    "err_connection_timed_out",
    "err_internet_disconnected",
    "this site can",
    "is not available",
    "server not found",
    "dns_probe_finished",
    "about:neterror",
)


def _save_debug_screenshot(url: str, png_bytes: bytes) -> None:
    """Save a full-resolution PNG to disk for inspection."""
    try:
        _DEBUG_DIR.mkdir(exist_ok=True)
        safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", url)[:120]
        path = _DEBUG_DIR / f"{safe_name}.png"
        path.write_bytes(png_bytes)
        logger.info("Debug screenshot saved: %s (%d bytes)", path, len(png_bytes))
    except Exception as e:
        logger.debug("Could not save debug screenshot: %s", e)


def make_thumbnail_b64(png_bytes: bytes, max_width: int = 640, quality: int = 60) -> str:
    """Resize PNG to a JPEG thumbnail and return as base64.

    Keeps the full visual content in ~20-40 KB instead of the raw ~300 KB PNG,
    which is friendly for WebSocket transport to the dashboard.
    """
    try:
        from PIL import Image

        img = Image.open(io.BytesIO(png_bytes))
        if img.width > max_width:
            ratio = max_width / img.width
            img = img.resize((max_width, int(img.height * ratio)), Image.LANCZOS)
        buf = io.BytesIO()
        img.convert("RGB").save(buf, format="JPEG", quality=quality)
        return base64.b64encode(buf.getvalue()).decode()
    except Exception as e:
        logger.debug("Thumbnail creation failed, using raw PNG base64: %s", e)
        return base64.b64encode(png_bytes).decode()


async def _navigate(page, url: str, timeout_ms: int) -> bool:
    """Try networkidle first; fall back to load then domcontentloaded."""
    for strategy in ("networkidle", "load", "domcontentloaded"):
        try:
            await page.goto(url, wait_until=strategy, timeout=timeout_ms)
            return True
        except PwTimeout:
            logger.debug("goto(%s) timed out with wait_until=%s", url, strategy)
        except Exception as e:
            logger.debug("goto(%s) failed with wait_until=%s: %s", url, strategy, e)
    return False


async def _is_error_page(page) -> bool:
    """Heuristic check for browser error / DNS failure pages."""
    try:
        title = (await page.title()).lower()
        if any(ind in title for ind in _ERROR_INDICATORS):
            return True
        body_text = await page.evaluate(
            "document.body ? document.body.innerText.substring(0, 500).toLowerCase() : ''"
        )
        return any(ind in body_text for ind in _ERROR_INDICATORS)
    except Exception:
        return False


async def capture_and_analyze(
    url: str, timeout_ms: int = 15000
) -> tuple[str, list[str], DOMAnalysis]:
    """Navigate to URL once and collect screenshot, redirect chain, and DOM analysis.

    Returns:
        (screenshot_base64, redirect_chain, dom_analysis)

    The base64 screenshot returned is a JPEG thumbnail (640px wide, quality 60)
    suitable for WebSocket transport.  Full PNGs are saved to ./debug_screenshots/.
    """
    screenshot_b64 = ""
    redirect_chain: list[str] = []
    dom = DOMAnalysis()

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 720},
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                ),
            )
            page = await context.new_page()

            page.on("response", lambda resp: redirect_chain.append(resp.url))

            try:
                loaded = await _navigate(page, url, timeout_ms)

                if not loaded:
                    logger.warning("All navigation strategies failed for %s", url)

                await page.wait_for_timeout(3000)

                error_page = await _is_error_page(page)
                if error_page:
                    logger.warning("Error/blank page detected for %s", url)

                # Extra settling for pages that loaded successfully:
                # wait for network to go idle and give JS frameworks time to hydrate.
                if loaded and not error_page:
                    try:
                        await page.wait_for_load_state("networkidle", timeout=5000)
                    except Exception:
                        pass
                    await page.wait_for_timeout(1000)

                # Inject placeholder when the body is completely empty.
                is_blank = await page.evaluate(
                    "(document.body && document.body.children.length === 0) "
                    "|| !document.body"
                )
                if is_blank:
                    await page.evaluate("""
                        document.body.style.background = '#f8f8f8';
                        document.body.innerHTML =
                            '<div style="display:flex;align-items:center;'
                          + 'justify-content:center;height:100vh;color:#888;'
                          + 'font-family:sans-serif;font-size:24px">'
                          + 'Page did not render any content</div>';
                    """)

                png_bytes = await page.screenshot(full_page=False)

                _save_debug_screenshot(url, png_bytes)

                screenshot_b64 = make_thumbnail_b64(png_bytes)

                # --- DOM analysis ---
                dom.forms_count = await page.evaluate(
                    "document.querySelectorAll('form').length"
                )
                dom.has_password_field = await page.evaluate(
                    "document.querySelectorAll('input[type=password]').length > 0"
                )

                scripts = await page.evaluate("""
                    Array.from(document.querySelectorAll('script[src]'))
                         .map(s => s.src)
                         .filter(s => s.startsWith('http'))
                """)
                page_domain = urlparse(url).netloc
                dom.external_scripts = [
                    s for s in scripts if urlparse(s).netloc != page_domain
                ]

                links = await page.evaluate("""
                    Array.from(document.querySelectorAll('a[href]'))
                         .map(a => a.href)
                         .filter(h => h.startsWith('http'))
                """)
                dom.external_links = [
                    link for link in links if urlparse(link).netloc != page_domain
                ][:20]

                dom.iframes_count = await page.evaluate(
                    "document.querySelectorAll('iframe').length"
                )

            except Exception as e:
                logger.warning("Page navigation/analysis error for %s: %s", url, e)

            await browser.close()

    except Exception as e:
        logger.error("Playwright error for %s: %s", url, e)

    return screenshot_b64, redirect_chain, dom


async def capture(url: str, timeout_ms: int = 15000) -> tuple[str, list[str]]:
    """Legacy wrapper — returns (screenshot_base64, redirect_chain)."""
    screenshot_b64, redirect_chain, _ = await capture_and_analyze(url, timeout_ms)
    return screenshot_b64, redirect_chain
