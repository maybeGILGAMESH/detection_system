"""DOM analysis — delegates to screenshot.capture_and_analyze for single-visit efficiency.

Kept as a separate module for backward compatibility with imports.
"""

import logging

from app.schemas import DOMAnalysis
from app.l3_evidence.screenshot import capture_and_analyze

logger = logging.getLogger(__name__)


async def analyze(url: str, timeout_ms: int = 15000) -> DOMAnalysis:
    """Analyze the DOM structure of a page for phishing indicators."""
    _, _, dom = await capture_and_analyze(url, timeout_ms)
    return dom
