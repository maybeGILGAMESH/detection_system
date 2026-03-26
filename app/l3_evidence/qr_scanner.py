"""QR code scanner — extracts URLs hidden inside QR code images in emails.

Scans HTML email bodies for embedded base64 images, decodes any QR codes
found, and returns the URLs they encode.  Uses pyzbar + Pillow.
"""

import base64
import io
import logging
import re
from urllib.parse import urlparse

from app.schemas import ParsedEmail

logger = logging.getLogger(__name__)

try:
    from PIL import Image
    from pyzbar.pyzbar import decode as zbar_decode, ZBarSymbol

    _HAS_DEPS = True
except ImportError:
    _HAS_DEPS = False
    logger.warning(
        "pyzbar or Pillow not installed — QR code scanning disabled. "
        "Install with: pip install Pillow pyzbar  (+ apt install libzbar0)"
    )

_DATA_URI_RE = re.compile(
    r'<img[^>]+src=["\']data:image/[^;]+;base64,([A-Za-z0-9+/=\s]+)["\']',
    re.IGNORECASE,
)

_URL_RE = re.compile(r"https?://[^\s<>\"']+")


def scan_image_bytes(data: bytes) -> list[str]:
    """Decode QR codes from raw image bytes, return any URLs found."""
    if not _HAS_DEPS:
        return []
    try:
        img = Image.open(io.BytesIO(data))
        results = zbar_decode(img, symbols=[ZBarSymbol.QRCODE])
        urls: list[str] = []
        for sym in results:
            text = sym.data.decode("utf-8", errors="ignore")
            parsed = urlparse(text)
            if parsed.scheme in ("http", "https"):
                urls.append(text)
            else:
                urls.extend(_URL_RE.findall(text))
        return urls
    except Exception as e:
        logger.debug("QR decode failed for image bytes: %s", e)
        return []


def scan_html_for_qr(html: str) -> list[str]:
    """Extract base64 images from HTML, decode QR codes, return URLs."""
    if not _HAS_DEPS or not html:
        return []

    urls: list[str] = []
    for match in _DATA_URI_RE.finditer(html):
        b64_data = match.group(1).replace("\n", "").replace("\r", "").replace(" ", "")
        try:
            image_bytes = base64.b64decode(b64_data)
            found = scan_image_bytes(image_bytes)
            urls.extend(found)
        except Exception as e:
            logger.debug("Failed to decode base64 image from HTML: %s", e)

    return urls


def extract_qr_urls(email: ParsedEmail) -> list[str]:
    """Scan email HTML body for QR codes and return all decoded URLs."""
    if not email.html_body:
        return []

    qr_urls = scan_html_for_qr(email.html_body)

    if qr_urls:
        logger.info(
            "QR scanner found %d URL(s) in email from %s: %s",
            len(qr_urls),
            email.sender,
            qr_urls,
        )

    return list(dict.fromkeys(qr_urls))
