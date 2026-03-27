"""Tests for l3_evidence modules with mocked external dependencies."""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio

from app.schemas import SSLInfo, WHOISInfo, DOMAnalysis, EvidenceBundle, ParsedEmail


# --- ssl_checker.py ---

def test_ssl_check_sync_success():
    from app.l3_evidence.ssl_checker import _check_sync

    mock_cert = {
        "issuer": ((("organizationName", "Let's Encrypt"),),),
        "subject": ((("commonName", "example.com"),),),
        "notBefore": "Jan  1 00:00:00 2024 GMT",
        "notAfter": "Dec 31 23:59:59 2030 GMT",
    }

    mock_ssock = MagicMock()
    mock_ssock.getpeercert.return_value = mock_cert
    mock_ssock.__enter__ = MagicMock(return_value=mock_ssock)
    mock_ssock.__exit__ = MagicMock(return_value=False)

    mock_sock = MagicMock()
    mock_sock.__enter__ = MagicMock(return_value=mock_sock)
    mock_sock.__exit__ = MagicMock(return_value=False)

    with patch("app.l3_evidence.ssl_checker.socket.create_connection", return_value=mock_sock), \
         patch("app.l3_evidence.ssl_checker.ssl.create_default_context") as mock_ctx:
        mock_ctx.return_value.wrap_socket.return_value = mock_ssock
        mock_ctx.return_value.wrap_socket.return_value.__enter__ = MagicMock(return_value=mock_ssock)
        mock_ctx.return_value.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)

        result = _check_sync("example.com")

    assert isinstance(result, SSLInfo)
    assert result.issuer == "Let's Encrypt"
    assert result.is_valid is True


def test_ssl_check_sync_verification_error():
    import ssl as ssl_mod
    from app.l3_evidence.ssl_checker import _check_sync

    with patch("app.l3_evidence.ssl_checker.socket.create_connection",
               side_effect=ssl_mod.SSLCertVerificationError("bad cert")):
        result = _check_sync("bad.com")

    assert isinstance(result, SSLInfo)
    assert result.is_valid is False


def test_ssl_check_sync_connection_error():
    from app.l3_evidence.ssl_checker import _check_sync

    with patch("app.l3_evidence.ssl_checker.socket.create_connection",
               side_effect=ConnectionRefusedError("refused")):
        result = _check_sync("nossl.com")

    assert isinstance(result, SSLInfo)


@pytest.mark.asyncio
async def test_ssl_check_async():
    from app.l3_evidence import ssl_checker

    with patch.object(ssl_checker, "_check_sync", return_value=SSLInfo(issuer="Test CA")):
        result = await ssl_checker.check("https://example.com")

    assert result.issuer == "Test CA"


# --- whois_lookup.py ---

def test_whois_lookup_sync_success():
    from app.l3_evidence.whois_lookup import _lookup_sync
    from datetime import datetime, timezone

    mock_whois = MagicMock()
    mock_whois.registrar = "GoDaddy"
    mock_whois.creation_date = datetime(2020, 1, 1, tzinfo=timezone.utc)
    mock_whois.expiration_date = datetime(2025, 1, 1)
    mock_whois.country = "US"

    with patch.dict("sys.modules", {"whois": MagicMock()}):
        import sys
        sys.modules["whois"].whois.return_value = mock_whois
        result = _lookup_sync("example.com")

    assert isinstance(result, WHOISInfo)
    assert result.registrar == "GoDaddy"
    assert result.domain_age_days > 0
    assert result.country == "US"


def test_whois_lookup_sync_list_dates():
    from app.l3_evidence.whois_lookup import _lookup_sync
    from datetime import datetime, timezone

    mock_whois = MagicMock()
    mock_whois.registrar = "Namecheap"
    mock_whois.creation_date = [datetime(2019, 6, 1, tzinfo=timezone.utc), datetime(2019, 6, 1)]
    mock_whois.expiration_date = [datetime(2026, 6, 1)]
    mock_whois.country = "UK"

    with patch.dict("sys.modules", {"whois": MagicMock()}):
        import sys
        sys.modules["whois"].whois.return_value = mock_whois
        result = _lookup_sync("example.co.uk")

    assert result.registrar == "Namecheap"


def test_whois_lookup_sync_error():
    from app.l3_evidence.whois_lookup import _lookup_sync

    with patch.dict("sys.modules", {"whois": MagicMock()}):
        import sys
        sys.modules["whois"].whois.side_effect = Exception("WHOIS timeout")
        result = _lookup_sync("bad-domain.xyz")

    assert isinstance(result, WHOISInfo)
    assert result.registrar == ""


@pytest.mark.asyncio
async def test_whois_lookup_async():
    from app.l3_evidence import whois_lookup

    with patch.object(whois_lookup, "_lookup_sync",
                      return_value=WHOISInfo(registrar="TestReg", country="DE")):
        result = await whois_lookup.lookup("https://example.de")

    assert result.registrar == "TestReg"


# --- qr_scanner.py ---

def test_scan_image_bytes_no_deps():
    from app.l3_evidence import qr_scanner

    original = qr_scanner._HAS_DEPS
    qr_scanner._HAS_DEPS = False
    result = qr_scanner.scan_image_bytes(b"fake image data")
    assert result == []
    qr_scanner._HAS_DEPS = original


def test_scan_html_for_qr_empty():
    from app.l3_evidence.qr_scanner import scan_html_for_qr
    assert scan_html_for_qr("") == []
    assert scan_html_for_qr("<html><body>no images</body></html>") == []


def test_extract_qr_urls_no_html():
    from app.l3_evidence.qr_scanner import extract_qr_urls
    email = ParsedEmail(sender="a@b.com", body="text only")
    assert extract_qr_urls(email) == []


def test_extract_qr_urls_with_html():
    from app.l3_evidence.qr_scanner import extract_qr_urls

    with patch("app.l3_evidence.qr_scanner.scan_html_for_qr",
               return_value=["https://phish.com", "https://phish.com"]):
        email = ParsedEmail(
            sender="a@b.com",
            body="Scan this",
            html_body='<img src="data:image/png;base64,AAAA">',
        )
        result = extract_qr_urls(email)

    assert "https://phish.com" in result
    assert len(result) == 1  # deduped


def test_scan_image_bytes_with_mock_deps():
    from app.l3_evidence import qr_scanner

    original = qr_scanner._HAS_DEPS
    qr_scanner._HAS_DEPS = True

    mock_sym = MagicMock()
    mock_sym.data = b"https://evil.com/phish"

    with patch("app.l3_evidence.qr_scanner.Image") as mock_pil, \
         patch("app.l3_evidence.qr_scanner.zbar_decode", return_value=[mock_sym]):
        mock_pil.open.return_value = MagicMock()
        result = qr_scanner.scan_image_bytes(b"fake png")

    assert "https://evil.com/phish" in result
    qr_scanner._HAS_DEPS = original


def test_scan_image_bytes_non_url_qr():
    from app.l3_evidence import qr_scanner

    original = qr_scanner._HAS_DEPS
    qr_scanner._HAS_DEPS = True

    mock_sym = MagicMock()
    mock_sym.data = b"Visit https://example.com/page for details"

    with patch("app.l3_evidence.qr_scanner.Image") as mock_pil, \
         patch("app.l3_evidence.qr_scanner.zbar_decode", return_value=[mock_sym]):
        mock_pil.open.return_value = MagicMock()
        result = qr_scanner.scan_image_bytes(b"fake")

    assert "https://example.com/page" in result
    qr_scanner._HAS_DEPS = original


def test_scan_image_bytes_decode_error():
    from app.l3_evidence import qr_scanner

    original = qr_scanner._HAS_DEPS
    qr_scanner._HAS_DEPS = True

    with patch("app.l3_evidence.qr_scanner.Image") as mock_pil:
        mock_pil.open.side_effect = Exception("Bad image")
        result = qr_scanner.scan_image_bytes(b"garbage")

    assert result == []
    qr_scanner._HAS_DEPS = original


# --- dom_analyzer.py ---

@pytest.mark.asyncio
async def test_dom_analyze():
    from app.l3_evidence import dom_analyzer

    dom = DOMAnalysis(forms_count=3, has_password_field=True, iframes_count=1)
    with patch("app.l3_evidence.dom_analyzer.capture_and_analyze",
               new_callable=AsyncMock,
               return_value=("b64img", ["url1"], dom)):
        result = await dom_analyzer.analyze("https://example.com")

    assert result.forms_count == 3
    assert result.has_password_field is True


# --- screenshot.py ---

def test_save_debug_screenshot(tmp_path):
    from app.l3_evidence.screenshot import _save_debug_screenshot

    with patch("app.l3_evidence.screenshot._DEBUG_DIR", tmp_path):
        _save_debug_screenshot("https://example.com/page", b"\x89PNG fake")

    files = list(tmp_path.iterdir())
    assert len(files) == 1


def test_make_thumbnail_b64_fallback():
    """When PIL raises, falls back to raw base64 encoding."""
    from app.l3_evidence.screenshot import make_thumbnail_b64

    mock_image_mod = MagicMock()
    mock_image_mod.open.side_effect = Exception("corrupt image")

    with patch.dict("sys.modules", {"PIL.Image": mock_image_mod, "PIL": MagicMock()}):
        result = make_thumbnail_b64(b"\x89PNG fake data")

    assert isinstance(result, str)
    assert len(result) > 0


def test_make_thumbnail_b64_resize():
    """Test thumbnail creation with a valid mock image."""
    from app.l3_evidence.screenshot import make_thumbnail_b64
    import io

    mock_img = MagicMock()
    mock_img.width = 1280
    mock_img.height = 720
    mock_resized = MagicMock()
    mock_img.resize.return_value = mock_resized
    mock_rgb = MagicMock()
    mock_resized.convert.return_value = mock_rgb
    mock_rgb.save = MagicMock(side_effect=lambda b, **kw: b.write(b"jpegdata"))

    mock_image_mod = MagicMock()
    mock_image_mod.open.return_value = mock_img
    mock_image_mod.LANCZOS = 1

    with patch.dict("sys.modules", {"PIL.Image": mock_image_mod, "PIL": MagicMock()}):
        from importlib import reload
        result = make_thumbnail_b64(b"png bytes")

    assert isinstance(result, str)


@pytest.mark.asyncio
async def test_capture_and_analyze_playwright_error():
    from app.l3_evidence.screenshot import capture_and_analyze

    with patch("app.l3_evidence.screenshot.async_playwright") as mock_pw:
        mock_pw.return_value.__aenter__ = AsyncMock(side_effect=Exception("No browser"))
        mock_pw.return_value.__aexit__ = AsyncMock()

        b64, chain, dom = await capture_and_analyze("https://example.com")

    assert b64 == ""
    assert chain == []


@pytest.mark.asyncio
async def test_is_error_page():
    from app.l3_evidence.screenshot import _is_error_page

    mock_page = MagicMock()
    mock_page.title = AsyncMock(return_value="ERR_NAME_NOT_RESOLVED")
    assert await _is_error_page(mock_page) is True


@pytest.mark.asyncio
async def test_is_error_page_clean():
    from app.l3_evidence.screenshot import _is_error_page

    mock_page = MagicMock()
    mock_page.title = AsyncMock(return_value="Google")
    mock_page.evaluate = AsyncMock(return_value="welcome to our site")
    assert await _is_error_page(mock_page) is False


@pytest.mark.asyncio
async def test_is_error_page_exception():
    from app.l3_evidence.screenshot import _is_error_page

    mock_page = MagicMock()
    mock_page.title = AsyncMock(side_effect=Exception("detached"))
    assert await _is_error_page(mock_page) is False


# --- service.py (evidence orchestration) ---

@pytest.mark.asyncio
async def test_investigate_url_success():
    from app.l3_evidence.service import investigate_url

    mock_pw = ("b64screenshot", ["https://redirect.com"], DOMAnalysis(forms_count=1))

    with patch("app.l3_evidence.service.screenshot.capture_and_analyze",
               new_callable=AsyncMock, return_value=mock_pw), \
         patch("app.l3_evidence.service.whois_lookup.lookup",
               new_callable=AsyncMock, return_value=WHOISInfo(registrar="Test")), \
         patch("app.l3_evidence.service.ssl_checker.check",
               new_callable=AsyncMock, return_value=SSLInfo(issuer="CA")), \
         patch("app.l3_evidence.service.tranco_check.check",
               new_callable=AsyncMock, return_value=5000):

        bundle = await investigate_url("https://example.com")

    assert isinstance(bundle, EvidenceBundle)
    assert bundle.screenshot_base64 == "b64screenshot"
    assert bundle.whois.registrar == "Test"
    assert bundle.tranco_rank == 5000


@pytest.mark.asyncio
async def test_investigate_url_timeout():
    from app.l3_evidence.service import investigate_url

    async def slow(*a, **kw):
        await asyncio.sleep(100)

    with patch("app.l3_evidence.service.screenshot.capture_and_analyze",
               new_callable=AsyncMock, side_effect=slow), \
         patch("app.l3_evidence.service.whois_lookup.lookup",
               new_callable=AsyncMock, side_effect=slow), \
         patch("app.l3_evidence.service.ssl_checker.check",
               new_callable=AsyncMock, side_effect=slow), \
         patch("app.l3_evidence.service.tranco_check.check",
               new_callable=AsyncMock, side_effect=slow), \
         patch("app.l3_evidence.service.EVIDENCE_TIMEOUT", 0.01):

        bundle = await investigate_url("https://example.com")

    assert "Timed out" in bundle.error


@pytest.mark.asyncio
async def test_investigate_url_exception():
    from app.l3_evidence.service import investigate_url

    with patch("app.l3_evidence.service.screenshot.capture_and_analyze",
               new_callable=AsyncMock, side_effect=RuntimeError("crash")), \
         patch("app.l3_evidence.service.whois_lookup.lookup",
               new_callable=AsyncMock, side_effect=RuntimeError("crash")), \
         patch("app.l3_evidence.service.ssl_checker.check",
               new_callable=AsyncMock, side_effect=RuntimeError("crash")), \
         patch("app.l3_evidence.service.tranco_check.check",
               new_callable=AsyncMock, side_effect=RuntimeError("crash")):

        bundle = await investigate_url("https://example.com")

    assert isinstance(bundle, EvidenceBundle)


@pytest.mark.asyncio
async def test_investigate_urls_empty():
    from app.l3_evidence.service import investigate_urls
    result = await investigate_urls([])
    assert result == []


@pytest.mark.asyncio
async def test_investigate_urls_limit():
    from app.l3_evidence.service import investigate_urls

    with patch("app.l3_evidence.service.investigate_url",
               new_callable=AsyncMock,
               return_value=EvidenceBundle(url="x")):
        result = await investigate_urls(["u1", "u2", "u3", "u4", "u5"])

    assert len(result) == 3  # limited to 3
