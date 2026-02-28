"""Tests for L1 Threat Intel module."""

import pytest

from app.schemas import L1CheckRequest, Verdict
from app.l1_threat_intel import service as l1_service
from app.l1_threat_intel.checkers import phishtank


@pytest.mark.asyncio
async def test_l1_empty_request():
    """L1 should PROCEED when no URLs/IPs/domains given."""
    result = await l1_service.check(L1CheckRequest())
    assert result.verdict == Verdict.PROCEED
    assert len(result.results) == 0


@pytest.mark.asyncio
async def test_l1_safe_url():
    """L1 should PROCEED for a non-malicious URL."""
    result = await l1_service.check(
        L1CheckRequest(urls=["https://www.google.com"])
    )
    # PhishTank and OpenPhish should not flag Google
    phishtank_results = [r for r in result.results if r.source == "phishtank"]
    for r in phishtank_results:
        assert r.is_malicious is False


@pytest.mark.asyncio
async def test_phishtank_checker_not_found():
    """PhishTank checker should return not malicious for unknown URL."""
    result = await phishtank.check_url("https://totally-safe-site-12345.com/page")
    assert result.is_malicious is False
    assert result.source == "phishtank"

