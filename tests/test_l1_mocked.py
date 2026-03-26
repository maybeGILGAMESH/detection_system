"""Tests for L1 checkers with mocked HTTP responses."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from app.schemas import L1CheckRequest, Verdict


@pytest.mark.asyncio
@patch("app.l1_threat_intel.checkers.virustotal.get_client")
async def test_virustotal_malicious_url(mock_get_client):
    """VirusTotal flags malicious URL."""
    from app.l1_threat_intel.checkers import virustotal
    from app.l1_threat_intel.checkers import cache
    cache._store.clear()  # clear cache

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 1}}}
    }

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)
    mock_get_client.return_value = mock_client

    with patch.object(virustotal, "settings", MagicMock(virustotal_api_key="test-key")):
        result = await virustotal.check_url("http://evil.com/phish")
    assert result.is_malicious is True
    assert result.source == "virustotal"


@pytest.mark.asyncio
@patch("app.l1_threat_intel.checkers.virustotal.get_client")
async def test_virustotal_safe_url(mock_get_client):
    """VirusTotal reports clean URL."""
    from app.l1_threat_intel.checkers import virustotal
    from app.l1_threat_intel.checkers import cache
    cache._store.clear()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0}}}
    }

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)
    mock_get_client.return_value = mock_client

    with patch.object(virustotal, "settings", MagicMock(virustotal_api_key="test-key")):
        result = await virustotal.check_url("http://google.com")
    assert result.is_malicious is False


@pytest.mark.asyncio
@patch("app.l1_threat_intel.checkers.abuseipdb.get_client")
async def test_abuseipdb_high_score(mock_get_client):
    """AbuseIPDB reports high abuse score."""
    from app.l1_threat_intel.checkers import abuseipdb
    from app.l1_threat_intel.checkers import cache
    cache._store.clear()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {
        "data": {"abuseConfidenceScore": 85, "totalReports": 42}
    }

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)
    mock_get_client.return_value = mock_client

    with patch.object(abuseipdb, "settings", MagicMock(abuseipdb_api_key="test-key")):
        result = await abuseipdb.check_ip("1.2.3.4")
    assert result.is_malicious is True
    assert "85%" in result.detail


@pytest.mark.asyncio
async def test_virustotal_no_api_key():
    """VirusTotal gracefully handles missing API key."""
    from app.l1_threat_intel.checkers import virustotal

    with patch.object(virustotal, "settings", MagicMock(virustotal_api_key="")):
        result = await virustotal.check_url("http://example.com")
    assert result.is_malicious is False
    assert "not configured" in result.detail


@pytest.mark.asyncio
async def test_local_blacklist_hit():
    """Local blacklist correctly identifies known-bad domain."""
    from app.l1_threat_intel.local_blacklist import check_url

    result = await check_url("http://acc0unt-verify.xyz/login")
    assert result.is_malicious is True
    assert result.source == "local_blacklist"


@pytest.mark.asyncio
async def test_local_blacklist_miss():
    """Local blacklist passes clean domain."""
    from app.l1_threat_intel.local_blacklist import check_url

    result = await check_url("https://www.google.com")
    assert result.is_malicious is False
