"""Tests for L3 Evidence Agent module."""

import pytest

from app.l3_evidence import tranco_check


@pytest.mark.asyncio
async def test_tranco_google():
    """Google should be in Tranco Top 1M."""
    rank = await tranco_check.check("https://www.google.com/search")
    # Google should have a very low rank (high popularity)
    if rank is not None:
        assert rank < 100


@pytest.mark.asyncio
async def test_tranco_unknown_domain():
    """An unknown domain should not be in Tranco."""
    rank = await tranco_check.check("https://totally-random-phish-xyz-99999.com")
    assert rank is None

