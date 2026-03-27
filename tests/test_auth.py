"""Tests for auth.py — API key authentication."""

import pytest
from unittest.mock import patch
from fastapi import HTTPException

from app.auth import require_operator_key


@pytest.mark.asyncio
async def test_auth_disabled_no_key():
    """When OPERATOR_API_KEY is empty, auth is bypassed."""
    with patch("app.auth.settings") as mock_settings:
        mock_settings.operator_api_key = ""
        result = await require_operator_key(api_key=None)
        assert result is None


@pytest.mark.asyncio
async def test_auth_disabled_any_key():
    """When OPERATOR_API_KEY is empty, any key is accepted."""
    with patch("app.auth.settings") as mock_settings:
        mock_settings.operator_api_key = ""
        result = await require_operator_key(api_key="anything")
        assert result is None


@pytest.mark.asyncio
async def test_auth_correct_key():
    """Correct key passes."""
    with patch("app.auth.settings") as mock_settings:
        mock_settings.operator_api_key = "secret123"
        result = await require_operator_key(api_key="secret123")
        assert result is None


@pytest.mark.asyncio
async def test_auth_wrong_key():
    """Wrong key raises 403."""
    with patch("app.auth.settings") as mock_settings:
        mock_settings.operator_api_key = "secret123"
        with pytest.raises(HTTPException) as exc:
            await require_operator_key(api_key="wrong")
        assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_auth_missing_key():
    """Missing key when auth is enabled raises 403."""
    with patch("app.auth.settings") as mock_settings:
        mock_settings.operator_api_key = "secret123"
        with pytest.raises(HTTPException) as exc:
            await require_operator_key(api_key=None)
        assert exc.value.status_code == 403
