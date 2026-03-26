"""Tests for the gateway cascade (L1 -> L2 -> L3) with mocked services."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from app.schemas import (
    ParsedEmail, Verdict, Label,
    L1Result, L2Result, CheckerResult, JudgeVerdict,
)
from app.gateway.router import process_email


def _make_email(**kwargs) -> ParsedEmail:
    defaults = dict(
        sender="sender@example.com",
        recipient="user@example.com",
        subject="Test",
        body="Hello world",
        urls=["https://example.com"],
    )
    defaults.update(kwargs)
    return ParsedEmail(**defaults)


@pytest.fixture(autouse=True)
def _enable_all_layers():
    """Ensure all layers are enabled for each test."""
    from app.layer_toggle import layer_state
    layer_state["L1"] = True
    layer_state["L2"] = True
    layer_state["L3"] = True
    yield
    layer_state["L1"] = True
    layer_state["L2"] = True
    layer_state["L3"] = True


@pytest.mark.asyncio
@patch("app.gateway.router.events.publish", new_callable=AsyncMock)
@patch("app.gateway.router.l1_service.check", new_callable=AsyncMock)
async def test_l1_reject(mock_l1, mock_events):
    """L1 detects malicious URL -> immediate REJECT."""
    mock_l1.return_value = L1Result(
        verdict=Verdict.REJECT,
        results=[CheckerResult(source="local_blacklist", is_malicious=True, detail="Blacklisted")],
    )

    result = await process_email(_make_email())
    assert result.action == Verdict.REJECT
    assert result.l1_result is not None
    assert result.l1_result.verdict == Verdict.REJECT


@pytest.mark.asyncio
@patch("app.gateway.router._summarize_for_inbox", new_callable=AsyncMock)
@patch("app.gateway.router.events.publish", new_callable=AsyncMock)
@patch("app.gateway.router.l2_service.classify", new_callable=AsyncMock)
@patch("app.gateway.router.l1_service.check", new_callable=AsyncMock)
async def test_l1_proceed_l2_safe(mock_l1, mock_l2, mock_events, mock_inbox):
    """L1 clean, L2 high confidence safe -> DELIVER."""
    mock_l1.return_value = L1Result(verdict=Verdict.PROCEED, results=[])
    mock_l2.return_value = L2Result(confidence=0.95, label=Label.SAFE)

    result = await process_email(_make_email())
    assert result.action == Verdict.DELIVER
    assert result.l2_result is not None
    assert result.l2_result.confidence == 0.95


@pytest.mark.asyncio
@patch("app.gateway.router.events.publish", new_callable=AsyncMock)
@patch("app.gateway.router.l2_service.classify", new_callable=AsyncMock)
@patch("app.gateway.router.l1_service.check", new_callable=AsyncMock)
async def test_l1_proceed_l2_phishing(mock_l1, mock_l2, mock_events):
    """L1 clean, L2 low confidence (phishing) -> REJECT."""
    mock_l1.return_value = L1Result(verdict=Verdict.PROCEED, results=[])
    mock_l2.return_value = L2Result(confidence=0.1, label=Label.PHISHING)

    result = await process_email(_make_email())
    assert result.action == Verdict.REJECT


@pytest.mark.asyncio
@patch("app.gateway.router._summarize_for_inbox", new_callable=AsyncMock)
@patch("app.gateway.router.events.publish", new_callable=AsyncMock)
@patch("app.gateway.router.run_investigation", new_callable=AsyncMock)
@patch("app.gateway.router.l2_service.classify", new_callable=AsyncMock)
@patch("app.gateway.router.l1_service.check", new_callable=AsyncMock)
async def test_grey_zone_l3_release(mock_l1, mock_l2, mock_l3, mock_events, mock_inbox):
    """L2 grey zone -> L3 judge says safe -> RELEASE."""
    from app.l3_orchestrator.state import InvestigationState

    mock_l1.return_value = L1Result(verdict=Verdict.PROCEED, results=[])
    mock_l2.return_value = L2Result(confidence=0.55, label=Label.SAFE)

    state = InvestigationState(email=_make_email())
    state.verdict = JudgeVerdict(
        verdict=Label.SAFE, confidence=0.9, reasoning="Safe email",
        recommended_action=Verdict.RELEASE,
    )
    state.action = Verdict.RELEASE
    mock_l3.return_value = state

    result = await process_email(_make_email())
    assert result.action == Verdict.RELEASE


@pytest.mark.asyncio
@patch("app.gateway.router.events.publish", new_callable=AsyncMock)
@patch("app.gateway.router.run_investigation", new_callable=AsyncMock)
@patch("app.gateway.router.l2_service.classify", new_callable=AsyncMock)
@patch("app.gateway.router.l1_service.check", new_callable=AsyncMock)
async def test_grey_zone_l3_operator_review(mock_l1, mock_l2, mock_l3, mock_events):
    """L2 grey zone -> L3 uncertain -> OPERATOR_REVIEW."""
    from app.l3_orchestrator.state import InvestigationState

    mock_l1.return_value = L1Result(verdict=Verdict.PROCEED, results=[])
    mock_l2.return_value = L2Result(confidence=0.55, label=Label.SAFE)

    state = InvestigationState(email=_make_email())
    state.verdict = JudgeVerdict(
        verdict=Label.UNCERTAIN, confidence=0.5, reasoning="Can't tell",
        recommended_action=Verdict.OPERATOR_REVIEW,
    )
    state.action = Verdict.OPERATOR_REVIEW
    mock_l3.return_value = state

    with patch("app.gateway.router.operator_store.add_pending"):
        result = await process_email(_make_email())
    assert result.action == Verdict.OPERATOR_REVIEW


@pytest.mark.asyncio
@patch("app.gateway.router._summarize_for_inbox", new_callable=AsyncMock)
@patch("app.gateway.router.events.publish", new_callable=AsyncMock)
async def test_all_layers_disabled_delivers(mock_events, mock_inbox):
    """All layers disabled -> DELIVER (passthrough)."""
    from app.layer_toggle import layer_state
    layer_state["L1"] = False
    layer_state["L2"] = False
    layer_state["L3"] = False

    result = await process_email(_make_email())
    assert result.action == Verdict.DELIVER
    assert "disabled" in result.detail.lower() or "no analysis" in result.detail.lower()
