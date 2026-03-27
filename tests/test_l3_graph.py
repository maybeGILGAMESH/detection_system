"""Tests for l3_orchestrator/graph.py — full investigation pipeline."""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from app.schemas import (
    ParsedEmail, EvidenceBundle, JudgeVerdict, Label, Verdict, DOMAnalysis,
    WHOISInfo, SSLInfo,
)
from app.l3_orchestrator.state import InvestigationState
from app.l3_orchestrator.graph import (
    extract_urls, gather_evidence, judge_verdict, make_decision, run_investigation,
)


def _email(**kw):
    defaults = dict(sender="a@b.com", recipient="user@test.com",
                    subject="Test", body="Click https://evil.com", urls=["https://evil.com"])
    defaults.update(kw)
    return ParsedEmail(**defaults)


@pytest.mark.asyncio
@patch("app.l3_orchestrator.graph.events.publish", new_callable=AsyncMock)
async def test_extract_urls_from_email(mock_pub):
    state = InvestigationState(email=_email())
    result = await extract_urls(state, "eid1")
    assert "https://evil.com" in result.urls


@pytest.mark.asyncio
@patch("app.l3_orchestrator.graph.events.publish", new_callable=AsyncMock)
async def test_extract_urls_from_body(mock_pub):
    email = _email(body="Visit https://hidden.com now!", urls=[])
    state = InvestigationState(email=email)
    result = await extract_urls(state, "eid2")
    assert "https://hidden.com" in result.urls


@pytest.mark.asyncio
@patch("app.l3_orchestrator.graph.events.publish", new_callable=AsyncMock)
async def test_extract_urls_from_html(mock_pub):
    email = _email(html_body='<a href="https://html-url.com">click</a>', urls=[])
    state = InvestigationState(email=email)
    result = await extract_urls(state, "eid3")
    assert "https://html-url.com" in result.urls


@pytest.mark.asyncio
@patch("app.l3_orchestrator.graph.events.publish", new_callable=AsyncMock)
@patch("app.l3_orchestrator.graph.extract_qr_urls", return_value=["https://qr-phish.com"])
async def test_extract_urls_with_qr(mock_qr, mock_pub):
    state = InvestigationState(email=_email())
    result = await extract_urls(state, "eid4")
    assert "https://qr-phish.com" in result.urls
    assert "https://qr-phish.com" in result.qr_urls


@pytest.mark.asyncio
@patch("app.l3_orchestrator.graph.events.publish", new_callable=AsyncMock)
async def test_gather_evidence_no_urls(mock_pub):
    state = InvestigationState(email=_email())
    state.urls = []
    result = await gather_evidence(state, "eid5")
    assert result.evidence_bundles == []


@pytest.mark.asyncio
@patch("app.l3_orchestrator.graph.events.publish", new_callable=AsyncMock)
@patch("app.l3_orchestrator.graph.investigate_urls", new_callable=AsyncMock)
async def test_gather_evidence_success(mock_inv, mock_pub):
    bundle = EvidenceBundle(
        url="https://evil.com",
        screenshot_base64="abc",
        dom_analysis=DOMAnalysis(forms_count=2, has_password_field=True),
        whois=WHOISInfo(registrar="GoDaddy", domain_age_days=5, country="RU"),
        ssl=SSLInfo(issuer="Let's Encrypt", is_valid=True, valid_from="Jan", valid_to="Dec"),
        tranco_rank=None,
        redirect_chain=["https://evil.com", "https://evil.com/login"],
    )
    mock_inv.return_value = [bundle]

    state = InvestigationState(email=_email())
    state.urls = ["https://evil.com"]
    result = await gather_evidence(state, "eid6")

    assert len(result.evidence_bundles) == 1
    assert result.evidence_bundles[0].whois.registrar == "GoDaddy"


@pytest.mark.asyncio
@patch("app.l3_orchestrator.graph.events.publish", new_callable=AsyncMock)
@patch("app.l3_orchestrator.graph.investigate_urls", new_callable=AsyncMock,
       side_effect=RuntimeError("network down"))
async def test_gather_evidence_error(mock_inv, mock_pub):
    state = InvestigationState(email=_email())
    state.urls = ["https://evil.com"]
    result = await gather_evidence(state, "eid7")
    assert "failed" in result.error.lower()


@pytest.mark.asyncio
@patch("app.l3_orchestrator.graph.events.publish", new_callable=AsyncMock)
@patch("app.l3_orchestrator.graph.judge_email", new_callable=AsyncMock)
async def test_judge_verdict_safe(mock_judge, mock_pub):
    mock_judge.return_value = JudgeVerdict(
        verdict=Label.SAFE, confidence=0.9,
        reasoning="Safe", recommended_action=Verdict.RELEASE,
    )
    state = InvestigationState(email=_email())
    state.evidence_bundles = [EvidenceBundle(url="https://evil.com")]
    result = await judge_verdict(state, "eid8")
    assert result.verdict.verdict == Label.SAFE


@pytest.mark.asyncio
@patch("app.l3_orchestrator.graph.events.publish", new_callable=AsyncMock)
@patch("app.l3_orchestrator.graph.judge_email", new_callable=AsyncMock,
       side_effect=RuntimeError("GPU OOM"))
async def test_judge_verdict_error(mock_judge, mock_pub):
    state = InvestigationState(email=_email())
    state.evidence_bundles = []
    result = await judge_verdict(state, "eid9")
    assert result.verdict is not None
    assert "error" in result.error.lower() or result.verdict.verdict == Label.PHISHING


@pytest.mark.asyncio
async def test_make_decision_safe():
    state = InvestigationState(email=_email())
    state.verdict = JudgeVerdict(
        verdict=Label.SAFE, confidence=0.95,
        reasoning="Safe", recommended_action=Verdict.RELEASE,
    )
    result = await make_decision(state)
    assert result.action == Verdict.RELEASE


@pytest.mark.asyncio
async def test_make_decision_phishing():
    state = InvestigationState(email=_email())
    state.verdict = JudgeVerdict(
        verdict=Label.PHISHING, confidence=0.9,
        reasoning="Phish", recommended_action=Verdict.DELETE,
    )
    result = await make_decision(state)
    assert result.action == Verdict.DELETE


@pytest.mark.asyncio
async def test_make_decision_uncertain():
    state = InvestigationState(email=_email())
    state.verdict = JudgeVerdict(
        verdict=Label.UNCERTAIN, confidence=0.5,
        reasoning="Unclear", recommended_action=Verdict.OPERATOR_REVIEW,
    )
    result = await make_decision(state)
    assert result.action == Verdict.OPERATOR_REVIEW


@pytest.mark.asyncio
async def test_make_decision_no_verdict():
    state = InvestigationState(email=_email())
    state.verdict = None
    result = await make_decision(state)
    assert result.action == Verdict.DELETE


@pytest.mark.asyncio
@patch("app.l3_orchestrator.graph.events.publish", new_callable=AsyncMock)
@patch("app.l3_orchestrator.graph.judge_email", new_callable=AsyncMock)
@patch("app.l3_orchestrator.graph.investigate_urls", new_callable=AsyncMock)
@patch("app.l3_orchestrator.graph.extract_qr_urls", return_value=[])
async def test_run_investigation_full(mock_qr, mock_inv, mock_judge, mock_pub):
    mock_inv.return_value = [EvidenceBundle(url="https://evil.com")]
    mock_judge.return_value = JudgeVerdict(
        verdict=Label.PHISHING, confidence=0.95,
        reasoning="Phishing", recommended_action=Verdict.DELETE,
    )

    state = await run_investigation(_email(), "eid10")
    assert state.action == Verdict.DELETE
    assert state.verdict.verdict == Label.PHISHING
