"""Tests for gateway/smtp_handler.py and additional gateway/router.py coverage."""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from app.schemas import (
    ParsedEmail, Verdict, Label, ProcessResult,
    L1Result, L2Result, JudgeVerdict, CheckerResult,
    EvidenceBundle, WHOISInfo, DOMAnalysis,
)
from app.gateway.router import process_email, _email_id, _summarize_for_inbox, health


def _email(**kw):
    defaults = dict(sender="test@example.com", recipient="user@local.com",
                    subject="Test", body="Hello", urls=["https://example.com"])
    defaults.update(kw)
    return ParsedEmail(**defaults)


# --- _email_id ---

def test_email_id_generates_hash():
    email = _email()
    eid = _email_id(email)
    assert len(eid) == 12
    assert isinstance(eid, str)


# --- _summarize_for_inbox ---

@pytest.mark.asyncio
@patch("app.gateway.router.events.publish", new_callable=AsyncMock)
@patch("app.gateway.router.operator_store")
async def test_summarize_for_inbox_deliver(mock_store, mock_events):
    email = _email()
    await _summarize_for_inbox(email, Verdict.DELIVER, "eid1", "Safe by L2")
    mock_store.add_to_inbox.assert_called_once()


@pytest.mark.asyncio
@patch("app.gateway.router.events.publish", new_callable=AsyncMock)
@patch("app.gateway.router.operator_store")
async def test_summarize_for_inbox_release(mock_store, mock_events):
    email = _email()
    await _summarize_for_inbox(email, Verdict.RELEASE, "eid2", "Safe by L3")
    mock_store.add_to_inbox.assert_called_once()


@pytest.mark.asyncio
@patch("app.gateway.router.events.publish", new_callable=AsyncMock)
@patch("app.gateway.router.operator_store")
async def test_summarize_for_inbox_reject_noop(mock_store, mock_events):
    """REJECT/DELETE emails should NOT be added to inbox."""
    email = _email()
    await _summarize_for_inbox(email, Verdict.REJECT, "eid3", "Blocked")
    mock_store.add_to_inbox.assert_not_called()


@pytest.mark.asyncio
@patch("app.gateway.router.events.publish", new_callable=AsyncMock)
@patch("app.gateway.router.operator_store")
async def test_summarize_for_inbox_l3_disabled(mock_store, mock_events):
    email = _email()
    await _summarize_for_inbox(email, Verdict.DELIVER, "eid4", "L3 disabled, no analysis")
    mock_store.add_to_inbox.assert_called_once()


# --- process_email: L3 DELETE path ---

@pytest.fixture(autouse=True)
def _enable_all_layers():
    from app.layer_toggle import layer_state
    orig = dict(layer_state)
    layer_state["L1"] = True
    layer_state["L2"] = True
    layer_state["L3"] = True
    yield
    layer_state.update(orig)


@pytest.mark.asyncio
@patch("app.gateway.router._summarize_for_inbox", new_callable=AsyncMock)
@patch("app.gateway.router.events.publish", new_callable=AsyncMock)
@patch("app.gateway.router.run_investigation", new_callable=AsyncMock)
@patch("app.gateway.router.l2_service.classify", new_callable=AsyncMock)
@patch("app.gateway.router.l1_service.check", new_callable=AsyncMock)
async def test_grey_zone_l3_delete(mock_l1, mock_l2, mock_l3, mock_events, mock_inbox):
    """L2 grey zone -> L3 judge says phishing -> DELETE."""
    from app.l3_orchestrator.state import InvestigationState

    mock_l1.return_value = L1Result(verdict=Verdict.PROCEED, results=[])
    mock_l2.return_value = L2Result(confidence=0.5, label=Label.SAFE)

    state = InvestigationState(email=_email())
    state.verdict = JudgeVerdict(
        verdict=Label.PHISHING, confidence=0.95,
        reasoning="Phishing URL", recommended_action=Verdict.DELETE,
    )
    state.action = Verdict.DELETE
    mock_l3.return_value = state

    result = await process_email(_email())
    assert result.action == Verdict.DELETE


# --- L3 OPERATOR_REVIEW with evidence ---

@pytest.mark.asyncio
@patch("app.gateway.router.events.publish", new_callable=AsyncMock)
@patch("app.gateway.router.run_investigation", new_callable=AsyncMock)
@patch("app.gateway.router.l2_service.classify", new_callable=AsyncMock)
@patch("app.gateway.router.l1_service.check", new_callable=AsyncMock)
async def test_grey_zone_operator_review_with_evidence(mock_l1, mock_l2, mock_l3, mock_events):
    from app.l3_orchestrator.state import InvestigationState

    mock_l1.return_value = L1Result(verdict=Verdict.PROCEED, results=[])
    mock_l2.return_value = L2Result(confidence=0.5, label=Label.SAFE)

    state = InvestigationState(email=_email())
    state.verdict = JudgeVerdict(
        verdict=Label.UNCERTAIN, confidence=0.5,
        reasoning="Unclear", recommended_action=Verdict.OPERATOR_REVIEW,
    )
    state.action = Verdict.OPERATOR_REVIEW
    state.evidence_bundles = [
        EvidenceBundle(
            url="https://evil.com",
            whois=WHOISInfo(registrar="Shady", domain_age_days=3),
            tranco_rank=None,
            dom_analysis=DOMAnalysis(forms_count=2, has_password_field=True),
        )
    ]
    mock_l3.return_value = state

    with patch("app.gateway.router.operator_store.add_pending"):
        result = await process_email(_email())

    assert result.action == Verdict.OPERATOR_REVIEW


# --- L1 disabled ---

@pytest.mark.asyncio
@patch("app.gateway.router._summarize_for_inbox", new_callable=AsyncMock)
@patch("app.gateway.router.events.publish", new_callable=AsyncMock)
@patch("app.gateway.router.l2_service.classify", new_callable=AsyncMock)
async def test_l1_disabled_l2_safe(mock_l2, mock_events, mock_inbox):
    from app.layer_toggle import layer_state
    layer_state["L1"] = False

    mock_l2.return_value = L2Result(confidence=0.95, label=Label.SAFE)
    result = await process_email(_email())
    assert result.action == Verdict.DELIVER


# --- L2 disabled, L3 disabled ---

@pytest.mark.asyncio
@patch("app.gateway.router._summarize_for_inbox", new_callable=AsyncMock)
@patch("app.gateway.router.events.publish", new_callable=AsyncMock)
@patch("app.gateway.router.l1_service.check", new_callable=AsyncMock)
async def test_l2_disabled_l3_disabled(mock_l1, mock_events, mock_inbox):
    from app.layer_toggle import layer_state
    layer_state["L2"] = False
    layer_state["L3"] = False

    mock_l1.return_value = L1Result(verdict=Verdict.PROCEED, results=[])
    result = await process_email(_email())
    assert result.action == Verdict.DELIVER
    assert "disabled" in result.detail.lower() or "no analysis" in result.detail.lower()


# --- L3 disabled with L2 grey zone ---

@pytest.mark.asyncio
@patch("app.gateway.router._summarize_for_inbox", new_callable=AsyncMock)
@patch("app.gateway.router.events.publish", new_callable=AsyncMock)
@patch("app.gateway.router.l2_service.classify", new_callable=AsyncMock)
@patch("app.gateway.router.l1_service.check", new_callable=AsyncMock)
async def test_l3_disabled_grey_zone(mock_l1, mock_l2, mock_events, mock_inbox):
    from app.layer_toggle import layer_state
    layer_state["L3"] = False

    mock_l1.return_value = L1Result(verdict=Verdict.PROCEED, results=[])
    mock_l2.return_value = L2Result(confidence=0.5, label=Label.SAFE)

    result = await process_email(_email())
    assert result.action == Verdict.DELIVER
    assert "L3 disabled" in result.detail or "grey zone" in result.detail.lower()


# --- L3 disabled with L2 phishing threshold ---

@pytest.mark.asyncio
@patch("app.gateway.router._summarize_for_inbox", new_callable=AsyncMock)
@patch("app.gateway.router.events.publish", new_callable=AsyncMock)
@patch("app.gateway.router.l2_service.classify", new_callable=AsyncMock)
@patch("app.gateway.router.l1_service.check", new_callable=AsyncMock)
async def test_l3_disabled_low_confidence(mock_l1, mock_l2, mock_events, mock_inbox):
    from app.layer_toggle import layer_state
    layer_state["L3"] = False

    mock_l1.return_value = L1Result(verdict=Verdict.PROCEED, results=[])
    mock_l2.return_value = L2Result(confidence=0.2, label=Label.PHISHING)

    result = await process_email(_email())
    assert result.action == Verdict.REJECT


# --- health endpoint ---

@pytest.mark.asyncio
async def test_health():
    from app.gateway.router import health
    result = await health()
    assert result["status"] == "ok"
    assert "layers" in result


# --- SMTP handler ---

def test_smtp_handler_init():
    from app.gateway.smtp_handler import PhishingHandler
    handler = PhishingHandler()
    assert hasattr(handler, "handle_DATA")


@pytest.mark.asyncio
async def test_smtp_handle_data_success():
    from app.gateway.smtp_handler import PhishingHandler

    handler = PhishingHandler()
    mock_server = MagicMock()
    mock_session = MagicMock()
    mock_session.peer = ("127.0.0.1", 12345)

    mock_envelope = MagicMock()
    mock_envelope.mail_from = "sender@test.com"
    mock_envelope.rcpt_tos = ["user@local.com"]
    mock_envelope.content = (
        b"From: sender@test.com\r\n"
        b"To: user@local.com\r\n"
        b"Subject: Test\r\n"
        b"\r\n"
        b"Hello World"
    )

    with patch("app.gateway.smtp_handler.process_email", new_callable=AsyncMock) as mock_proc, \
         patch("app.gateway.smtp_handler.settings") as mock_s:
        mock_s.max_email_size = 10 * 1024 * 1024
        mock_proc.return_value = ProcessResult(
            action=Verdict.DELIVER, detail="Safe",
        )
        result = await handler.handle_DATA(mock_server, mock_session, mock_envelope)

    assert "250" in result


@pytest.mark.asyncio
async def test_smtp_handle_data_reject():
    from app.gateway.smtp_handler import PhishingHandler

    handler = PhishingHandler()
    mock_server = MagicMock()
    mock_session = MagicMock()
    mock_session.peer = ("127.0.0.1", 12345)

    mock_envelope = MagicMock()
    mock_envelope.mail_from = "evil@phish.com"
    mock_envelope.rcpt_tos = ["user@local.com"]
    mock_envelope.content = (
        b"From: evil@phish.com\r\n"
        b"Subject: You won!\r\n"
        b"\r\n"
        b"Click here to claim your prize"
    )

    with patch("app.gateway.smtp_handler.process_email", new_callable=AsyncMock) as mock_proc, \
         patch("app.gateway.smtp_handler.settings") as mock_s:
        mock_s.max_email_size = 10 * 1024 * 1024
        mock_proc.return_value = ProcessResult(
            action=Verdict.REJECT, detail="Phishing",
        )
        result = await handler.handle_DATA(mock_server, mock_session, mock_envelope)

    assert "550" in result


@pytest.mark.asyncio
async def test_smtp_handle_data_too_large():
    from app.gateway.smtp_handler import PhishingHandler

    handler = PhishingHandler()
    mock_server = MagicMock()
    mock_session = MagicMock()
    mock_session.peer = ("127.0.0.1", 12345)

    mock_envelope = MagicMock()
    mock_envelope.mail_from = "sender@test.com"
    mock_envelope.rcpt_tos = ["user@local.com"]
    mock_envelope.content = b"X" * 1000

    with patch("app.gateway.smtp_handler.settings") as mock_s:
        mock_s.max_email_size = 100
        result = await handler.handle_DATA(mock_server, mock_session, mock_envelope)

    assert "552" in result


@pytest.mark.asyncio
async def test_smtp_handle_data_exception():
    from app.gateway.smtp_handler import PhishingHandler

    handler = PhishingHandler()
    mock_server = MagicMock()
    mock_session = MagicMock()
    mock_session.peer = ("127.0.0.1", 12345)

    mock_envelope = MagicMock()
    mock_envelope.mail_from = "sender@test.com"
    mock_envelope.rcpt_tos = ["user@local.com"]
    mock_envelope.content = b"From: a@b.com\r\n\r\nHello"

    with patch("app.gateway.smtp_handler.parse_email", side_effect=Exception("parse fail")), \
         patch("app.gateway.smtp_handler.settings") as mock_s:
        mock_s.max_email_size = 10 * 1024 * 1024
        result = await handler.handle_DATA(mock_server, mock_session, mock_envelope)

    assert "250" in result


def test_start_smtp_server():
    from app.gateway.smtp_handler import start_smtp_server

    with patch("app.gateway.smtp_handler.Controller") as mock_ctrl_cls, \
         patch("app.gateway.smtp_handler.settings") as mock_s:
        mock_s.max_email_size = 10_000_000
        mock_instance = MagicMock()
        mock_ctrl_cls.return_value = mock_instance

        ctrl = start_smtp_server("127.0.0.1", 2525)

    mock_instance.start.assert_called_once()
    assert ctrl is mock_instance


# --- email_parser edge cases ---

def test_parse_email_multipart():
    from app.gateway.email_parser import parse_email

    raw = (
        b"From: sender@test.com\r\n"
        b"To: user@local.com\r\n"
        b"Subject: Multipart Test\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/alternative; boundary=bound\r\n"
        b"\r\n"
        b"--bound\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"Plain text body with https://example.com link\r\n"
        b"--bound\r\n"
        b"Content-Type: text/html\r\n"
        b"\r\n"
        b"<html><body><a href='https://html-link.com'>Click</a></body></html>\r\n"
        b"--bound--\r\n"
    )

    parsed = parse_email(raw)
    assert parsed.sender == "sender@test.com"
    assert "example.com" in str(parsed.urls) or "html-link.com" in str(parsed.urls)


def test_parse_email_html_only():
    from app.gateway.email_parser import parse_email

    raw = (
        b"From: a@b.com\r\n"
        b"Subject: HTML Only\r\n"
        b"Content-Type: text/html\r\n"
        b"\r\n"
        b"<html><body><p>Hello <a href='https://link.com'>world</a></p></body></html>\r\n"
    )

    parsed = parse_email(raw)
    assert "Hello" in parsed.body or "world" in parsed.body


def test_parse_email_with_received_headers():
    from app.gateway.email_parser import parse_email

    raw = (
        b"Received: from mail.example.com (8.8.8.8) by local\r\n"
        b"Received: from gateway (203.0.113.5) by mail.example.com\r\n"
        b"From: a@b.com\r\n"
        b"Subject: IP Test\r\n"
        b"\r\n"
        b"Body\r\n"
    )

    parsed = parse_email(raw)
    assert "8.8.8.8" in parsed.ips or "203.0.113.5" in parsed.ips


# --- process_raw_email endpoint ---

@pytest.mark.asyncio
async def test_process_raw_email():
    from app.gateway.router import process_raw_email

    raw = (
        b"From: a@b.com\r\n"
        b"Subject: Test Raw\r\n"
        b"\r\n"
        b"Body text"
    )

    with patch("app.gateway.router.process_email", new_callable=AsyncMock) as mock_proc:
        mock_proc.return_value = ProcessResult(action=Verdict.DELIVER, detail="OK")
        result = await process_raw_email(raw)

    assert result.action == Verdict.DELIVER
