"""Tests for l3_judge/service.py (_parse_verdict) and prompts.py (build_judge_prompt)."""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio

from app.schemas import Label, Verdict, JudgeVerdict, ParsedEmail, EvidenceBundle
from app.l3_judge.prompts import SYSTEM_PROMPT, COT_TEMPLATE, build_judge_prompt


# --- prompts.py ---

def test_system_prompt_exists():
    assert len(SYSTEM_PROMPT) > 50
    assert "phishing" in SYSTEM_PROMPT.lower()


def test_cot_template_has_placeholders():
    assert "{sender}" in COT_TEMPLATE
    assert "{body_excerpt}" in COT_TEMPLATE
    assert "{tranco_rank}" in COT_TEMPLATE


def test_build_prompt_minimal():
    prompt = build_judge_prompt(
        sender="test@example.com",
        subject="Hello",
        body="This is a test email",
    )
    assert "test@example.com" in prompt
    assert "Hello" in prompt
    assert "This is a test email" in prompt
    assert "N/A" in prompt


def test_build_prompt_with_urls():
    prompt = build_judge_prompt(
        sender="a@b.com",
        body="Click here",
        urls=["https://evil.com", "https://safe.org"],
    )
    assert "evil.com" in prompt
    assert "safe.org" in prompt


def test_build_prompt_with_qr_urls():
    prompt = build_judge_prompt(
        sender="a@b.com",
        body="Scan QR",
        qr_urls=["https://qr-phish.com"],
    )
    assert "Yes" in prompt
    assert "qr-phish.com" in prompt


def test_build_prompt_with_evidence():
    from app.schemas import DOMAnalysis, WHOISInfo, SSLInfo

    evidence = EvidenceBundle(
        url="https://example.com",
        dom_analysis=DOMAnalysis(
            forms_count=2,
            has_password_field=True,
            external_scripts=["https://cdn.evil.com/script.js"],
            iframes_count=1,
        ),
        whois=WHOISInfo(
            registrar="GoDaddy",
            domain_age_days=30,
            country="US",
        ),
        ssl=SSLInfo(
            issuer="Let's Encrypt",
            is_valid=True,
            valid_from="Jan 1",
            valid_to="Dec 31",
        ),
        tranco_rank=5000,
        redirect_chain=["https://example.com", "https://example.com/login"],
    )

    prompt = build_judge_prompt(
        sender="a@b.com",
        body="Login now",
        evidence=evidence,
    )
    assert "GoDaddy" in prompt
    assert "#5000" in prompt
    assert "Let's Encrypt" in prompt
    assert "Yes" in prompt  # has_password_field
    assert "30" in prompt  # domain_age_days


def test_build_prompt_long_body_truncated():
    long_body = "A" * 1000
    prompt = build_judge_prompt(body=long_body)
    assert len(prompt) < len(long_body) + 5000


def test_build_prompt_empty():
    prompt = build_judge_prompt()
    assert "(empty)" in prompt
    assert "(none)" in prompt


# --- _parse_verdict from service.py ---

def test_parse_verdict_phishing_json():
    from app.l3_judge.service import _parse_verdict

    raw = '{"verdict": "phishing", "confidence": 0.95, "reasoning": "Suspicious URL"}'
    result = _parse_verdict(raw)
    assert result.verdict == Label.PHISHING
    assert result.confidence == 0.95
    assert result.recommended_action == Verdict.DELETE


def test_parse_verdict_safe_json():
    from app.l3_judge.service import _parse_verdict

    raw = '{"verdict": "safe", "confidence": 0.9, "reasoning": "Known sender"}'
    result = _parse_verdict(raw)
    assert result.verdict == Label.SAFE
    assert result.recommended_action == Verdict.RELEASE


def test_parse_verdict_uncertain_json():
    from app.l3_judge.service import _parse_verdict

    raw = '{"verdict": "uncertain", "confidence": 0.5, "reasoning": "Mixed signals"}'
    result = _parse_verdict(raw)
    assert result.verdict == Label.UNCERTAIN
    assert result.recommended_action == Verdict.OPERATOR_REVIEW


def test_parse_verdict_low_confidence_escalates():
    from app.l3_judge.service import _parse_verdict

    raw = '{"verdict": "phishing", "confidence": 0.4, "reasoning": "Weak signals"}'
    result = _parse_verdict(raw)
    assert result.verdict == Label.UNCERTAIN
    assert result.recommended_action == Verdict.OPERATOR_REVIEW


def test_parse_verdict_json_in_text():
    from app.l3_judge.service import _parse_verdict

    raw = 'Here is my analysis:\n\n{"verdict": "phishing", "confidence": 0.85, "reasoning": "Phish"}\n\nEnd.'
    result = _parse_verdict(raw)
    assert result.verdict == Label.PHISHING


def test_parse_verdict_keyword_phishing():
    from app.l3_judge.service import _parse_verdict

    raw = "After analysis, this is clearly phishing due to the suspicious URL."
    result = _parse_verdict(raw)
    assert result.verdict == Label.PHISHING
    assert result.recommended_action == Verdict.DELETE


def test_parse_verdict_keyword_uncertain():
    from app.l3_judge.service import _parse_verdict

    raw = "I am not sure about this email. Cannot determine the intent."
    result = _parse_verdict(raw)
    assert result.verdict == Label.UNCERTAIN


def test_parse_verdict_keyword_cannot_determine():
    from app.l3_judge.service import _parse_verdict

    raw = "The evidence is contradictory. I cannot determine if this is safe."
    result = _parse_verdict(raw)
    assert result.verdict == Label.UNCERTAIN


def test_parse_verdict_no_keywords_defaults_safe():
    from app.l3_judge.service import _parse_verdict

    raw = "This looks perfectly fine, a normal business communication."
    result = _parse_verdict(raw)
    assert result.verdict == Label.SAFE


def test_parse_verdict_confidence_clamped():
    from app.l3_judge.service import _parse_verdict

    raw = '{"verdict": "phishing", "confidence": 1.5, "reasoning": "x"}'
    result = _parse_verdict(raw)
    assert result.confidence == 1.0

    raw2 = '{"verdict": "safe", "confidence": -0.5, "reasoning": "x"}'
    result2 = _parse_verdict(raw2)
    assert result2.confidence == 0.0


def test_parse_verdict_malformed_json():
    from app.l3_judge.service import _parse_verdict

    raw = '{"verdict": "phishing", confidence: invalid}'
    result = _parse_verdict(raw)
    assert result.verdict in (Label.PHISHING, Label.SAFE, Label.UNCERTAIN)


def test_parse_verdict_unknown_verdict_string():
    from app.l3_judge.service import _parse_verdict

    raw = '{"verdict": "unknown", "confidence": 0.5, "reasoning": "x"}'
    result = _parse_verdict(raw)
    assert result.verdict == Label.UNCERTAIN


# --- judge() and summarize_email() from service.py ---

@pytest.mark.asyncio
async def test_judge_timeout():
    from app.l3_judge import service

    service._llm = MagicMock()

    async def slow_generate(*args, **kwargs):
        await asyncio.sleep(100)

    with patch.object(service, "_generate", side_effect=slow_generate), \
         patch.object(service, "JUDGE_TIMEOUT", 0.01), \
         patch("app.l3_judge.service.settings") as mock_s:
        mock_s.judge_backend = "llama_cpp"

        email = ParsedEmail(sender="a@b.com", subject="Test", body="Hello")
        result = await service.judge(email)

    assert result.verdict == Label.UNCERTAIN
    assert result.recommended_action == Verdict.OPERATOR_REVIEW
    service._llm = None


@pytest.mark.asyncio
async def test_judge_with_mocked_llm():
    from app.l3_judge import service

    service._llm = MagicMock()

    async def mock_gen(prompt):
        return '{"verdict": "safe", "confidence": 0.9, "reasoning": "Legit email"}'

    with patch.object(service, "_generate", side_effect=mock_gen), \
         patch("app.l3_judge.service.settings") as mock_s:
        mock_s.judge_backend = "vllm"

        email = ParsedEmail(sender="a@b.com", subject="Hello", body="Normal email")
        result = await service.judge(email)

    assert result.verdict == Label.SAFE
    service._llm = None


@pytest.mark.asyncio
async def test_summarize_email_no_model():
    """When model is not loaded, falls back to simple truncation."""
    from app.l3_judge import service

    service._llm = None
    email = ParsedEmail(sender="a@b.com", subject="Important", body="A" * 300)
    summary = await service.summarize_email(email)
    assert len(summary) <= 200
    service._llm = None


@pytest.mark.asyncio
async def test_summarize_email_with_model():
    from app.l3_judge import service
    service._llm = MagicMock()

    def mock_summarize(prompt):
        return "Short summary of the email."

    with patch.object(service, "_summarize_sync", side_effect=mock_summarize):
        email = ParsedEmail(sender="a@b.com", subject="Test", body="Long body text here")
        summary = await service.summarize_email(email)

    assert "summary" in summary.lower() or len(summary) > 0
    service._llm = None


@pytest.mark.asyncio
async def test_summarize_email_exception():
    """When summarization raises, falls back gracefully."""
    from app.l3_judge import service
    service._llm = MagicMock()

    def mock_summarize(prompt):
        raise RuntimeError("LLM crashed")

    with patch.object(service, "_summarize_sync", side_effect=mock_summarize):
        email = ParsedEmail(sender="a@b.com", subject="Test", body="Body content")
        summary = await service.summarize_email(email)

    assert isinstance(summary, str)
    assert len(summary) > 0
    service._llm = None


def test_load_model_llama_cpp():
    from app.l3_judge import service

    service._llm = None
    mock_llm_instance = MagicMock()

    with patch("app.l3_judge.service.settings") as mock_s, \
         patch.dict("sys.modules", {"llama_cpp": MagicMock()}):
        mock_s.judge_backend = "llama_cpp"
        mock_s.deepseek_gguf_path = "/fake/model.gguf"

        import sys
        sys.modules["llama_cpp"].Llama.return_value = mock_llm_instance

        service.load_model()

    assert service._llm is not None
    service._llm = None


def test_generate_sync_llama_cpp():
    from app.l3_judge import service

    mock_llm = MagicMock()
    mock_llm.create_chat_completion.return_value = {
        "choices": [{"message": {"content": "test output"}}]
    }
    service._llm = mock_llm

    with patch("app.l3_judge.service.settings") as mock_s:
        mock_s.judge_backend = "llama_cpp"
        result = service._generate_sync("test prompt")

    assert result == "test output"
    service._llm = None
