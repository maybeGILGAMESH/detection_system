"""Tests for L3 Judge _parse_verdict — parsing LLM output into JudgeVerdict."""

import pytest

from app.schemas import Label, Verdict
from app.l3_judge.service import _parse_verdict


class TestParseVerdictJSON:
    """Test parsing well-formed JSON responses."""

    def test_phishing_high_confidence(self):
        raw = '{"verdict": "phishing", "confidence": 0.95, "reasoning": "Obvious phishing"}'
        v = _parse_verdict(raw)
        assert v.verdict == Label.PHISHING
        assert v.confidence == 0.95
        assert v.recommended_action == Verdict.DELETE

    def test_safe_high_confidence(self):
        raw = '{"verdict": "safe", "confidence": 0.9, "reasoning": "Looks fine"}'
        v = _parse_verdict(raw)
        assert v.verdict == Label.SAFE
        assert v.confidence == 0.9
        assert v.recommended_action == Verdict.RELEASE

    def test_uncertain_explicit(self):
        raw = '{"verdict": "uncertain", "confidence": 0.5, "reasoning": "Cannot tell"}'
        v = _parse_verdict(raw)
        assert v.verdict == Label.UNCERTAIN
        assert v.recommended_action == Verdict.OPERATOR_REVIEW

    def test_low_confidence_escalates_to_uncertain(self):
        raw = '{"verdict": "safe", "confidence": 0.4, "reasoning": "Weak signal"}'
        v = _parse_verdict(raw)
        assert v.verdict == Label.UNCERTAIN
        assert v.recommended_action == Verdict.OPERATOR_REVIEW

    def test_json_embedded_in_text(self):
        raw = (
            "Let me think step by step...\n"
            '{"verdict": "phishing", "confidence": 0.88, "reasoning": "Bad domain"}\n'
            "That's my analysis."
        )
        v = _parse_verdict(raw)
        assert v.verdict == Label.PHISHING
        assert v.confidence == 0.88

    def test_confidence_clamped(self):
        raw = '{"verdict": "safe", "confidence": 1.5, "reasoning": "Over-confident"}'
        v = _parse_verdict(raw)
        assert v.confidence == 1.0

    def test_negative_confidence_clamped(self):
        raw = '{"verdict": "phishing", "confidence": -0.3, "reasoning": "Broken"}'
        v = _parse_verdict(raw)
        assert v.confidence == 0.0


class TestParseVerdictKeywordFallback:
    """Test keyword-based fallback when JSON is not parseable."""

    def test_phishing_keyword(self):
        raw = "This email is clearly phishing because of the fake URL."
        v = _parse_verdict(raw)
        assert v.verdict == Label.PHISHING
        assert v.recommended_action == Verdict.DELETE

    def test_uncertain_keywords(self):
        raw = "I am not sure whether this is malicious or legitimate."
        v = _parse_verdict(raw)
        assert v.verdict == Label.UNCERTAIN
        assert v.recommended_action == Verdict.OPERATOR_REVIEW

    def test_cannot_determine(self):
        raw = "I cannot determine the nature of this email."
        v = _parse_verdict(raw)
        assert v.verdict == Label.UNCERTAIN

    def test_no_keywords_defaults_safe(self):
        raw = "Everything looks normal here."
        v = _parse_verdict(raw)
        assert v.verdict == Label.SAFE
        assert v.recommended_action == Verdict.RELEASE

    def test_empty_string(self):
        v = _parse_verdict("")
        assert v.verdict == Label.SAFE
        assert v.confidence == 0.5


class TestParseVerdictMalformedJSON:
    """Test malformed JSON handling."""

    def test_invalid_json(self):
        raw = '{"verdict": phishing, confidence: 0.8}'
        v = _parse_verdict(raw)
        assert v.verdict == Label.PHISHING  # falls back to keyword "phishing"

    def test_empty_json_object(self):
        raw = '{}'
        v = _parse_verdict(raw)
        assert v.verdict is not None  # should not crash
