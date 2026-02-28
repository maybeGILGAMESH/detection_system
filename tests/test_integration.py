"""Integration tests — email parsing and basic pipeline."""

import pytest

from app.gateway.email_parser import parse_email


def test_parse_safe_email(safe_email_raw):
    """Should correctly parse a legitimate email."""
    email = parse_email(safe_email_raw)
    assert email.sender == "friend@gmail.com"
    assert email.recipient == "user@example.com"
    assert email.subject == "Coffee tomorrow?"
    assert "coffee" in email.body.lower()
    assert len(email.urls) >= 1
    assert any("google.com" in u for u in email.urls)


def test_parse_phishing_email(phishing_email_raw):
    """Should correctly parse a phishing email and extract malicious URLs."""
    email = parse_email(phishing_email_raw)
    assert email.sender == "security@fake-bank-alert.xyz"
    assert "URGENT" in email.subject
    assert "compromised" in email.body.lower()
    assert any("evil-phish.xyz" in u for u in email.urls)
    assert "fake-bank-alert.xyz" in email.domains or len(email.domains) > 0


def test_parse_grey_zone_email(grey_zone_email_raw):
    """Should correctly parse an ambiguous email."""
    email = parse_email(grey_zone_email_raw)
    assert email.sender == "promo@unknown-service.net"
    assert any("suspicious-deal.com" in u for u in email.urls)

