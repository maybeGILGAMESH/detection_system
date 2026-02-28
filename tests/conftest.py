"""Test fixtures — sample emails and shared utilities."""

import pytest


@pytest.fixture
def safe_email_raw() -> bytes:
    """Raw bytes of a legitimate email."""
    return (
        b"From: friend@gmail.com\r\n"
        b"To: user@example.com\r\n"
        b"Subject: Coffee tomorrow?\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Hey! Let's meet for coffee tomorrow at 3pm. "
        b"Here is the cafe: https://www.google.com/maps/place/cafe\r\n"
    )


@pytest.fixture
def phishing_email_raw() -> bytes:
    """Raw bytes of a phishing email."""
    return (
        b"From: security@fake-bank-alert.xyz\r\n"
        b"To: user@example.com\r\n"
        b"Subject: URGENT: Your account has been compromised!\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Dear customer,\r\n\r\n"
        b"We have detected unauthorized access to your account. "
        b"You must verify your identity immediately or your account will be suspended.\r\n\r\n"
        b"Click here to verify: http://evil-phish.xyz/login?id=12345\r\n\r\n"
        b"If you do not respond within 24 hours, your account will be permanently locked.\r\n\r\n"
        b"Best regards,\r\n"
        b"Security Team\r\n"
    )


@pytest.fixture
def grey_zone_email_raw() -> bytes:
    """Raw bytes of an ambiguous email (grey zone)."""
    return (
        b"From: promo@unknown-service.net\r\n"
        b"To: user@example.com\r\n"
        b"Subject: Special offer just for you!\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Congratulations! You've been selected for a special offer.\r\n"
        b"Visit https://suspicious-deal.com/verify to claim your reward.\r\n"
    )

