"""Tests for L2 Classifier module."""

import pytest

from app.l2_classifier.preprocess import clean_email_text, combine_subject_body


def test_clean_email_text_html():
    """Should strip HTML tags."""
    text = "<html><body><p>Hello <b>world</b></p></body></html>"
    cleaned = clean_email_text(text)
    assert "<" not in cleaned
    assert "Hello" in cleaned
    assert "world" in cleaned


def test_clean_email_text_urls():
    """Should simplify URLs to [URL:domain]."""
    text = "Visit https://www.example.com/page?q=1 for details"
    cleaned = clean_email_text(text)
    assert "[URL:www.example.com]" in cleaned


def test_clean_email_text_empty():
    """Should handle empty input."""
    assert clean_email_text("") == ""
    assert clean_email_text(None) == ""


def test_combine_subject_body():
    """Should combine subject and body."""
    result = combine_subject_body("Test Subject", "Test Body")
    assert "Subject: Test Subject" in result
    assert "Body:" in result


def test_combine_subject_body_no_subject():
    """Should handle missing subject."""
    result = combine_subject_body("", "Just a body")
    assert "Subject:" not in result
    assert "Just a body" in result

