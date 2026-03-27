"""Tests for app/utils.py — extract_domain and extract_host."""

from app.utils import extract_domain, extract_host


def test_extract_domain_full_url():
    assert extract_domain("https://www.example.com/path") == "www.example.com"


def test_extract_domain_bare():
    assert extract_domain("example.com") == "example.com"


def test_extract_domain_with_port():
    assert extract_domain("https://example.com:8080/path") == "example.com:8080"


def test_extract_host_full_url():
    assert extract_host("https://www.example.com/path") == "www.example.com"


def test_extract_host_bare():
    assert extract_host("example.com") == "example.com"


def test_extract_host_with_port():
    assert extract_host("https://example.com:443/path") == "example.com"
