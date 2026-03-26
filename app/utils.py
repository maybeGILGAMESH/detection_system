"""Shared utility functions used across multiple modules."""

from urllib.parse import urlparse


def extract_domain(url: str) -> str:
    """Extract the registrable domain from a URL or bare domain string.

    Handles both full URLs (``https://example.com/path``) and bare
    hostnames (``example.com``).
    """
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return (parsed.netloc or parsed.path.split("/")[0]).lower()


def extract_host(url: str) -> str:
    """Extract the hostname (without port) from a URL."""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return parsed.netloc.split(":")[0] or parsed.path.split("/")[0]
