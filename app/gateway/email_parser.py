"""Parse raw email bytes into a structured ParsedEmail object."""

import re
import logging
from email import message_from_bytes, policy
from email.message import EmailMessage
from urllib.parse import urlparse

from app.schemas import ParsedEmail

logger = logging.getLogger(__name__)

# Regex for URLs
_URL_RE = re.compile(r'https?://[^\s<>"\')\]]+')

# Regex for IP addresses
_IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def parse_email(raw: bytes) -> ParsedEmail:
    """Parse raw email bytes into a ParsedEmail.

    Extracts: sender, recipient, subject, body, URLs, IPs, domains.
    """
    try:
        msg = message_from_bytes(raw, policy=policy.default)
    except Exception:
        msg = message_from_bytes(raw)

    sender = str(msg.get("From", ""))
    recipient = str(msg.get("To", ""))
    subject = str(msg.get("Subject", ""))
    message_id = str(msg.get("Message-ID", ""))

    # Extract body
    body = ""
    html_body = ""

    if isinstance(msg, EmailMessage):
        # Modern API
        text_body = msg.get_body(preferencelist=("plain",))
        html_part = msg.get_body(preferencelist=("html",))

        if text_body:
            try:
                body = text_body.get_content()
            except Exception:
                body = str(text_body.get_payload(decode=True) or b"", "utf-8", errors="ignore")

        if html_part:
            try:
                html_body = html_part.get_content()
            except Exception:
                html_body = str(html_part.get_payload(decode=True) or b"", "utf-8", errors="ignore")
    else:
        # Legacy API
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                try:
                    payload = part.get_payload(decode=True)
                    if payload is None:
                        continue
                    text = payload.decode("utf-8", errors="ignore")
                except Exception:
                    continue

                if content_type == "text/plain" and not body:
                    body = text
                elif content_type == "text/html" and not html_body:
                    html_body = text
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    body = payload.decode("utf-8", errors="ignore")
            except Exception:
                body = str(msg.get_payload())

    # If no plain text, use HTML as body fallback
    if not body and html_body:
        body = re.sub(r"<[^>]+>", " ", html_body)
        body = re.sub(r"\s+", " ", body).strip()

    # Extract URLs
    all_text = f"{body} {html_body}"
    urls = list(set(_URL_RE.findall(all_text)))

    # Extract IPs from headers
    received_headers = msg.get_all("Received") or []
    header_text = " ".join(str(h) for h in received_headers)
    ips = list(set(_IP_RE.findall(header_text)))
    # Filter out private/local IPs
    ips = [ip for ip in ips if not ip.startswith(("10.", "127.", "192.168.", "0."))]

    # Extract domains from URLs
    domains = list(set(
        urlparse(url).netloc.lower()
        for url in urls
        if urlparse(url).netloc
    ))

    parsed = ParsedEmail(
        message_id=message_id,
        sender=sender,
        recipient=recipient,
        subject=subject,
        body=body,
        html_body=html_body,
        urls=urls,
        ips=ips,
        domains=domains,
        raw=raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw),
    )

    logger.info(
        "Parsed email: from=%s, subject='%s', urls=%d, ips=%d, domains=%d",
        sender, subject, len(urls), len(ips), len(domains),
    )

    return parsed

