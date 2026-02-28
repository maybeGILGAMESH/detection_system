"""Email text preprocessing for L2 classifier."""

import re
import html


def clean_email_text(text: str) -> str:
    """Clean raw email text for model input.

    Steps:
      1. Unescape HTML entities
      2. Strip HTML tags
      3. Normalize whitespace
      4. Remove excessive URLs (keep domain only for context)
      5. Truncate to reasonable length
    """
    if not text:
        return ""

    # Unescape HTML entities
    text = html.unescape(text)

    # Remove HTML tags
    text = re.sub(r"<[^>]+>", " ", text)

    # Remove base64 blobs / long encoded strings
    text = re.sub(r"[A-Za-z0-9+/]{50,}={0,2}", " ", text)

    # Simplify URLs: replace full URLs with just domain
    text = re.sub(
        r"https?://([a-zA-Z0-9.-]+)[^\s]*",
        r"[URL:\1]",
        text,
    )

    # Normalize whitespace
    text = re.sub(r"\s+", " ", text).strip()

    # Truncate to ~512 tokens worth (roughly 2000 chars for DistilBERT)
    max_chars = 2000
    if len(text) > max_chars:
        text = text[:max_chars]

    return text


def combine_subject_body(subject: str, body: str) -> str:
    """Combine subject and body into a single input string."""
    subject = (subject or "").strip()
    body = clean_email_text(body or "")

    if subject:
        return f"Subject: {subject} Body: {body}"
    return body

