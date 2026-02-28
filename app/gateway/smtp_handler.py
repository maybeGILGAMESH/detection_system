"""aiosmtpd handler — receives emails via SMTP and runs the AI cascade.

Replaces Mailu + PMG with a lightweight built-in SMTP receiver.
Runs alongside FastAPI in a separate thread.
"""

import asyncio
import logging
from threading import Thread

from aiosmtpd.controller import Controller

from app.gateway.email_parser import parse_email
from app.gateway.router import process_email

logger = logging.getLogger(__name__)


class PhishingHandler:
    """aiosmtpd handler that feeds incoming emails into the AI cascade."""

    async def handle_DATA(self, server, session, envelope):
        """Called when a complete email is received via SMTP."""
        peer = session.peer
        mail_from = envelope.mail_from
        rcpt_tos = envelope.rcpt_tos
        raw_content = envelope.content

        logger.info(
            "[SMTP] Email received from %s (%s) → %s (%d bytes)",
            mail_from, peer, rcpt_tos, len(raw_content),
        )

        try:
            # Parse the raw email
            parsed = parse_email(raw_content)

            # Run through the AI cascade
            result = await process_email(parsed)

            logger.info(
                "[SMTP] Result for '%s' from %s: action=%s — %s",
                parsed.subject,
                parsed.sender,
                result.action.value,
                result.detail,
            )

            # Return SMTP status based on result
            if result.action in ("REJECT", "DELETE"):
                return "550 Message rejected: phishing detected"
            else:
                return "250 OK"

        except Exception as e:
            logger.error("[SMTP] Error processing email: %s", e, exc_info=True)
            # Accept the message anyway on error (don't lose emails)
            return "250 OK (processing error, accepted for review)"


def start_smtp_server(host: str = "0.0.0.0", port: int = 1025) -> Controller:
    """Start the aiosmtpd server in a background thread.

    Args:
        host: Bind address.
        port: SMTP port (1025 doesn't require root).

    Returns:
        The Controller instance (call .stop() to shut down).
    """
    handler = PhishingHandler()
    controller = Controller(handler, hostname=host, port=port)
    controller.start()
    logger.info("[SMTP] Server started on %s:%d", host, port)
    return controller

