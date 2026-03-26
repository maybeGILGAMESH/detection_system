"""SSL certificate checker."""

import asyncio
import logging
import ssl
import socket
from datetime import datetime

from app.schemas import SSLInfo
from app.utils import extract_host

logger = logging.getLogger(__name__)


def _check_sync(host: str) -> SSLInfo:
    """Blocking SSL check — meant to be called via asyncio.to_thread."""
    info = SSLInfo()
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

                if cert:
                    issuer_parts = dict(x[0] for x in cert.get("issuer", []))
                    info.issuer = issuer_parts.get("organizationName", "")

                    subject_parts = dict(x[0] for x in cert.get("subject", []))
                    info.subject = subject_parts.get("commonName", "")

                    not_before = cert.get("notBefore", "")
                    not_after = cert.get("notAfter", "")

                    if not_before:
                        info.valid_from = not_before
                    if not_after:
                        info.valid_to = not_after

                    try:
                        nb = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                        na = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        now = datetime.utcnow()
                        info.is_valid = nb <= now <= na
                    except (ValueError, TypeError):
                        info.is_valid = True

    except ssl.SSLCertVerificationError:
        info.is_valid = False
        logger.info("SSL cert verification failed for %s", host)
    except Exception as e:
        logger.warning("SSL check failed for %s: %s", host, e)

    return info


async def check(url: str) -> SSLInfo:
    """Check SSL certificate for the URL's host (non-blocking)."""
    host = extract_host(url)
    return await asyncio.to_thread(_check_sync, host)
