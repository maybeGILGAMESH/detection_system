"""Gateway module — email ingestion (SMTP + REST) and AI cascade orchestration.

Components:
  - smtp_handler : aiosmtpd-based SMTP receiver (port 1025)
  - email_parser : raw email bytes → ParsedEmail
  - router       : FastAPI endpoints + full L1→L2→L3 cascade
"""

from app.gateway.email_parser import parse_email
from app.gateway.router import process_email

__all__ = ["parse_email", "process_email"]

