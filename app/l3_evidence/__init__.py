"""L3 Evidence Agent — collects technical evidence for suspicious URLs.

Tools (all async, run in parallel):
  - screenshot   : Playwright-based page capture + redirect chain
  - dom_analyzer : forms, password fields, external scripts, iframes
  - whois_lookup : domain registration info + age
  - ssl_checker  : certificate validity and issuer
  - tranco_check : Tranco Top-1M domain whitelist

Entry point: service.investigate_url(url) → EvidenceBundle
"""

from app.l3_evidence.service import investigate_url, investigate_urls

__all__ = ["investigate_url", "investigate_urls"]

