"""State definition for the L3 investigation pipeline."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from app.schemas import ParsedEmail, EvidenceBundle, JudgeVerdict, Verdict


class InvestigationState(BaseModel):
    """State passed through the L3 investigation pipeline."""

    # Input
    email: ParsedEmail

    # Extracted URLs to investigate
    urls: list[str] = Field(default_factory=list)

    # URLs decoded from QR code images embedded in the email
    qr_urls: list[str] = Field(default_factory=list)

    # Evidence gathered for each URL
    evidence_bundles: list[EvidenceBundle] = Field(default_factory=list)

    # Judge verdict
    verdict: Optional[JudgeVerdict] = None

    # Final action
    action: Verdict = Verdict.QUARANTINE

    # Error tracking
    error: str = ""

