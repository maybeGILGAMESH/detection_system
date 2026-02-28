"""Shared Pydantic models used across all modules."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# Enums

class Verdict(str, Enum):
    REJECT = "REJECT"
    PROCEED = "PROCEED"
    DELIVER = "DELIVER"
    RELEASE = "RELEASE"
    DELETE = "DELETE"
    QUARANTINE = "QUARANTINE"
    OPERATOR_REVIEW = "OPERATOR_REVIEW"   # LLM uncertain → human operator


class Label(str, Enum):
    PHISHING = "phishing"
    SAFE = "safe"
    UNCERTAIN = "uncertain"               # Judge can't decide


# Parsed Email

class ParsedEmail(BaseModel):
    """Structured representation of an incoming email."""
    message_id: str = ""
    sender: str = ""
    recipient: str = ""
    subject: str = ""
    body: str = ""
    html_body: str = ""
    urls: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    raw: str = ""

    class Config:
        arbitrary_types_allowed = True


# L1

class L1CheckRequest(BaseModel):
    urls: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)


class CheckerResult(BaseModel):
    source: str
    is_malicious: bool = False
    detail: str = ""


class L1Result(BaseModel):
    verdict: Verdict
    results: list[CheckerResult] = Field(default_factory=list)


# L2

class L2ClassifyRequest(BaseModel):
    body: str
    subject: str = ""


class L2Result(BaseModel):
    confidence: float = Field(ge=0.0, le=1.0)
    label: Label


# L3 Evidence

class DOMAnalysis(BaseModel):
    forms_count: int = 0
    has_password_field: bool = False
    external_scripts: list[str] = Field(default_factory=list)
    external_links: list[str] = Field(default_factory=list)
    iframes_count: int = 0


class WHOISInfo(BaseModel):
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    country: str = ""
    domain_age_days: int = -1


class SSLInfo(BaseModel):
    issuer: str = ""
    subject: str = ""
    valid_from: str = ""
    valid_to: str = ""
    is_valid: bool = False


class EvidenceBundle(BaseModel):
    url: str
    screenshot_base64: str = ""
    dom_analysis: Optional[DOMAnalysis] = None
    whois: Optional[WHOISInfo] = None
    ssl: Optional[SSLInfo] = None
    tranco_rank: Optional[int] = None
    redirect_chain: list[str] = Field(default_factory=list)
    error: str = ""


# L3 Judge

class JudgeVerdict(BaseModel):
    verdict: Label
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str = ""
    recommended_action: Verdict = Verdict.DELETE


# Pipeline Result

class ProcessResult(BaseModel):
    action: Verdict
    l1_result: Optional[L1Result] = None
    l2_result: Optional[L2Result] = None
    l3_verdict: Optional[JudgeVerdict] = None
    detail: str = ""
    email_id: str = ""                    # for operator lookup


# Operator Review

class OperatorDecision(BaseModel):
    """Operator's manual classification for an uncertain email."""
    email_id: str
    operator_label: Label                 # phishing / safe
    comment: str = ""


class OperatorPendingItem(BaseModel):
    """An email awaiting operator review."""
    email_id: str
    sender: str = ""
    recipient: str = ""
    subject: str = ""
    body_preview: str = ""
    urls: list[str] = Field(default_factory=list)
    l2_confidence: float = 0.0
    l3_confidence: float = 0.0
    l3_reasoning: str = ""
    evidence_summary: str = ""
    timestamp: float = 0.0


# User Inbox

class InboxItem(BaseModel):
    """Email delivered to user inbox with AI summary."""
    email_id: str
    sender: str = ""
    subject: str = ""
    body_preview: str = ""
    summary: str = ""
    safety_note: str = ""
    action: Verdict = Verdict.DELIVER
    timestamp: float = 0.0
