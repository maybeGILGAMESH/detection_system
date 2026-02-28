"""LangGraph workflow for L3 deep investigation.

Graph:
  [START] → extract_urls → gather_evidence → judge_verdict → make_decision → [END]

Publishes real-time events for each step.
"""

import logging
import re

from app.schemas import Verdict, Label
from app.l3_orchestrator.state import InvestigationState
from app.l3_evidence.service import investigate_urls
from app.l3_judge.service import judge as judge_email
from app import events

logger = logging.getLogger(__name__)


# Graph Nodes

async def extract_urls(state: InvestigationState, email_id: str = "") -> InvestigationState:
    """Extract URLs from the email body and populate state.urls."""
    urls = set(state.email.urls)

    url_pattern = re.compile(r'https?://[^\s<>"\']+')
    found = url_pattern.findall(state.email.body)
    urls.update(found)

    if state.email.html_body:
        found_html = url_pattern.findall(state.email.html_body)
        urls.update(found_html)

    # Keep all URLs — even trusted domains may be spoofed in phishing
    state.urls = list(urls)[:5]
    logger.info("Extracted %d URLs for investigation: %s", len(state.urls), state.urls)

    await events.publish("l3_step", email_id, "L3", {
        "step": "extract_urls",
        "urls": state.urls,
        "message": f"Extracted {len(state.urls)} suspicious URLs for investigation",
    })
    return state


async def gather_evidence(state: InvestigationState, email_id: str = "") -> InvestigationState:
    """Gather evidence for all extracted URLs."""
    if not state.urls:
        logger.info("No URLs to investigate, skipping evidence gathering")
        await events.publish("l3_step", email_id, "L3", {
            "step": "gather_evidence",
            "message": "No suspicious URLs found — skipping evidence",
        })
        return state

    await events.publish("l3_step", email_id, "L3", {
        "step": "evidence_start",
        "message": f"Gathering evidence for {len(state.urls)} URLs (screenshot, DOM, WHOIS, SSL, Tranco)...",
        "urls": state.urls,
    })

    try:
        bundles = await investigate_urls(state.urls)
        state.evidence_bundles = bundles
        logger.info("Gathered evidence for %d URLs", len(bundles))

        # Publish evidence summary for each URL
        for b in bundles:
            evidence_data = {
                "step": "evidence_gathered",
                "url": b.url,
                "has_screenshot": bool(b.screenshot_base64),
                "error": b.error,
            }
            if b.dom_analysis:
                evidence_data["dom"] = {
                    "forms": b.dom_analysis.forms_count,
                    "password_fields": b.dom_analysis.has_password_field,
                    "external_scripts": len(b.dom_analysis.external_scripts),
                    "iframes": b.dom_analysis.iframes_count,
                }
            if b.whois:
                evidence_data["whois"] = {
                    "registrar": b.whois.registrar,
                    "domain_age_days": b.whois.domain_age_days,
                    "country": b.whois.country,
                    "creation_date": b.whois.creation_date,
                }
            if b.ssl:
                evidence_data["ssl"] = {
                    "issuer": b.ssl.issuer,
                    "is_valid": b.ssl.is_valid,
                    "valid_from": b.ssl.valid_from,
                    "valid_to": b.ssl.valid_to,
                }
            evidence_data["tranco_rank"] = b.tranco_rank
            evidence_data["redirects"] = b.redirect_chain[:10]
            # Include screenshot (truncated for WS bandwidth)
            if b.screenshot_base64:
                evidence_data["screenshot_b64"] = b.screenshot_base64[:5000]  # first ~3.7KB

            await events.publish("l3_evidence", email_id, "L3", evidence_data)

    except Exception as e:
        logger.error("Evidence gathering failed: %s", e)
        state.error = f"Evidence gathering failed: {e}"
        await events.publish("l3_step", email_id, "L3", {
            "step": "evidence_error",
            "message": str(e),
        })

    return state


async def judge_verdict(state: InvestigationState, email_id: str = "") -> InvestigationState:
    """Send evidence to DeepSeek Judge for Chain-of-Thought analysis."""
    evidence = None
    for bundle in state.evidence_bundles:
        if not bundle.error:
            evidence = bundle
            break

    if not evidence and state.evidence_bundles:
        evidence = state.evidence_bundles[0]

    await events.publish("l3_step", email_id, "L3", {
        "step": "judge_start",
        "message": "DeepSeek-R1 14B analyzing evidence with Chain-of-Thought reasoning...",
    })

    try:
        verdict = await judge_email(state.email, evidence, email_id=email_id)
        state.verdict = verdict
        logger.info("Judge verdict: %s (confidence=%.2f)", verdict.verdict, verdict.confidence)

        await events.publish("l3_judge_verdict", email_id, "L3", {
            "step": "judge_complete",
            "verdict": verdict.verdict.value,
            "confidence": round(verdict.confidence, 2),
            "reasoning": verdict.reasoning,
            "recommended_action": verdict.recommended_action.value,
        })

    except Exception as e:
        logger.error("Judge failed: %s", e)
        state.error = f"Judge failed: {e}"
        from app.schemas import JudgeVerdict
        state.verdict = JudgeVerdict(
            verdict=Label.PHISHING,
            confidence=0.5,
            reasoning=f"Judge error: {e}. Defaulting to phishing for safety.",
            recommended_action=Verdict.DELETE,
        )
        await events.publish("l3_step", email_id, "L3", {
            "step": "judge_error",
            "message": str(e),
        })

    return state


async def make_decision(state: InvestigationState, email_id: str = "") -> InvestigationState:
    """Make final RELEASE/DELETE/OPERATOR_REVIEW decision based on judge verdict."""
    if state.verdict is None:
        state.action = Verdict.DELETE
        logger.warning("No verdict available, defaulting to DELETE")
        return state

    if state.verdict.verdict == Label.UNCERTAIN:
        state.action = Verdict.OPERATOR_REVIEW
    elif state.verdict.verdict == Label.SAFE:
        state.action = Verdict.RELEASE
    else:
        state.action = Verdict.DELETE

    logger.info("Final decision: %s", state.action)
    return state


# Full Pipeline

async def run_investigation(email, email_id: str = "") -> InvestigationState:
    """Run the full L3 investigation pipeline.

    This is a simplified sequential pipeline (no LangGraph dependency required).
    If langgraph is installed, it can be upgraded to a proper graph.
    """
    state = InvestigationState(email=email)

    # Sequential pipeline: extract → evidence → judge → decide
    state = await extract_urls(state, email_id)
    state = await gather_evidence(state, email_id)
    state = await judge_verdict(state, email_id)
    state = await make_decision(state, email_id)

    return state
