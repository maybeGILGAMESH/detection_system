"""Gateway — main cascade router (L1 → L2 → L3).

Implements the full email processing pipeline from the UML diagram.
Publishes real-time events for the dashboard via WebSocket.
Handles: DELIVER, RELEASE, REJECT, DELETE, OPERATOR_REVIEW.

Uses asyncio.Semaphore to limit concurrent L3 investigations (GPU bound).
"""

import asyncio
import logging
import hashlib
import time

from fastapi import APIRouter

from app.config import settings
from app.schemas import (
    ParsedEmail,
    ProcessResult,
    Verdict,
    Label,
    L1CheckRequest,
)
from app.l1_threat_intel import service as l1_service
from app.l2_classifier import service as l2_service
from app.l3_orchestrator.graph import run_investigation
from app.gateway.email_parser import parse_email
from app import events
from app import operator_store
from app.layer_toggle import is_enabled

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Gateway"])

# Concurrency control: max 1 L3 investigation at a time (GPU-bound)
_l3_semaphore = asyncio.Semaphore(1)

# Queue counter — show how many are waiting
_l3_queue_depth = 0


def _email_id(email: ParsedEmail) -> str:
    """Generate a short unique ID for an email."""
    data = f"{email.sender}:{email.subject}:{time.time()}"
    return hashlib.md5(data.encode()).hexdigest()[:12]


async def _summarize_for_inbox(email: ParsedEmail, action: Verdict, eid: str, detail: str):
    """Summarize email and add to user inbox (for DELIVER / RELEASE emails)."""
    if action not in (Verdict.DELIVER, Verdict.RELEASE):
        return

    try:
        from app.l3_judge.service import summarize_email
        summary = await summarize_email(email)
    except Exception:
        summary = email.body[:150] + "..." if email.body else email.subject

    l1_on, l2_on, l3_on = is_enabled("L1"), is_enabled("L2"), is_enabled("L3")
    active = [x for x, on in [("L1", l1_on), ("L2", l2_on), ("L3", l3_on)] if on]
    layers_str = " → ".join(active) if active else "none"

    if action == Verdict.DELIVER:
        if "L3 disabled" in detail or "no analysis" in detail:
            safety_note = f"📬 Delivered (layers active: {layers_str}) — {detail}"
        else:
            safety_note = f"✅ Verified safe by L2 classifier (layers active: {layers_str})"
    elif action == Verdict.RELEASE:
        safety_note = f"✅ Deep investigation complete — safe by L3 judge (layers active: {layers_str})"
    else:
        safety_note = f"📬 Delivered (layers active: {layers_str})"

    operator_store.add_to_inbox(eid, email, action, summary, safety_note)

    await events.publish("inbox_update", eid, "inbox", {
        "sender": email.sender,
        "subject": email.subject,
        "summary": summary,
        "safety_note": safety_note,
        "action": action.value,
    })


async def _run_l3_with_queue(email: ParsedEmail, eid: str) -> "InvestigationState":
    """Run L3 investigation with semaphore to prevent GPU overload."""
    global _l3_queue_depth
    _l3_queue_depth += 1

    if _l3_queue_depth > 1:
        logger.info("L3 queue: %d emails waiting (email %s queued)", _l3_queue_depth, eid)
        await events.publish("l3_step", eid, "L3", {
            "step": "queued",
            "message": f"Queued — {_l3_queue_depth - 1} email(s) ahead in L3 pipeline",
        })

    try:
        async with _l3_semaphore:
            return await run_investigation(email, email_id=eid)
    finally:
        _l3_queue_depth -= 1


async def process_email(email: ParsedEmail) -> ProcessResult:
    """Run the AI cascade with respect to layer toggles.

    Active layers are checked via is_enabled(). Disabled layers are skipped.
    Combinations:
      - All on:  L1 → L2 → L3 (normal)
      - L1 off:  Skip threat intel, go to L2
      - L2 off:  Skip classifier, everything goes to L3 (or delivers)
      - L3 off:  Grey zone delivers without deep investigation
      - None on: Everything passes through (deliver all)
    """
    eid = _email_id(email)
    t0 = time.time()
    l1_on, l2_on, l3_on = is_enabled("L1"), is_enabled("L2"), is_enabled("L3")
    active_layers = [x for x in ["L1", "L2", "L3"] if {"L1": l1_on, "L2": l2_on, "L3": l3_on}[x]]

    # Event: email received
    await events.publish("email_received", eid, "gateway", {
        "sender": email.sender,
        "recipient": email.recipient,
        "subject": email.subject,
        "urls_count": len(email.urls),
        "ips_count": len(email.ips),
        "domains_count": len(email.domains),
        "body_preview": email.body[:200] if email.body else "",
        "active_layers": active_layers,
    })

    l1_result = None
    l2_result = None

    # -- L1: Threat Intel --
    if l1_on:
        logger.info("L1: Threat Intel check")
        await events.publish("layer_start", eid, "L1", {
            "message": "Checking URL/IP/domain reputation...",
            "urls": email.urls[:5],
            "ips": email.ips[:5],
            "domains": email.domains[:5],
        })

        l1_result = await l1_service.check(
            L1CheckRequest(urls=email.urls, ips=email.ips, domains=email.domains)
        )

        await events.publish("layer_result", eid, "L1", {
            "verdict": l1_result.verdict.value,
            "checks_count": len(l1_result.results),
            "malicious_count": sum(1 for r in l1_result.results if r.is_malicious),
            "results": [
                {"source": r.source, "is_malicious": r.is_malicious, "detail": r.detail}
                for r in l1_result.results
            ],
        })

        if l1_result.verdict == Verdict.REJECT:
            logger.warning("L1 REJECT: known phishing detected for email from %s", email.sender)
            result = ProcessResult(
                action=Verdict.REJECT,
                l1_result=l1_result,
                detail="Blocked by L1: known malicious URL/IP/domain",
                email_id=eid,
            )
            await events.publish("final_verdict", eid, "L1", {
                "action": result.action.value,
                "detail": result.detail,
                "stopped_at": "L1",
                "elapsed": round(time.time() - t0, 2),
            })
            return result
    else:
        logger.info("L1: DISABLED (skipped)")
        await events.publish("layer_start", eid, "L1", {"message": "⏭ L1 Threat Intel — DISABLED (skipped)"})
        await events.publish("layer_result", eid, "L1", {"verdict": "SKIPPED", "checks_count": 0, "malicious_count": 0, "results": []})

    # -- L2: Classifier --
    if l2_on:
        logger.info("L2: DistilBERT classifier")
        await events.publish("layer_start", eid, "L2", {
            "message": "Running DistilBERT text classification...",
        })

        l2_result = await l2_service.classify(body=email.body, subject=email.subject)

        await events.publish("layer_result", eid, "L2", {
            "label": l2_result.label.value,
            "confidence": round(l2_result.confidence, 4),
            "safe_pct": round(l2_result.confidence * 100, 1),
            "phish_pct": round((1 - l2_result.confidence) * 100, 1),
            "zone": "safe" if l2_result.confidence > settings.l2_safe_threshold
                    else "phishing" if l2_result.confidence < settings.l2_phish_threshold
                    else "grey",
        })

        if l2_result.confidence > settings.l2_safe_threshold:
            logger.info("L2 DELIVER: high confidence safe (%.3f)", l2_result.confidence)
            result = ProcessResult(
                action=Verdict.DELIVER,
                l1_result=l1_result,
                l2_result=l2_result,
                detail=f"Safe (L2 confidence={l2_result.confidence:.3f})",
                email_id=eid,
            )
            await events.publish("final_verdict", eid, "L2", {
                "action": result.action.value,
                "detail": result.detail,
                "stopped_at": "L2",
                "elapsed": round(time.time() - t0, 2),
            })
            await _summarize_for_inbox(email, Verdict.DELIVER, eid, result.detail)
            return result

        if l2_result.confidence < settings.l2_phish_threshold:
            logger.warning(
                "L2 REJECT: low confidence (%.3f) → obvious phishing",
                l2_result.confidence,
            )
            result = ProcessResult(
                action=Verdict.REJECT,
                l1_result=l1_result,
                l2_result=l2_result,
                detail=f"Phishing (L2 confidence={l2_result.confidence:.3f})",
                email_id=eid,
            )
            await events.publish("final_verdict", eid, "L2", {
                "action": result.action.value,
                "detail": result.detail,
                "stopped_at": "L2",
                "elapsed": round(time.time() - t0, 2),
            })
            return result

        # L2 grey zone → fall through to L3
    else:
        logger.info("L2: DISABLED (skipped)")
        await events.publish("layer_start", eid, "L2", {"message": "⏭ L2 Classifier — DISABLED (skipped)"})
        await events.publish("layer_result", eid, "L2", {"label": "skipped", "confidence": 0.5, "safe_pct": 50, "phish_pct": 50, "zone": "grey"})

    # -- L3: Deep Investigation --
    if l3_on:
        conf_str = f" (L2 confidence={l2_result.confidence:.3f})" if l2_result else " (L2 disabled)"
        logger.info("Grey Zone%s -> L3 deep investigation", conf_str)
        await events.publish("layer_start", eid, "L3", {
            "message": f"Grey zone{conf_str} → Deep Investigation",
            "confidence": round(l2_result.confidence, 4) if l2_result else 0.5,
        })

        # Run L3 with concurrency control (semaphore)
        state = await _run_l3_with_queue(email, eid)

        # Handle L3 outcomes
        if state.verdict and state.verdict.recommended_action == Verdict.OPERATOR_REVIEW:
            logger.warning("L3 UNCERTAIN: judge can't decide → operator review")
            result = ProcessResult(
                action=Verdict.OPERATOR_REVIEW,
                l1_result=l1_result,
                l2_result=l2_result,
                l3_verdict=state.verdict,
                detail="Judge uncertain — escalated to human operator",
                email_id=eid,
            )

            evidence_summary = ""
            if state.evidence_bundles:
                b = state.evidence_bundles[0]
                parts = []
                if b.whois and b.whois.domain_age_days >= 0:
                    parts.append(f"Domain age: {b.whois.domain_age_days} days")
                if b.tranco_rank:
                    parts.append(f"Tranco: #{b.tranco_rank}")
                else:
                    parts.append("Not in Tranco Top 1M")
                if b.dom_analysis:
                    parts.append(f"Forms: {b.dom_analysis.forms_count}, Password: {b.dom_analysis.has_password_field}")
                evidence_summary = " | ".join(parts)

            operator_store.add_pending(
                eid, email, l2_result, state.verdict, evidence_summary
            )

            await events.publish("final_verdict", eid, "L3", {
                "action": "OPERATOR_REVIEW",
                "detail": result.detail,
                "stopped_at": "L3",
                "elapsed": round(time.time() - t0, 2),
                "judge_verdict": "uncertain",
                "judge_confidence": round(state.verdict.confidence, 2) if state.verdict else 0,
                "judge_reasoning": state.verdict.reasoning if state.verdict else "",
            })
            return result

        elif state.action == Verdict.RELEASE:
            logger.info("L3 RELEASE: judge says safe")
            result = ProcessResult(
                action=Verdict.RELEASE,
                l1_result=l1_result,
                l2_result=l2_result,
                l3_verdict=state.verdict,
                detail="Released after L3 investigation (judge: safe)",
                email_id=eid,
            )
            await events.publish("final_verdict", eid, "L3", {
                "action": result.action.value,
                "detail": result.detail,
                "stopped_at": "L3",
                "elapsed": round(time.time() - t0, 2),
                "judge_verdict": state.verdict.verdict.value if state.verdict else "",
                "judge_confidence": round(state.verdict.confidence, 2) if state.verdict else 0,
                "judge_reasoning": state.verdict.reasoning if state.verdict else "",
            })
            await _summarize_for_inbox(email, Verdict.RELEASE, eid, result.detail)
            return result

        else:
            logger.warning("L3 DELETE: judge says phishing")
            result = ProcessResult(
                action=Verdict.DELETE,
                l1_result=l1_result,
                l2_result=l2_result,
                l3_verdict=state.verdict,
                detail="Deleted after L3 investigation (judge: phishing)",
                email_id=eid,
            )
            await events.publish("final_verdict", eid, "L3", {
                "action": result.action.value,
                "detail": result.detail,
                "stopped_at": "L3",
                "elapsed": round(time.time() - t0, 2),
                "judge_verdict": state.verdict.verdict.value if state.verdict else "",
                "judge_confidence": round(state.verdict.confidence, 2) if state.verdict else 0,
                "judge_reasoning": state.verdict.reasoning if state.verdict else "",
            })
            return result

    else:
        logger.info("L3: DISABLED (skipped)")
        await events.publish("layer_start", eid, "L3", {"message": "⏭ L3 Judge — DISABLED (skipped)"})

        # L3 disabled: deliver grey zone with a note
        if l2_result and l2_result.confidence < settings.l2_phish_threshold:
            detail = f"Delivered (L3 disabled, L2 confidence={l2_result.confidence:.3f})"
        elif l2_result:
            detail = f"Delivered — grey zone, L3 disabled (L2 confidence={l2_result.confidence:.3f})"
        else:
            detail = "Delivered — all AI layers disabled, no analysis performed"

        result = ProcessResult(
            action=Verdict.DELIVER,
            l1_result=l1_result,
            l2_result=l2_result,
            detail=detail,
            email_id=eid,
        )
        await events.publish("final_verdict", eid, "L3", {
            "action": result.action.value,
            "detail": result.detail,
            "stopped_at": "L3-disabled",
            "elapsed": round(time.time() - t0, 2),
        })
        await _summarize_for_inbox(email, Verdict.DELIVER, eid, result.detail)
        return result


# API Endpoints

@router.post("/api/v1/process", response_model=ProcessResult)
async def process_email_endpoint(email: ParsedEmail) -> ProcessResult:
    """Process a pre-parsed email through the AI cascade."""
    return await process_email(email)


@router.post("/api/v1/process_raw")
async def process_raw_email(raw_body: bytes) -> ProcessResult:
    """Process raw email bytes (EML format) through the AI cascade."""
    email = parse_email(raw_body)
    return await process_email(email)


@router.get("/health")
async def health():
    """Health check endpoint with component status."""
    from app.l2_classifier import service as l2_svc
    l2_loaded = l2_svc._model is not None

    from app.l3_judge import service as l3_svc
    l3_loaded = l3_svc._llm is not None

    from app.layer_toggle import get_layers
    pending = operator_store.get_decision_count()

    return {
        "status": "ok",
        "service": "detect_email",
        "l2_loaded": l2_loaded,
        "l3_loaded": l3_loaded,
        "operator_pending": len(operator_store.get_pending()),
        "operator_decisions": pending,
        "l3_queue": _l3_queue_depth,
        "layers": get_layers(),
    }
