"""L3 Orchestrator — FastAPI router."""

from fastapi import APIRouter
from pydantic import BaseModel

from app.schemas import ParsedEmail, Verdict
from app.l3_orchestrator.graph import run_investigation

router = APIRouter(prefix="/api/v1/l3", tags=["L3 Orchestrator"])


class InvestigateRequest(BaseModel):
    email: ParsedEmail


class InvestigateResponse(BaseModel):
    action: Verdict
    verdict_label: str = ""
    confidence: float = 0.0
    reasoning: str = ""
    evidence_count: int = 0
    error: str = ""


@router.post("/investigate", response_model=InvestigateResponse)
async def investigate(request: InvestigateRequest) -> InvestigateResponse:
    """Run full L3 investigation on an email."""
    state = await run_investigation(request.email)

    return InvestigateResponse(
        action=state.action,
        verdict_label=state.verdict.verdict.value if state.verdict else "",
        confidence=state.verdict.confidence if state.verdict else 0.0,
        reasoning=state.verdict.reasoning if state.verdict else "",
        evidence_count=len(state.evidence_bundles),
        error=state.error,
    )

