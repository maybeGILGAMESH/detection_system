"""L3 Judge — FastAPI router."""

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.schemas import JudgeVerdict, ParsedEmail, EvidenceBundle
from app.l3_judge import service

router = APIRouter(prefix="/api/v1/l3", tags=["L3 Judge"])


class JudgeRequest(BaseModel):
    email: ParsedEmail
    evidence: EvidenceBundle | None = None


@router.post("/judge", response_model=JudgeVerdict)
async def judge_email(request: JudgeRequest) -> JudgeVerdict:
    """Analyze email + evidence and return a verdict."""
    return await service.judge(email=request.email, evidence=request.evidence)

