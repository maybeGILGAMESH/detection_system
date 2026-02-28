"""L1 Threat Intel — FastAPI router."""

from fastapi import APIRouter

from app.schemas import L1CheckRequest, L1Result
from app.l1_threat_intel import service

router = APIRouter(prefix="/api/v1/l1", tags=["L1 Threat Intel"])


@router.post("/check", response_model=L1Result)
async def check_threats(request: L1CheckRequest) -> L1Result:
    """Check URLs / IPs / domains against threat intelligence sources."""
    return await service.check(request)

