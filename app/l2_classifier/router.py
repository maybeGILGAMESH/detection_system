"""L2 Classifier — FastAPI router."""

from fastapi import APIRouter

from app.schemas import L2ClassifyRequest, L2Result
from app.l2_classifier import service

router = APIRouter(prefix="/api/v1/l2", tags=["L2 Classifier"])


@router.post("/classify", response_model=L2Result)
async def classify_email(request: L2ClassifyRequest) -> L2Result:
    """Classify email text as phishing or safe."""
    return await service.classify(body=request.body, subject=request.subject)

