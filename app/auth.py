"""Simple API-key authentication for critical operator endpoints."""

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader

from app.config import settings

_api_key_header = APIKeyHeader(name="X-Operator-Key", auto_error=False)


async def require_operator_key(
    api_key: str | None = Security(_api_key_header),
) -> None:
    """Dependency that enforces OPERATOR_API_KEY when it is configured.

    If OPERATOR_API_KEY is empty/unset, authentication is bypassed
    (convenient for local development).
    """
    expected = settings.operator_api_key
    if not expected:
        return  # auth disabled
    if api_key != expected:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing X-Operator-Key header",
        )
