"""
Authentication Router
Development token issuance endpoint for prototyping and automated tests.
"""

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from services.control_plane.auth.jwt import create_access_token

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


class TokenRequest(BaseModel):
    user_id: str = Field(..., min_length=2, max_length=100)
    tenant_id: str = Field(..., min_length=2, max_length=100)
    role: str = Field(..., pattern="^(platform_admin|auditor|red_lead|red_operator|blue_lead|blue_operator|svc:evaluator|svc:control-plane)$")
    email: str = Field(default="")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    tenant_id: str
    role: str
    expires_in_minutes: int = 60


@router.post(
    "/token",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Issue Development JWT (Hackathon Prototype Identity)",
)
async def issue_token(body: TokenRequest):
    """
    Issues a signed JWT with strict issuer, audience, tenant scoping, and expiration claims.
    """
    token = create_access_token(
        user_id=body.user_id,
        tenant_id=body.tenant_id,
        role=body.role,
        email=body.email or f"{body.user_id}@bayora.io",
    )
    return TokenResponse(
        access_token=token,
        user_id=body.user_id,
        tenant_id=body.tenant_id,
        role=body.role,
    )
