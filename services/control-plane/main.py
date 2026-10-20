"""
Bayora Shield - Control Plane Service (FastAPI)
Foundation Entrypoint (Phase 1)
"""

from datetime import datetime, timezone
from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict

app = FastAPI(
    title="Bayora Shield Control Plane",
    description="Trusted control plane API for AI adversarial evaluation platform",
    version="0.1.0-phase1",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS configuration for Dashboard integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict to dashboard origin in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class HealthResponse(BaseModel):
    status: str
    timestamp: datetime
    services: Dict[str, str]
    version: str


@app.get(
    "/api/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    tags=["Diagnostics"],
    summary="System Health & Diagnostic Status",
)
async def get_health():
    """
    Returns platform health, component operational status, and API version.
    """
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now(timezone.utc),
        services={
            "database": "configured",
            "audit_service": "configured",
            "model_gateway": "configured",
        },
        version="0.1.0-phase1",
    )


# Note: Additional endpoints specified in docs/api-contract.md:
# - POST /api/runs
# - POST /api/runs/{id}/execute
# - GET /api/runs/{id}
# - GET /api/findings
# - POST /api/isolation-tests
# - GET /api/audit/events
# - POST /api/audit/verify
# are normative specifications scheduled for implementation in Phase 2.
