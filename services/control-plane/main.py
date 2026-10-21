"""
Bayora Shield - Control Plane Service (FastAPI)
Functional Security Core & API Orchestrator (Phase 2)
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from services.control_plane.config import settings
from services.control_plane.db.session import init_db
from services.control_plane.routers import (
    health,
    auth,
    runs,
    findings,
    isolation,
    audit,
    performance,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure database schema is ready on startup
    await init_db()
    yield


app = FastAPI(
    title="Bayora Shield Control Plane",
    description="Trusted control plane API for AI adversarial evaluation platform with multi-enclave isolation and tamper-evident audit logging.",
    version="0.2.0-phase2",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS middleware for Next.js dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS + ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(health.router)
app.include_router(auth.router)
app.include_router(runs.router)
app.include_router(findings.router)
app.include_router(isolation.router)
app.include_router(audit.router)
app.include_router(performance.router)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Sanitizes unhandled exceptions to prevent database connection string or
    internal stack trace leakage in accordance with Threat 9 (Credential Leakage).
    """
    # Return structured error response without internal details
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal server error occurred. Transaction rolled back.",
            "type": "InternalServerError",
        },
    )
