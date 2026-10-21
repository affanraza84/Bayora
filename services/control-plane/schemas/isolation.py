"""
Pydantic Schemas for Isolation Lab & Verification Probes
"""

from datetime import datetime
from typing import Dict, Any
from pydantic import BaseModel, Field


class IsolationTestRequest(BaseModel):
    test_suite: str = Field(..., pattern="^(NETWORK_BOUNDARIES|EGRESS_GATING|TAMPER_SIMULATION)$")
    target_worker: str = Field(default="worker-red-team")
    parameters: Dict[str, Any] = Field(default_factory=dict)


class IsolationTestResponse(BaseModel):
    test_id: str
    test_suite: str
    target_worker: str
    result: str  # PASSED, FAILED
    details: Dict[str, Any]
    executed_at: datetime
