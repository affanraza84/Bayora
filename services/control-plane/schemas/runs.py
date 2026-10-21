"""
Pydantic Schemas for Evaluation Runs
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field


class RunCreate(BaseModel):
    target_model: str = Field(default="gpt-4o-mini-mock", min_length=2, max_length=100)
    policy_version_id: Optional[str] = None
    suite_categories: List[str] = Field(
        default=["PROMPT_INJECTION", "JAILBREAK", "SYSTEM_PROMPT_LEAK"]
    )
    max_concurrency: int = Field(default=2, ge=1, le=10)
    timeout_seconds: int = Field(default=300, ge=10, le=3600)


class RunExecuteRequest(BaseModel):
    dry_run: bool = False


class RunProgress(BaseModel):
    total_tests: int
    completed_tests: int
    blocked_count: int
    breach_count: int


class RunResponse(BaseModel):
    run_id: str
    tenant_id: str
    status: str
    target_model: str
    policy_version_id: Optional[str] = None
    policy_version_label: Optional[str] = "v1.0-default"
    total_tests: int = 0
    blocked_count: int = 0
    breach_count: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


class RunDetailResponse(RunResponse):
    progress: RunProgress


class RunListResponse(BaseModel):
    total: int
    items: List[RunResponse]
