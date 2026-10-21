"""
Pydantic Schemas for Evaluation Runs
Explicitly distinguishes input blocks, output redactions, model safety findings,
and infrastructure escapes to avoid conflating model vulnerabilities with container escapes.
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict


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
    input_blocked_count: int = 0
    output_redacted_count: int = 0
    model_safety_findings_count: int = 0
    infrastructure_escape_count: int = 0


class RunResponse(BaseModel):
    run_id: str
    tenant_id: str
    status: str
    target_model: str
    policy_version_id: Optional[str] = None
    policy_version_label: Optional[str] = "v1.0-default"
    total_tests: int = 0
    blocked_count: int = 0
    # Explicit semantic fields
    input_blocked_count: int = 0
    output_redacted_count: int = 0
    model_safety_findings_count: int = 0
    infrastructure_escape_count: int = 0
    # Backward-compatible mapping: breach_count == model_safety_findings_count
    breach_count: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RunDetailResponse(RunResponse):
    progress: RunProgress


class RunListResponse(BaseModel):
    total: int
    items: List[RunResponse]


class EvidenceVerifyResponse(BaseModel):
    verification_status: str
    run_id: str
    bundle_checksum_sha256: str
    signer_key_id: str
    is_trusted_key: bool
    ed25519_signature_valid: bool
    chain_root_hash_matches: bool
    verified_at: datetime
    message: str
