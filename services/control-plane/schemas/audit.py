"""
Pydantic Schemas for Audit Trail & Verification
"""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field, ConfigDict


class AuditEventResponse(BaseModel):
    sequence_number: int
    event_id: str
    tenant_id: str
    actor: str
    action: str
    resource: str
    decision: str
    timestamp: datetime
    policy_version: str
    payload_digest: str
    previous_hash: str
    event_hash: str

    model_config = ConfigDict(from_attributes=True)


class AuditListResponse(BaseModel):
    total_events: int
    returned_events: int
    events: List[AuditEventResponse]


class AuditCheckpointCreateRequest(BaseModel):
    start_sequence: int = Field(default=1, ge=1)
    end_sequence: Optional[int] = Field(default=None, ge=1)


class AuditCheckpointResponse(BaseModel):
    checkpoint_id: str
    tenant_id: str
    start_sequence: int
    end_sequence: int
    root_hash: str
    timestamp: datetime
    signer_key_id: str
    ed25519_signature: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AuditVerifyRequest(BaseModel):
    start_sequence: int = Field(default=1, ge=1)
    end_sequence: Optional[int] = Field(default=None, ge=1)
    verify_ed25519_signatures: bool = Field(default=True)


class AuditVerifyResponse(BaseModel):
    verification_status: str
    events_evaluated: int
    hash_chain_continuity: str
    ed25519_signature_status: str
    root_hash: str
    verified_at: datetime
    signer_key_id: Optional[str] = None
    checkpoint_id: Optional[str] = None
    checkpoints_evaluated: int = 0
    error_code: Optional[str] = None
    broken_sequence_number: Optional[int] = None
    message: Optional[str] = None
