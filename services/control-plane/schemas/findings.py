"""
Pydantic Schemas for Security Findings
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict


class FindingResponse(BaseModel):
    finding_id: str
    run_id: str
    tenant_id: str
    test_case_id: Optional[str] = None
    title: str
    severity: str
    cwe_id: str
    description: str
    redacted_proof: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FindingListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: List[FindingResponse]
