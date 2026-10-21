"""
Security Findings Router
Lists confirmed vulnerabilities with tenant scoping, severity filtering, and pagination.
"""

from typing import Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from services.control_plane.db.session import get_db
from services.control_plane.db.models import Finding
from services.control_plane.auth.jwt import SecurityContext
from services.control_plane.auth.rbac import require_permissions
from services.control_plane.schemas.findings import FindingResponse, FindingListResponse

router = APIRouter(prefix="/api/findings", tags=["Findings"])


@router.get(
    "",
    response_model=FindingListResponse,
    status_code=status.HTTP_200_OK,
    summary="List Security Findings",
)
async def list_findings(
    run_id: Optional[str] = Query(None, description="Filter by evaluation run ID"),
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, etc)"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: SecurityContext = Depends(require_permissions("finding:view")),
    db: AsyncSession = Depends(get_db),
):
    """
    Lists confirmed findings with tenant scoping.
    Platform admins can inspect across tenants; all other roles only see findings for their own tenant.
    """
    query = select(Finding).order_by(desc(Finding.created_at))

    if current_user.role != "platform_admin":
        query = query.where(Finding.tenant_id == current_user.tenant_id)

    if run_id:
        query = query.where(Finding.run_id == run_id)
    if severity:
        query = query.where(Finding.severity == severity.upper())

    # Count total matching query
    count_query = select(Finding)
    if current_user.role != "platform_admin":
        count_query = count_query.where(Finding.tenant_id == current_user.tenant_id)
    if run_id:
        count_query = count_query.where(Finding.run_id == run_id)
    if severity:
        count_query = count_query.where(Finding.severity == severity.upper())

    all_res = await db.execute(count_query)
    total = len(all_res.scalars().all())

    # Paginate
    paged_query = query.offset(offset).limit(limit)
    res = await db.execute(paged_query)
    items = res.scalars().all()

    resp_items = [
        FindingResponse(
            finding_id=f.id,
            run_id=f.run_id,
            tenant_id=f.tenant_id,
            test_case_id=f.test_case_id,
            title=f.title,
            severity=f.severity,
            cwe_id=f.cwe_id,
            description=f.description,
            redacted_proof=f.redacted_proof,
            created_at=f.created_at,
        )
        for f in items
    ]

    return FindingListResponse(
        total=total,
        limit=limit,
        offset=offset,
        items=resp_items,
    )
