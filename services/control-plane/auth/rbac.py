"""
Bayora Shield - Role-Based Access Control (RBAC) & Tenant Isolation Module
Defines permission sets and guards against unauthorized actions and IDOR vulnerabilities.
"""

from typing import List, Set, Callable
from fastapi import HTTPException, status, Depends
from services.control_plane.auth.jwt import SecurityContext, get_current_user

# Permission sets per docs/access-control-matrix.md
ROLE_PERMISSIONS: dict[str, Set[str]] = {
    "platform_admin": {
        "run:create",
        "run:execute",
        "run:view",
        "run:delete",
        "finding:view",
        "finding:create",
        "policy:read:blue",
        "policy:write:blue",
        "artifact:read:red",
        "artifact:write:red",
        "artifact:read:blue",
        "artifact:write:blue",
        "audit:view",
        "audit:verify",
        "audit:append",
        "isolation:test",
        "tenant:admin",
    },
    "auditor": {
        "run:view",
        "finding:view",
        "audit:view",
        "audit:verify",
        "isolation:test",
    },
    "red_lead": {
        "run:create",
        "run:execute",
        "run:view",
        "finding:view",
        "finding:create",
        "artifact:read:red",
        "artifact:write:red",
        "audit:view",
        "audit:verify",
    },
    "red_operator": {
        "run:view",
        "finding:view",
        "finding:create",
        "artifact:read:red",
        "audit:view",
    },
    "blue_lead": {
        "run:create",
        "run:execute",
        "run:view",
        "finding:view",
        "policy:read:blue",
        "policy:write:blue",
        "artifact:read:blue",
        "artifact:write:blue",
        "audit:view",
        "audit:verify",
    },
    "blue_operator": {
        "run:view",
        "finding:view",
        "policy:read:blue",
        "artifact:read:blue",
        "audit:view",
    },
    "svc:evaluator": {
        "run:execute",
        "run:view",
        "run:finalize",
        "finding:create",
        "audit:append",
        "audit:view",
        "model:infer",
    },
    "svc:control-plane": {
        "run:create",
        "run:execute",
        "run:view",
        "audit:append",
        "audit:view",
        "audit:verify",
    },
}


def require_permissions(*required_permissions: str) -> Callable[[SecurityContext], SecurityContext]:
    """
    FastAPI dependency factory to verify the authenticated user has all specified permissions.
    """
    async def permission_checker(
        current_user: SecurityContext = Depends(get_current_user),
    ) -> SecurityContext:
        user_perms = ROLE_PERMISSIONS.get(current_user.role, set())
        for perm in required_permissions:
            if perm not in user_perms:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Forbidden: Role '{current_user.role}' lacks required permission '{perm}'",
                )
        return current_user

    return permission_checker


def enforce_tenant_boundary(current_user: SecurityContext, resource_tenant_id: str) -> None:
    """
    Guarantees tenant isolation: Prevents Insecure Direct Object References (IDOR).
    Platform admins can inspect across tenants; all other roles are strictly partitioned.
    """
    if current_user.role == "platform_admin":
        return

    if current_user.tenant_id != resource_tenant_id:
        # Return 403 Forbidden to clearly indicate cross-tenant boundary breach
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Cannot access resources belonging to another tenant",
        )
