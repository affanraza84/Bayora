"""
Unit tests for Authentication & Role-Based Access Control (RBAC).
Validates missing/invalid/expired tokens, role permissions, and cross-tenant isolation.
"""

import unittest
from datetime import timedelta
from fastapi import HTTPException
from services.control_plane.auth.jwt import (
    create_access_token,
    decode_access_token,
)
from services.control_plane.auth.rbac import (
    ROLE_PERMISSIONS,
    require_permissions,
    enforce_tenant_boundary,
)
import asyncio


class TestAuthRBAC(unittest.TestCase):
    def test_valid_token_decoding(self):
        token = create_access_token(
            user_id="usr-123",
            tenant_id="tenant-alpha",
            role="red_lead",
            email="redlead@bayora.io",
        )
        ctx = decode_access_token(token)
        self.assertEqual(ctx.user_id, "usr-123")
        self.assertEqual(ctx.tenant_id, "tenant-alpha")
        self.assertEqual(ctx.role, "red_lead")
        self.assertEqual(ctx.email, "redlead@bayora.io")

    def test_expired_token_rejected(self):
        # Create token that expired 10 minutes ago
        expired_token = create_access_token(
            user_id="usr-expired",
            tenant_id="tenant-alpha",
            role="red_lead",
            expires_delta=timedelta(minutes=-10),
        )
        with self.assertRaises(HTTPException) as cm:
            decode_access_token(expired_token)
        self.assertEqual(cm.exception.status_code, 401)
        self.assertIn("expired", cm.exception.detail.lower())

    def test_invalid_signature_rejected(self):
        token = create_access_token(
            user_id="usr-valid",
            tenant_id="tenant-alpha",
            role="red_lead",
        )
        # Mutate signature characters
        parts = token.split(".")
        tampered_sig = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
        tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"

        with self.assertRaises(HTTPException) as cm:
            decode_access_token(tampered_token)
        self.assertEqual(cm.exception.status_code, 401)

    def test_missing_or_malformed_token_rejected(self):
        with self.assertRaises(HTTPException) as cm:
            decode_access_token("not-a-real-jwt")
        self.assertEqual(cm.exception.status_code, 401)

    def test_unauthorized_role_access(self):
        # red_operator lacks 'run:create'
        checker = require_permissions("run:create")
        token = create_access_token(
            user_id="usr-operator",
            tenant_id="tenant-alpha",
            role="red_operator",
        )
        ctx = decode_access_token(token)

        with self.assertRaises(HTTPException) as cm:
            asyncio.run(checker(current_user=ctx))
        self.assertEqual(cm.exception.status_code, 403)
        self.assertIn("lacks required permission", cm.exception.detail)

    def test_cross_team_artifact_isolation(self):
        # Red Lead cannot read Blue policies
        blue_checker = require_permissions("policy:read:blue")
        red_ctx = decode_access_token(
            create_access_token(user_id="red", tenant_id="t1", role="red_lead")
        )
        with self.assertRaises(HTTPException) as cm:
            asyncio.run(blue_checker(current_user=red_ctx))
        self.assertEqual(cm.exception.status_code, 403)

        # Blue Lead cannot read Red raw artifacts
        red_checker = require_permissions("artifact:read:red")
        blue_ctx = decode_access_token(
            create_access_token(user_id="blue", tenant_id="t1", role="blue_lead")
        )
        with self.assertRaises(HTTPException) as cm:
            asyncio.run(red_checker(current_user=blue_ctx))
        self.assertEqual(cm.exception.status_code, 403)

    def test_cross_tenant_access_denied(self):
        tenant_a_user = decode_access_token(
            create_access_token(user_id="user-a", tenant_id="tenant-A", role="red_lead")
        )
        # Attempt to access resource owned by tenant-B
        with self.assertRaises(HTTPException) as cm:
            enforce_tenant_boundary(tenant_a_user, resource_tenant_id="tenant-B")
        self.assertEqual(cm.exception.status_code, 403)
        self.assertIn("another tenant", cm.exception.detail)

    def test_platform_admin_can_access_cross_tenant(self):
        admin_user = decode_access_token(
            create_access_token(user_id="admin", tenant_id="tenant-admin", role="platform_admin")
        )
        # Should not raise exception
        enforce_tenant_boundary(admin_user, resource_tenant_id="tenant-B")


if __name__ == "__main__":
    unittest.main()
