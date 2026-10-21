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

    def test_jwt_none_algorithm_rejected(self):
        import jwt as pyjwt
        # Construct an unsigned token with 'none' algorithm
        header = {"alg": "none", "typ": "JWT"}
        payload = {
            "sub": "attacker",
            "tid": "tenant-alpha",
            "role": "platform_admin",
            "iss": "bayora-shield",
            "aud": "bayora-api",
            "exp": 9999999999,
        }
        unsigned_token = pyjwt.encode(payload, key="", algorithm="none")
        with self.assertRaises(HTTPException) as cm:
            decode_access_token(unsigned_token)
        self.assertEqual(cm.exception.status_code, 401)

    def test_jwt_invalid_issuer_rejected(self):
        import jwt as pyjwt
        from services.control_plane.config import settings
        payload = {
            "sub": "user-1",
            "tid": "tenant-alpha",
            "role": "red_lead",
            "iss": "malicious-issuer",
            "aud": settings.JWT_AUDIENCE,
            "exp": 9999999999,
            "iat": 1000000000,
        }
        token = pyjwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
        with self.assertRaises(HTTPException) as cm:
            decode_access_token(token)
        self.assertEqual(cm.exception.status_code, 401)

    def test_jwt_invalid_audience_rejected(self):
        import jwt as pyjwt
        from services.control_plane.config import settings
        payload = {
            "sub": "user-1",
            "tid": "tenant-alpha",
            "role": "red_lead",
            "iss": settings.JWT_ISSUER,
            "aud": "wrong-audience",
            "exp": 9999999999,
            "iat": 1000000000,
        }
        token = pyjwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
        with self.assertRaises(HTTPException) as cm:
            decode_access_token(token)
        self.assertEqual(cm.exception.status_code, 401)

    def test_jwt_missing_required_claims_rejected(self):
        import jwt as pyjwt
        from services.control_plane.config import settings
        # Missing role and tid
        payload = {
            "sub": "user-1",
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE,
            "exp": 9999999999,
        }
        token = pyjwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
        with self.assertRaises(HTTPException) as cm:
            decode_access_token(token)
        self.assertEqual(cm.exception.status_code, 401)

    def test_rbac_auditor_cannot_execute_runs(self):
        auditor_token = create_access_token(user_id="auditor-1", tenant_id="t1", role="auditor")
        ctx = decode_access_token(auditor_token)
        checker = require_permissions("run:execute")
        with self.assertRaises(HTTPException) as cm:
            asyncio.run(checker(current_user=ctx))
        self.assertEqual(cm.exception.status_code, 403)

    def test_rbac_red_operator_cannot_verify_audit(self):
        red_op_token = create_access_token(user_id="red-op-1", tenant_id="t1", role="red_operator")
        ctx = decode_access_token(red_op_token)
        checker = require_permissions("audit:verify")
        with self.assertRaises(HTTPException) as cm:
            asyncio.run(checker(current_user=ctx))
        self.assertEqual(cm.exception.status_code, 403)

    def test_rbac_red_lead_cannot_write_blue_policy(self):
        red_token = create_access_token(user_id="red-1", tenant_id="t1", role="red_lead")
        ctx = decode_access_token(red_token)
        checker = require_permissions("policy:write:blue")
        with self.assertRaises(HTTPException) as cm:
            asyncio.run(checker(current_user=ctx))
        self.assertEqual(cm.exception.status_code, 403)


if __name__ == "__main__":
    unittest.main()
