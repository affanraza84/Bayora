"""
Integration test suite for Bayora Shield Control Plane APIs.
Tests health, authentication, runs lifecycle, duplicate execution guards,
cross-tenant isolation, findings, isolation lab, and audit verification.
"""

import unittest
import asyncio
import os
from httpx import AsyncClient, ASGITransport
from sqlalchemy import update

from services.control_plane.main import app
from services.control_plane.db.session import init_db, AsyncSessionLocal
from services.control_plane.db.models import AuditEvent
from services.control_plane.auth.jwt import create_access_token


class TestControlPlaneAPI(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # Ensure database tables exist
        await init_db()

        self.transport = ASGITransport(app=app)
        self.client = AsyncClient(transport=self.transport, base_url="http://testserver")

        # Dev tokens for testing
        self.admin_token = create_access_token(
            user_id="admin-1",
            tenant_id="tenant-alpha",
            role="platform_admin",
        )
        self.red_lead_token = create_access_token(
            user_id="red-lead-1",
            tenant_id="tenant-alpha",
            role="red_lead",
        )
        self.red_operator_token = create_access_token(
            user_id="red-op-1",
            tenant_id="tenant-alpha",
            role="red_operator",
        )
        self.tenant_b_token = create_access_token(
            user_id="red-lead-b",
            tenant_id="tenant-beta",
            role="red_lead",
        )
        self.auditor_token = create_access_token(
            user_id="auditor-1",
            tenant_id="tenant-alpha",
            role="auditor",
        )

    async def asyncTearDown(self):
        await self.client.aclose()

    async def test_01_health_endpoint_connected(self):
        response = await self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["services"]["database"], "connected")
        self.assertEqual(data["services"]["audit_service"], "online")
        self.assertEqual(data["services"]["model_gateway"], "ready")

    async def test_02_create_run_authentication_and_rbac(self):
        # 1. Missing token -> 401
        res = await self.client.post("/api/runs", json={"target_model": "gpt-4o-mini-mock"})
        self.assertEqual(res.status_code, 401)

        # 2. red_operator lacks run:create -> 403
        headers_op = {"Authorization": f"Bearer {self.red_operator_token}"}
        res = await self.client.post("/api/runs", json={"target_model": "gpt-4o-mini-mock"}, headers=headers_op)
        self.assertEqual(res.status_code, 403)

        # 3. red_lead creates run -> 201 Created
        headers_red = {"Authorization": f"Bearer {self.red_lead_token}"}
        res = await self.client.post("/api/runs", json={"target_model": "gpt-4o-mini-mock"}, headers=headers_red)
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertIn("run_id", data)
        self.assertEqual(data["status"], "created")
        self.assertEqual(data["tenant_id"], "tenant-alpha")

    async def test_03_run_execution_and_duplicate_guard(self):
        headers_red = {"Authorization": f"Bearer {self.red_lead_token}"}

        # Provision run
        create_res = await self.client.post("/api/runs", json={"target_model": "gpt-4o-mini-mock"}, headers=headers_red)
        self.assertEqual(create_res.status_code, 201)
        run_id = create_res.json()["run_id"]

        # First execution -> 200 OK
        exec_res = await self.client.post(f"/api/runs/{run_id}/execute", json={}, headers=headers_red)
        self.assertEqual(exec_res.status_code, 200)
        exec_data = exec_res.json()
        self.assertEqual(exec_data["status"], "completed")
        self.assertEqual(exec_data["total_tests"], 4)
        self.assertGreaterEqual(exec_data["blocked_count"], 1)
        self.assertGreaterEqual(exec_data["breach_count"], 1)

        # DUPLICATE EXECUTION GUARD: Second execution attempt must fail with 409 Conflict
        dup_res = await self.client.post(f"/api/runs/{run_id}/execute", json={}, headers=headers_red)
        self.assertEqual(dup_res.status_code, 409)
        self.assertIn("cannot be executed twice", dup_res.json()["detail"])

    async def test_04_cross_tenant_isolation(self):
        # Create run in tenant-alpha
        headers_alpha = {"Authorization": f"Bearer {self.red_lead_token}"}
        create_res = await self.client.post("/api/runs", json={"target_model": "gpt-4o-mini-mock"}, headers=headers_alpha)
        self.assertEqual(create_res.status_code, 201)
        run_id = create_res.json()["run_id"]

        # Tenant-beta user attempts to execute tenant-alpha run -> 403 Forbidden
        headers_beta = {"Authorization": f"Bearer {self.tenant_b_token}"}
        exec_res = await self.client.post(f"/api/runs/{run_id}/execute", json={}, headers=headers_beta)
        self.assertEqual(exec_res.status_code, 403)
        self.assertIn("another tenant", exec_res.json()["detail"])

        # Tenant-beta user attempts to get tenant-alpha run -> 403 Forbidden
        get_res = await self.client.get(f"/api/runs/{run_id}", headers=headers_beta)
        self.assertEqual(get_res.status_code, 403)

    async def test_05_findings_retrieval(self):
        # Provision and execute run to produce findings
        headers_red = {"Authorization": f"Bearer {self.red_lead_token}"}
        create_res = await self.client.post("/api/runs", json={"target_model": "gpt-4o-mini-mock"}, headers=headers_red)
        run_id = create_res.json()["run_id"]
        await self.client.post(f"/api/runs/{run_id}/execute", json={}, headers=headers_red)

        # Query findings for tenant-alpha
        res = await self.client.get("/api/findings", headers=headers_red)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertGreaterEqual(data["total"], 1)
        finding = data["items"][0]
        self.assertEqual(finding["tenant_id"], "tenant-alpha")
        self.assertIn("CWE-200", finding["cwe_id"])
        self.assertIn("REDACTED", finding["redacted_proof"])

    async def test_06_isolation_tests_endpoint(self):
        headers_admin = {"Authorization": f"Bearer {self.admin_token}"}
        headers_op = {"Authorization": f"Bearer {self.red_operator_token}"}

        # red_operator cannot run isolation tests -> 403
        res = await self.client.post(
            "/api/isolation-tests",
            json={"test_suite": "NETWORK_BOUNDARIES", "target_worker": "worker-red-team"},
            headers=headers_op,
        )
        self.assertEqual(res.status_code, 403)

        # admin executes network boundary test -> 200 PASSED
        res = await self.client.post(
            "/api/isolation-tests",
            json={"test_suite": "NETWORK_BOUNDARIES", "target_worker": "worker-red-team"},
            headers=headers_admin,
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["result"], "PASSED")
        self.assertTrue(data["details"]["boundary_intact"])

        # admin executes tamper simulation test -> 200 PASSED
        res = await self.client.post(
            "/api/isolation-tests",
            json={"test_suite": "TAMPER_SIMULATION"},
            headers=headers_admin,
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["result"], "PASSED")
        self.assertTrue(data["details"]["integrity_alarm_triggered"])

    async def test_07_audit_trail_and_verification(self):
        headers_auditor = {"Authorization": f"Bearer {self.auditor_token}"}

        # 1. List audit events
        res = await self.client.get("/api/audit/events", headers=headers_auditor)
        self.assertEqual(res.status_code, 200)
        events_data = res.json()
        self.assertGreaterEqual(events_data["total_events"], 1)

        # 2. Verify audit chain continuity and Ed25519 checkpoint signature -> 200 VALID
        verify_res = await self.client.post(
            "/api/audit/verify",
            json={"start_sequence": 1, "verify_ed25519_signatures": True},
            headers=headers_auditor,
        )
        self.assertEqual(verify_res.status_code, 200)
        v_data = verify_res.json()
        self.assertEqual(v_data["verification_status"], "VALID")
        self.assertEqual(v_data["hash_chain_continuity"], "INTACT")
        self.assertEqual(v_data["ed25519_signature_status"], "VERIFIED")

    async def test_08_tamper_detection_in_database(self):
        headers_auditor = {"Authorization": f"Bearer {self.auditor_token}"}

        # Inject an event and intentionally mutate its decision directly in the DB
        async with AsyncSessionLocal() as session:
            # Modify decision of sequence 1
            await session.execute(
                update(AuditEvent).where(AuditEvent.sequence_number == 1).values(decision="MUTATED_DECISION")
            )
            await session.commit()

        # Invoking audit verification must detect the modified row and return 422 Unprocessable Entity
        verify_res = await self.client.post(
            "/api/audit/verify",
            json={"start_sequence": 1, "verify_ed25519_signatures": True},
            headers=headers_auditor,
        )
        self.assertEqual(verify_res.status_code, 422)
        err = verify_res.json()["detail"]
        self.assertEqual(err["verification_status"], "TAMPERING_DETECTED")
        self.assertEqual(err["error_code"], "HASH_CHAIN_BROKEN")
        self.assertEqual(err["broken_sequence_number"], 1)


if __name__ == "__main__":
    unittest.main()
