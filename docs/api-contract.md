# Bayora Shield: API Specification Contract (v1 Draft)

> **Specification Notice:**
> The endpoints specified below represent the normative API contract designed in Phase 1 for implementation across Phase 2 and subsequent phases. These are API specifications at this stage and are not exposed as functional mock stubs or incomplete placeholders until implemented in Phase 2.

All requests accept and return `application/json` unless otherwise specified.
All authenticated endpoints require an `Authorization: Bearer <JWT>` HTTP header.

---

## 1. System Health & Diagnostics

### `GET /api/health`
- **Purpose:** Verifies platform operational health, database connectivity, and crypto subsystem readiness.
- **Authentication:** None (Public / Orchestrator probe).
- **Required Permissions:** None.
- **Request Schema:** None (Empty query/body).
- **Response Schema (`200 OK`):**
  ```json
  {
    "status": "healthy",
    "timestamp": "2026-10-20T22:00:00.000000Z",
    "services": {
      "database": "connected",
      "audit_service": "online",
      "model_gateway": "ready"
    },
    "version": "0.1.0-phase1"
  }
  ```
- **Expected Error Cases:**
  - `503 Service Unavailable`: Database or audit service unreachable.

---

## 2. Evaluation Runs Lifecycle

### `POST /api/runs`
- **Purpose:** Provisions a new adversarial evaluation run for a target model under a specified defensive policy version.
- **Authentication:** Required (Bearer JWT).
- **Required Permissions:** `platform_admin`, `red_lead`, `blue_lead`.
- **Request Schema:**
  ```json
  {
    "target_model": "gpt-4o-mini-mock",
    "policy_version_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "suite_categories": [
      "PROMPT_INJECTION",
      "JAILBREAK",
      "SYSTEM_PROMPT_LEAK"
    ],
    "max_concurrency": 2,
    "timeout_seconds": 300
  }
  ```
- **Response Schema (`201 Created`):**
  ```json
  {
    "run_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
    "tenant_id": "e0a4f5b2-38d1-4e1a-8c76-d1e57c6b8401",
    "status": "PENDING",
    "target_model": "gpt-4o-mini-mock",
    "policy_version_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "total_tests_planned": 12,
    "created_at": "2026-10-20T22:01:00.000000Z"
  }
  ```
- **Expected Error Cases:**
  - `400 Bad Request`: Invalid target model or empty suite categories.
  - `401 Unauthorized`: Missing or invalid Bearer token.
  - `403 Forbidden`: User has insufficient permissions (e.g. `red_operator` cannot provision new runs).
  - `404 Not Found`: Specified `policy_version_id` does not exist in tenant.

---

### `POST /api/runs/{id}/execute`
- **Purpose:** Dispatches the execution loop for a provisioned run to the Evaluator service.
- **Authentication:** Required (Bearer JWT).
- **Required Permissions:** `platform_admin`, `red_lead`.
- **Path Parameters:**
  - `id` (UUID): The unique evaluation run identifier.
- **Request Schema:** None or optional execution flags:
  ```json
  {
    "dry_run": false
  }
  ```
- **Response Schema (`202 Accepted`):**
  ```json
  {
    "run_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
    "status": "INITIALIZING",
    "message": "Evaluation run queued for dispatch",
    "dispatch_timestamp": "2026-10-20T22:01:15.000000Z"
  }
  ```
- **Expected Error Cases:**
  - `400 Bad Request`: Run is already running or completed.
  - `401 Unauthorized`: Token invalid or expired.
  - `403 Forbidden`: Operator not entitled to execute run for this tenant.
  - `404 Not Found`: Run ID does not exist.
  - `409 Conflict`: Target model gateway capacity exhausted.

---

### `GET /api/runs/{id}`
- **Purpose:** Retrieves run status, progress counter, aggregate defense metrics, and breach counts.
- **Authentication:** Required (Bearer JWT).
- **Required Permissions:** `platform_admin`, `auditor`, `red_lead`, `red_operator`, `blue_lead`, `blue_operator` (Scoped to user tenant).
- **Path Parameters:**
  - `id` (UUID): Run ID.
- **Response Schema (`200 OK`):**
  ```json
  {
    "run_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
    "tenant_id": "e0a4f5b2-38d1-4e1a-8c76-d1e57c6b8401",
    "status": "RUNNING",
    "target_model": "gpt-4o-mini-mock",
    "policy_version_label": "v1.2-strict",
    "progress": {
      "total_tests": 12,
      "completed_tests": 8,
      "blocked_count": 6,
      "breach_count": 2
    },
    "started_at": "2026-10-20T22:01:20.000000Z",
    "completed_at": null
  }
  ```
- **Expected Error Cases:**
  - `401 Unauthorized`: Missing or expired token.
  - `403 Forbidden`: User tenant does not match run tenant.
  - `404 Not Found`: Run ID not found.

---

## 3. Findings & Vulnerabilities

### `GET /api/findings`
- **Purpose:** Lists confirmed security vulnerabilities, categorized by severity and CWE, with redacted evidence.
- **Authentication:** Required (Bearer JWT).
- **Required Permissions:** `platform_admin`, `auditor`, `red_lead`, `red_operator`, `blue_lead`, `blue_operator`.
- **Query Parameters:**
  - `run_id` (optional, UUID): Filter by evaluation run.
  - `severity` (optional, string): `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.
  - `limit` (int, default 50, max 200).
  - `offset` (int, default 0).
- **Response Schema (`200 OK`):**
  ```json
  {
    "total": 1,
    "limit": 50,
    "offset": 0,
    "items": [
      {
        "finding_id": "b1e9c20a-8149-43c2-8419-f54e17ef9a12",
        "run_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
        "title": "System Prompt Extraction via Multi-Turn Delimiter Injection",
        "severity": "HIGH",
        "cwe_id": "CWE-200",
        "description": "Adversarial payload bypassed Blue input guardrail and extracted canary token CANARY-7729 from model context.",
        "redacted_proof": "Response preview: 'System instruction confirmed: [REDACTED_CANARY_TOKEN]'",
        "created_at": "2026-10-20T22:02:10.000000Z"
      }
    ]
  }
  ```
- **Expected Error Cases:**
  - `401 Unauthorized`: Authentication required.
  - `403 Forbidden`: Scoped to tenant.

---

## 4. Isolation Lab & Security Verification

### `POST /api/isolation-tests`
- **Purpose:** Triggers on-demand security assertion tests across network boundaries, tenant separation, and file isolation.
- **Authentication:** Required (Bearer JWT).
- **Required Permissions:** `platform_admin`, `auditor`.
- **Request Schema:**
  ```json
  {
    "test_suite": "NETWORK_BOUNDARIES",
    "target_worker": "worker-red-team",
    "parameters": {
      "probe_target": "worker-blue-team:8002",
      "expected_outcome": "BLOCKED"
    }
  }
  ```
- **Response Schema (`200 OK`):**
  ```json
  {
    "test_id": "iso-99812",
    "test_suite": "NETWORK_BOUNDARIES",
    "target_worker": "worker-red-team",
    "result": "PASSED",
    "details": {
      "connection_attempt": "TCP 172.28.0.4:8002",
      "outcome": "Connection timed out / Host unreachable",
      "boundary_intact": true
    },
    "executed_at": "2026-10-20T22:03:00.000000Z"
  }
  ```
- **Expected Error Cases:**
  - `400 Bad Request`: Unknown isolation test suite.
  - `401 Unauthorized`: Token missing.
  - `403 Forbidden`: Regular operators (`red_operator`, `blue_operator`) cannot trigger infrastructure isolation tests.

---

## 5. Audit Trail & Cryptographic Verification

### `GET /api/audit/events`
- **Purpose:** Retrieves append-only hash-chained audit events with payload digests.
- **Authentication:** Required (Bearer JWT).
- **Required Permissions:** `platform_admin`, `auditor`, `red_lead`, `blue_lead`.
- **Query Parameters:**
  - `start_seq` (int, default 1).
  - `end_seq` (optional, int).
  - `limit` (int, default 100, max 1000).
- **Response Schema (`200 OK`):**
  ```json
  {
    "total_events": 45,
    "returned_events": 2,
    "events": [
      {
        "sequence_number": 1,
        "event_id": "673f8a91-4e4b-4a25-a7b2-13c5ef61a001",
        "actor": "user:red_lead@bayora.io",
        "action": "RUN_PROVISIONED",
        "resource": "run:7c9e6679-7425-40de-944b-e07fc1f90ae7",
        "decision": "ALLOW",
        "timestamp": "2026-10-20T22:01:00.000000Z",
        "policy_version": "v1.2-strict",
        "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "event_hash": "8f483de4f58f4a7c1b52a512403de144e5cc5b9b7754f24c0d1887e2b1049c63"
      },
      {
        "sequence_number": 2,
        "event_id": "a90b3491-12c1-4ef4-9842-832145bca112",
        "actor": "svc:evaluator",
        "action": "GUARDRAIL_BLOCKED",
        "resource": "test:tc-001",
        "decision": "DENY",
        "timestamp": "2026-10-20T22:01:25.000000Z",
        "policy_version": "v1.2-strict",
        "previous_hash": "8f483de4f58f4a7c1b52a512403de144e5cc5b9b7754f24c0d1887e2b1049c63",
        "event_hash": "37a915f013143c0889f074dcfc9f372a85750a980590a5d2b781121d51a660a9"
      }
    ]
  }
  ```
- **Expected Error Cases:**
  - `401 Unauthorized`: Token invalid.
  - `403 Forbidden`: Insufficient role permissions.

---

### `POST /api/audit/verify`
- **Purpose:** Cryptographically verifies unbroken continuity of the SHA-256 hash chain and validates Ed25519 checkpoint digital signatures.
- **Authentication:** Required (Bearer JWT).
- **Required Permissions:** `platform_admin`, `auditor`, `red_lead`, `blue_lead`.
- **Request Schema:**
  ```json
  {
    "start_sequence": 1,
    "end_sequence": 45,
    "verify_ed25519_signatures": true
  }
  ```
- **Response Schema (`200 OK` - Verification Succeeded):**
  ```json
  {
    "verification_status": "VALID",
    "events_evaluated": 45,
    "hash_chain_continuity": "INTACT",
    "ed25519_signature_status": "VERIFIED",
    "root_hash": "37a915f013143c0889f074dcfc9f372a85750a980590a5d2b781121d51a660a9",
    "verified_at": "2026-10-20T22:05:00.000000Z"
  }
  ```
- **Response Schema (`422 Unprocessable Entity` - Tampering Detected):**
  ```json
  {
    "verification_status": "TAMPERING_DETECTED",
    "error_code": "HASH_CHAIN_BROKEN",
    "broken_sequence_number": 23,
    "expected_previous_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "actual_previous_hash": "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00",
    "message": "Audit event hash chain discontinuity detected at sequence 23"
  }
  ```
- **Expected Error Cases:**
  - `400 Bad Request`: Invalid sequence numbers (`start_sequence > end_sequence`).
  - `401 Unauthorized`: Authentication required.
  - `403 Forbidden`: Role not authorized to run audit verification.
