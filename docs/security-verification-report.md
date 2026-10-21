# Bayora Shield: Security Hardening & Independent Verification Report

**Date:** 2026-10-21  
**Target:** Bayora Shield Hackathon Release (Phase 4: Security Hardening & Readiness)  
**Author:** Antigravity AI Security Engineering  
**Scope:** Control Plane API, Authentication & RBAC, Tamper-Evident Audit Service, Blue-Team Guardrail Engine, Live Docker Enclave Container Isolation, and Next.js Security Dashboard.

---

## 1. Executive Summary & Verification Verdict

| Component | Status | Verification Summary |
| :--- | :---: | :--- |
| **Authentication & RBAC** | **VERIFIED** | Strict JWT validation (HS256 only; `none` algorithm rejected; issuer/audience/expiry enforced; role boundaries verified). |
| **Cryptographic Audit Ledger** | **VERIFIED** | SHA-256 hash-chaining with sequence monotonicity; deletion, reordering, and injection tamper-detection; Ed25519 digital checkpoint signatures. |
| **Blue-Team Guardrail Engine** | **VERIFIED** | Pre-inference override block (INP-001/002/003); post-inference canary leak detection & redaction (OUT-001/002); benign queries permitted without false positives. |
| **Live Docker Runtime Isolation** | **VERIFIED** | L3 kernel unreachability (`OSError: [Errno 101] Network is unreachable`), DNS segmentation, read-only root filesystems, absent Docker socket, and cgroup v2 limits (512MB RAM, 1.0 CPU) proven live. |
| **Evaluation Pipeline** | **VERIFIED** | Multi-phase adversarial runner; stateless model gateway isolation; automated finding generation (CWE-200); Ed25519 evidence bundle signing. |
| **API Route Consistency** | **VERIFIED** | Unified `/api/audit/verify` and alias `/api/audit-events/verify`; scenario ID alias resolution; strict tenant scoping. |
| **Dashboard Integration** | **VERIFIED** | Production Next.js build validated; live status indicators; colorized tamper alerts; explicit synthetic mock disclaimers. |

---

## 2. Changes Made & Rationale

| File Modified / Created | Change Summary | Rationale |
| :--- | :--- | :--- |
| [`tests/integration/test_runs_api.py`](file:///Users/affanraza/Developer/Bayora/tests/integration/test_runs_api.py) | Added clean DB initialization in `setUpClass` and wrapped `test_08` tamper injection in `try...finally`. | Fixes non-idempotent test runs where database tampering permanently altered sequence 1 on disk, failing subsequent test executions. |
| [`services/control-plane/routers/audit.py`](file:///Users/affanraza/Developer/Bayora/services/control-plane/routers/audit.py) | Added `audit_events_router` alias supporting both `/api/audit/verify` and `/api/audit-events/verify`. | Resolves API route discrepancy between frontend callers and backend definitions. |
| [`services/control-plane/main.py`](file:///Users/affanraza/Developer/Bayora/services/control-plane/main.py) | Mounted `audit_events_router` on FastAPI application. | Ensures zero 404s for any legacy or alternate client route calls. |
| [`services/audit-service/hasher.py`](file:///Users/affanraza/Developer/Bayora/services/audit-service/hasher.py) | Enforced strict sequence monotonicity check (`seq == prev_event['sequence_number'] + 1`) in `verify_chain`. | Prevents attackers from deleting or inserting events in the audit trail without triggering an immediate sequence gap alarm. |
| [`tests/unit/test_audit_crypto.py`](file:///Users/affanraza/Developer/Bayora/tests/unit/test_audit_crypto.py) | Added unit tests for event deletion, event reordering, and rogue event injection. | Verifies all tamper-detection failure modes under automated unit test assertions. |
| [`tests/unit/test_auth_rbac.py`](file:///Users/affanraza/Developer/Bayora/tests/unit/test_auth_rbac.py) | Added negative tests for algorithm `none`, invalid issuer, invalid audience, missing required claims, and cross-role permission checks. | Hardens JWT decoding against algorithm-confusion and signature-bypass attacks. |
| [`tests/isolation/test_live_docker_isolation.py`](file:///Users/affanraza/Developer/Bayora/tests/isolation/test_live_docker_isolation.py) | Added raw L3 IP connectivity probes, Linux cgroup v2 resource limit inspection, and host port binding verification. | Distinguishes DNS resolution failure from raw kernel IP unreachability; validates memory and CPU limits inside running containers. |
| [`tests/adversarial/test_guardrail_adversarial.py`](file:///Users/affanraza/Developer/Bayora/tests/adversarial/test_guardrail_adversarial.py) | Added comprehensive adversarial and benign guardrail test suite. | Proves detection of synthetic injection, roleplay escape, credential harvesting, canary leakage, while confirming zero false positives on benign queries. |
| [`services/control-plane/routers/isolation.py`](file:///Users/affanraza/Developer/Bayora/services/control-plane/routers/isolation.py) | Added scenario identifier alias normalization (`SCN-CROSS-TENANT-ARTIFACT`, `ISO-SCEN-*`). | Allows scenarios to be executed via standard or alternate catalog IDs. |
| [`apps/dashboard/app/page.tsx`](file:///Users/affanraza/Developer/Bayora/apps/dashboard/app/page.tsx) | Upgraded audit verification display with red/green conditional formatting and detailed tamper alarm messages. | Delivers clear visual feedback during hackathon judging if audit tampering occurs. |
| [`.env.example`](file:///Users/affanraza/Developer/Bayora/.env.example) | Set default `DATABASE_URL` to local async SQLite with PostgreSQL commented out for Docker Compose. | Guarantees fresh checkout immediately works without requiring external PostgreSQL setup. |
| [`scripts/check-prereqs.sh`](file:///Users/affanraza/Developer/Bayora/scripts/check-prereqs.sh) | Updated secret scanner to distinguish Git-tracked committed secrets from local `.env` files protected by `.gitignore`. | Prevents false positives when developers initialize local `.env` from template. |
| [`scripts/demo.sh`](file:///Users/affanraza/Developer/Bayora/scripts/demo.sh) | Created 9-step automated judge demonstration script. | Automates end-to-end evaluation, testing, run execution, scenario probing, and audit verification. |

---

## 3. Test Execution Summary

Automated testing was executed using Python 3.14 on macOS with Docker Compose active:

```
================================== TEST TOTALS ==================================
  Suite Category                   Total Tests    Passed    Failed    Blocked
  -----------------------------------------------------------------------------
  1. Unit Tests (Crypto, RBAC)              25        25         0          0
  2. Enclave Isolation Tests (Docker)       11        11         0          0
  3. Adversarial & Guardrails               10        10         0          0
  4. Integration Tests (API, DB)             8         8         0          0
  5. Performance Tests (Benchmarks)          3         3         0          0
  -----------------------------------------------------------------------------
  TOTAL AUTOMATED TESTS                     57        57         0          0
=================================================================================
```

### Cryptographic Architecture Reconciliation

Bayora Shield differentiates three cryptographic mechanisms across three operational domains:

1. **SHA-256 Canonical Hash-Chaining (`hashlib.sha256`):**
   - **Operational Domain:** Audit event link-to-link continuity and artifact checksums.
   - **Guarantee:** Strict Merkle-style chronological chain continuity. Every event binds `H_i = SHA256(canonical_json(previous_hash, sequence_number, ...))`. Detects in-database row mutation, event deletion, or reordering.
   - **Boundary Limitation:** A hash chain alone does not prevent an attacker with full database write access from recomputing a fake alternate history branch from scratch unless anchored to an external signature.
2. **Ed25519 Digital Checkpoint Signatures (`cryptography.hazmat...ed25519`):**
   - **Operational Domain:** Audit checkpoints and exported `EvidenceBundle` archives.
   - **Guarantee:** Asymmetric non-repudiation. Private signing keys are held strictly in memory/isolated volumes (`/etc/bayora/keys`) and never written to database tables. Checkpoint payloads `(start_seq, end_seq, root_hash, timestamp)` are signed with Ed25519. Even an attacker with complete PostgreSQL write access cannot forge an Ed25519 signature over modified events.
3. **HMAC-SHA256 Symmetric Tokens (`PyJWT` / HS256):**
   - **Operational Domain:** User authentication sessions and internal service identity assertion.
   - **Guarantee:** Fast bearer token authorization and RBAC role validation with issuer (`bayora-shield`) and audience (`bayora-shield-api`) verification.

---

## 4. Live Runtime Container Isolation Evidence

Probes were executed via `docker exec` against the running multi-enclave Docker Compose cluster:

### A. Network Enclave Segmentation (Red vs. Blue)
1. **L7/L4 DNS Resolution Probe:**
   - Command: `bayora-worker-red` attempts `socket.connect(('bayora-worker-blue', 8002))`
   - Result: `socket.gaierror: [Errno -3] Temporary failure in name resolution`
   - Classification: **VERIFIED PASS** (Docker embedded DNS refuses cross-network hostname resolution).
2. **L3 Kernel Routing Probe (DNS Bypassed):**
   - Command: `bayora-worker-red` attempts direct connection to dynamically discovered Blue container IP `172.22.0.3:8002`.
   - Result: `OSError: [Errno 101] Network is unreachable`
   - Classification: **VERIFIED PASS** (Kernel routing table has no route between `red-net` and `blue-net` because `internal: true` is configured).

### B. Database Isolation
1. **L3 Direct Connection Probe to PostgreSQL:**
   - Command: `bayora-worker-red` attempts direct connection to database IP `172.20.0.2:5432`.
   - Result: `OSError: [Errno 101] Network is unreachable`
   - Classification: **VERIFIED PASS** (Database is strictly isolated on `control-net`; workers have zero network access to DB).

### C. Container Breakout & Host Escape Prevention
1. **Docker Daemon Socket Absence:**
   - Command: `os.path.exists('/var/run/docker.sock')` inside `bayora-worker-red`.
   - Result: `False`
   - Classification: **VERIFIED PASS** (No Docker socket mounted into untrusted worker enclaves).
2. **Root Filesystem Read-Only Enforcement:**
   - Command: `open('/root_test_write.txt', 'w')` inside `bayora-worker-red`.
   - Result: `OSError: [Errno 30] Read-only file system`
   - Classification: **VERIFIED PASS** (Enforced by Linux VFS kernel driver via `read_only: true`).
3. **Artifact Volume Mount Boundaries:**
   - Command: `os.path.exists('/artifacts/red')` inside `bayora-worker-blue`.
   - Result: `False`
   - Classification: **VERIFIED PASS** (Separate host directories mounted into separate enclaves).

### D. Kernel Cgroup Resource Limit Quotas
1. **Memory Quota:**
   - Command: `cat /sys/fs/cgroup/memory.max` inside `bayora-worker-red`.
   - Result: `536870912` (512MB hard memory ceiling).
   - Classification: **VERIFIED PASS**.
2. **CPU Quota:**
   - Command: `cat /sys/fs/cgroup/cpu.max` inside `bayora-worker-red`.
   - Result: `100000 100000` (100,000 µs quota per 100,000 µs period = 1.0 CPU).
   - Classification: **VERIFIED PASS**.

### E. Host Port Exposure
1. **Port Binding Audit:**
   - Inspected `NetworkSettings.Ports` on `bayora-database`, `bayora-worker-red`, `bayora-worker-blue`, `bayora-model-gateway`, `bayora-audit-service`, `bayora-evaluator`.
   - Result: All internal containers return `null` / empty host port bindings.
   - Classification: **VERIFIED PASS** (Only Control Plane port is exposed).

---

## 5. API Inconsistencies Discovered & Resolved

1. **Audit Verify Route Mismatch:**
   - *Discovery:* API documentation and tests referenced `/api/audit/verify`, while some specifications referenced `/api/audit-events/verify`.
   - *Resolution:* Registered both canonical `/api/audit/verify` and alias router `/api/audit-events/verify` pointing to the same handler in `services/control-plane/routers/audit.py`.
2. **Database Mutation in Test Suite:**
   - *Discovery:* `test_08_tamper_detection_in_database` permanently updated sequence 1's decision to `"MUTATED_DECISION"` without rollback, causing subsequent test runs to fail with HTTP 422.
   - *Resolution:* Wrapped the DB mutation in a `try...finally` block to restore sequence 1's decision back to `"ALLOW"`, and added clean table recreation in `setUpClass`.
3. **Scenario Identifier Aliases:**
   - *Discovery:* Different callers requested `SCN-CROSS-TENANT-ARTIFACT` vs `SCN-TENANT-ISOLATION`.
   - *Resolution:* Updated `isolation.py` router to accept both names as valid scenario IDs.

---

## 6. How to Reproduce the Demonstration (Judge Guide)

To execute the complete demonstration workflow from a fresh terminal:

```bash
# 1. Verify prerequisites & environment
./scripts/check-prereqs.sh

# 2. Start container enclaves in background
docker compose -f infrastructure/compose/docker-compose.yml up -d

# 3. Apply database schema migrations
.venv/bin/alembic upgrade head

# 4. Run automated security test suite (57 tests)
make test-security

# 5. Run end-to-end automated demo script
./scripts/demo.sh

# 6. (Optional) Run the Next.js visual dashboard
cd apps/dashboard && npm run dev
# Open http://localhost:3000 in your browser
```

---

## 7. Remaining Security Risks & Production Limitations

1. **Shared Linux Kernel (Container vs. MicroVM Enclaves):**
   - *Current Implementation:* Shared Linux kernel isolation using Docker bridge networks, user namespaces, and cgroups.
   - *Limitation:* Linux kernel vulnerabilities (e.g. zero-day kernel privilege escalations) could theoretically compromise the host. Production deployments should migrate untrusted workers to hardware-assisted MicroVMs (e.g., AWS Firecracker or gVisor `runsc`).
2. **Pattern-Based Blue-Team Guardrails:**
   - *Current Implementation:* Regex and canary detection rules in `base_guardrails.json`.
   - *Limitation:* Regex pattern matching serves as a deterministic baseline. It is vulnerable to obfuscation, character homoglyphs, or indirect prompt injection. Production deployments should combine regex with semantic embedding classifiers and LLM-as-a-judge secondary verification.
3. **Mock Model Determinism vs. External LLM Non-Determinism:**
   - *Current Implementation:* Mock model provider ensures 100% reproducible, offline evaluation without API key dependencies.
   - *Limitation:* Real upstream LLMs exhibit probabilistic responses, non-deterministic token sampling, and multi-turn indirect jailbreaks that require ongoing adaptive adversarial probes.
