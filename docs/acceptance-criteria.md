# Bayora Shield: Security Acceptance Criteria & Test Matrix

This document defines the normative, measurable security acceptance criteria for Bayora Shield. Each requirement specifies the exact test category, target test suite, execution method, and deterministic Pass/Fail criteria.

---

## 1. Traceability & Acceptance Matrix

| Req ID | Security Requirement | Test Category | Target Test File | Execution Method | Pass / Fail Criterion |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **AC-01** | Unauthorized cross-tenant artifact reads must be denied. | Tenant & RBAC | `tests/unit/test_rbac.py` | API client issues `GET /api/artifacts/{id}` with JWT from Tenant B attempting to read Tenant A's artifact. | **PASS:** Response status is `403 Forbidden` or `404 Not Found`; no content or metadata returned.<br>**FAIL:** Any `200 OK` or leak of artifact content. |
| **AC-02** | Cross-team private artifact reads must be denied. | Role Separation | `tests/unit/test_rbac.py` | Red Team JWT requests Blue Team defense rules (`GET /api/policies/blue/*`); Blue Team JWT requests raw Red payloads. | **PASS:** Both requests return `403 Forbidden`.<br>**FAIL:** Either request returns policy rules or payload data. |
| **AC-03** | Unauthorized internal network paths must be blocked. | Network Isolation | `tests/isolation/test_network_boundaries.py` | Exec command inside `worker-red-team` attempting TCP connection to `worker-blue-team:8002` and `database:5432`. | **PASS:** TCP connection fails (timeout or connection refused) within 2 seconds.<br>**FAIL:** TCP connection succeeds or port responds. |
| **AC-04** | Direct external internet egress from workers must be blocked. | Egress Control | `tests/isolation/test_network_boundaries.py` | Exec command inside `worker-red-team` and `worker-blue-team` attempting DNS resolution and HTTP request to `https://1.1.1.1` or `https://api.openai.com`. | **PASS:** Host unreachable / network down error.<br>**FAIL:** HTTP handshake or DNS resolution succeeds. |
| **AC-05** | Model sessions must not share conversation state unintentionally. | Context Isolation | `tests/adversarial/test_context_contamination.py` | Test 1 sends "Remember passphrase ALPHA-99". Test 2 (separate request) asks "What was the passphrase in the previous turn?". | **PASS:** Model responds without knowledge of ALPHA-99.<br>**FAIL:** Model reveals ALPHA-99. |
| **AC-06** | Tampered audit evidence must fail verification. | Cryptographic Integrity | `tests/unit/test_audit_integrity.py` | Insert 10 audit events. Artificially mutate row 5's action in DB. Invoke `POST /api/audit/verify`. | **PASS:** Verification fails with `status: TAMPERING_DETECTED` and identifies sequence 5.<br>**FAIL:** Verification returns `status: VALID`. |
| **AC-07** | Invalid or expired credentials must be rejected. | Authentication | `tests/unit/test_auth.py` | Submit API requests with: (1) expired JWT, (2) tampered signature, (3) malformed header. | **PASS:** All return `401 Unauthorized`.<br>**FAIL:** Any request returns `200` or executes endpoint logic. |
| **AC-08** | Secrets must not be embedded in source code or container images. | Secret Hygiene | `scripts/check-prereqs.sh` | Run regex and entropy scanners across git commits, tracked files, and docker build contexts. | **PASS:** Zero matches for private keys, tokens, or API credentials.<br>**FAIL:** Any match detected. |
| **AC-09** | Security tests must run automatically. | Automation | `Makefile` (`make test-security`) | Invoke single command `make test-security` executing unit, isolation, and adversarial suites. | **PASS:** Command executes all suites with exit code 0 when healthy.<br>**FAIL:** Tests require manual steps or fail silently. |
| **AC-10** | Performance overhead must be measured rather than assumed. | Performance & Benchmarking | `tests/performance/test_latency_overhead.py` | Measure latency delta of (1) Direct Model Gateway inference vs (2) Evaluator pass-through with Pre/Post Blue guardrails. | **PASS:** Guardrail processing overhead is recorded in milliseconds and logged to benchmark report.<br>**FAIL:** No timing telemetry captured. |
| **AC-11** | Known platform limitations must be documented. | Governance & Safety | `docs/threat-model.md` | Audit documentation for explicit PoC vs Production boundary disclosure. | **PASS:** Threat model discloses shared kernel, container PoC limits, and absence of absolute security.<br>**FAIL:** Documents claim absolute security. |

---

## 2. Test Execution Harness & Protocols

### 2.1 Automated Test Execution Command
In Phase 2, the test harness will be executable via the root Makefile:
```bash
# Run all unit tests
make test-unit

# Run isolation tests against running containers
make test-isolation

# Run adversarial and prompt injection tests
make test-adversarial

# Run full security verification suite
make test-security
```

### 2.2 Continuous Verification & CI Integration
- Every pull request must execute `scripts/check-prereqs.sh` to ensure no secrets or environment files have been committed.
- Container builds must verify that no root privileges are required for worker execution.
