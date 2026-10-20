# Bayora Shield: Access Control Matrix (RBAC & Service Identities)

## 1. Principles of Least Privilege

Bayora Shield operates on strict principles of least privilege and zero-implicit-trust:
1. **Separation of Concerns:** Red-team identities (attackers) and Blue-team identities (defenders) are cryptographically and logically isolated. Neither role can access the other's raw private artifacts.
2. **Worker Non-Privilege:** Background worker containers (Red Worker, Blue Worker, Model Gateway) operate under unprivileged service identities. They cannot query the relational database directly, perform user administration, or access Control Plane signing keys.
3. **Run Authorization:** Only authorized operators (`platform_admin`, `red_lead`, `blue_lead`) can provision or trigger evaluation runs. Only the trusted `evaluator` service identity can finalize runs or transition their status to `COMPLETED`.
4. **Audit Immutability:** Audit logs can be read and verified by authorized compliance auditors, but cannot be modified, truncated, or backdated by any role, including `platform_admin`.

---

## 2. Identified Personas & Service Roles

### Human Personas
- **`platform_admin`**: Manages platform configuration, tenant onboarding, user roles, and system health.
- **`auditor`**: Compliance and security auditor. Has read-only access to audit logs, cryptographic signatures, and finalized findings; can trigger cryptographic audit verification.
- **`red_lead`**: Senior red-team operator. Can configure adversarial test suites, initiate runs, view full Red artifacts, and review breach findings.
- **`red_operator`**: Junior red-team operator. Can submit individual attack probes and view assigned run metrics.
- **`blue_lead`**: Senior blue-team operator. Can manage defensive policies/guardrails, review mitigation efficacy, and configure defense rules.
- **`blue_operator`**: Junior blue-team operator. Can test guardrail rules against simulated inputs and view defense performance telemetry.

### Service Identities (Machine-to-Machine)
- **`svc:control-plane`**: Central orchestrator. Has read/write access to PostgreSQL and dispatches tasks to the Evaluator.
- **`svc:evaluator`**: Execution loop runner. Has scoped access to dispatch steps to Red Worker, Blue Worker, and Model Gateway, and emit audit events.
- **`svc:audit-service`**: Cryptographic logger. Holds the Ed25519 signing key; appends and verifies hash chains.
- **`svc:worker-red`**: Sandboxed red worker. Limited to executing attack generation tools; zero access to blue artifacts, database, or LLM directly.
- **`svc:worker-blue`**: Sandboxed blue worker. Limited to running guardrail checks; zero access to red payload catalogs or database.
- **`svc:model-gateway`**: LLM proxy. Holds provider API keys; strictly answers inference calls from `svc:evaluator`.

---

## 3. Comprehensive Access Control Matrix

The matrix below maps roles and service identities to resources and actions.

**Legend:**
- **`C`**: Create
- **`R`**: Read
- **`U`**: Update
- **`D`**: Delete
- **`E`**: Execute / Trigger
- **`V`**: Verify Cryptographically
- **`--`**: Denied (Enforced by API gateway & firewall)

| Resource / Action | `platform_admin` | `auditor` | `red_lead` | `red_operator` | `blue_lead` | `blue_operator` | `svc:evaluator` | `svc:worker-red` | `svc:worker-blue` | `svc:model-gateway` |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Users & Roles** | CRUD | R | -- | -- | -- | -- | -- | -- | -- | -- |
| **Tenants** | CRUD | R | -- | -- | -- | -- | -- | -- | -- | -- |
| **Evaluation Runs: Create** | C | -- | C | -- | C | -- | -- | -- | -- | -- |
| **Evaluation Runs: View** | R | R | R (Own Tenant) | R (Assigned) | R (Own Tenant) | R (Assigned) | R | -- | -- | -- |
| **Evaluation Runs: Execute** | E | -- | E | -- | E | -- | E | -- | -- | -- |
| **Evaluation Runs: Finalize**| -- | -- | -- | -- | -- | -- | U (State) | -- | -- | -- |
| **Red Team Artifacts (Raw)** | R | -- | CRUD | CR | -- | -- | R | R | -- | -- |
| **Blue Team Rules (Raw)** | R | -- | -- | -- | CRUD | CR | R | -- | R | -- |
| **Findings: View Confirmed** | R | R | R | R | R | R | R | -- | -- | -- |
| **Findings: Create / Assert** | -- | -- | C | C | -- | -- | C | -- | -- | -- |
| **Model Inference (Direct)** | -- | -- | -- | -- | -- | -- | E (Via Gateway)| -- | -- | E (Internal) |
| **Audit Logs: Append** | -- | -- | -- | -- | -- | -- | C (Via svc:audit)| -- | -- | -- |
| **Audit Logs: View Metadata**| R | R | R (Scoped) | R (Scoped) | R (Scoped) | R (Scoped) | R | -- | -- | -- |
| **Audit Logs: View Raw Prompts**| R (Redacted) | R (Redacted) | R (Red Only) | R (Red Only) | -- | -- | R | -- | -- | -- |
| **Audit Logs: Verify Chain** | V | V | V | V | V | V | V | -- | -- | -- |
| **Ed25519 Signing Key** | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- |
| **Database Direct Access** | Admin (CLI) | -- | -- | -- | -- | -- | -- | -- | -- | -- |

> *Note:* The Ed25519 signing key is held solely by `svc:audit-service` in memory / secure key file. No human user or other service identity has read access to the private signing key.

---

## 4. Resource Boundary Rules & Enforcement Mechanics

### 4.1 Cross-Team Artifact Isolation
- **Rule:** A user with role `red_*` requesting `GET /api/policies/blue/*` receives `HTTP 403 Forbidden`.
- **Rule:** A user with role `blue_*` requesting `GET /api/artifacts/red/*` receives `HTTP 403 Forbidden`.
- **Enforcement:** Enforced in the Control Plane by FastAPI dependency `require_permissions("artifact:read:blue")` or `require_permissions("artifact:read:red")` backed by the JWT claim `role`.

### 4.2 Model Gateway Boundary
- **Rule:** Neither `svc:worker-red` nor `svc:worker-blue` can connect directly to `svc:model-gateway`.
- **Enforcement:**
  - `svc:model-gateway` listens only on the internal Docker network `model-net`.
  - `svc:worker-red` is bound solely to `red-net`.
  - `svc:worker-blue` is bound solely to `blue-net`.
  - Only `svc:evaluator` bridges `red-net`, `blue-net`, and `model-net`.

### 4.3 Database Access Restriction
- **Rule:** Worker containers (`svc:worker-red`, `svc:worker-blue`, `svc:model-gateway`) must not possess database credentials or database network routes.
- **Enforcement:**
  - PostgreSQL container is connected solely to `control-net`.
  - Worker containers are omitted from `control-net`.
  - Database credentials (`POSTGRES_USER`, `POSTGRES_PASSWORD`, `DATABASE_URL`) are omitted from worker environment definitions.

### 4.4 Audit Scoping & Redaction Policy
- **Rule:** Audit event queries (`GET /api/audit/events`) return canonical event metadata, actor identity, action type, resource identifier, timestamp, and SHA-256 payload digest.
- **Redaction:**
  - Raw prompt texts containing sensitive proprietary payloads or canary tokens are redacted by default:
    `"payload_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "raw_content": "[REDACTED_BY_POLICY]"`
  - Only authorized Red leads can view raw Red prompt content corresponding to that digest.

---

## 5. Token & Credential Lifecycles

1. **User Authentication:**
   - Issues short-lived RS256 or HS256 signed JWTs with expiration ($T_{exp} = 60\text{ minutes}$).
   - Claims include `sub` (User ID), `tid` (Tenant ID), `role` (Assigned Role), `exp`, `iat`.
2. **Internal Service Tokens (mTLS / Pre-shared Tokens):**
   - Inter-service communication from `svc:evaluator` to `svc:audit-service` or `svc:model-gateway` uses short-lived ephemeral run execution tokens signed by the Control Plane.
   - Run tokens expire immediately upon run finalization or after 30 minutes.
3. **Revocation:**
   - User tokens can be revoked immediately via Redis/in-memory token blacklist or session invalidation table in PostgreSQL.
