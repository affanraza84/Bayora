# Bayora Shield: AI Adversarial Testing & Multi-Enclave Isolation Platform

[![Security Tests](https://img.shields.io/badge/Security_Tests-62%20Passing-emerald)](tests/)
[![Enclave Isolation](https://img.shields.io/badge/Enclaves-Docker%20Bridge%20Isolated-blue)](#)
[![Audit Ledger](https://img.shields.io/badge/Audit-SHA--256%20Chained%20%2B%20Ed25519-amber)](#)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Hackathon Status](https://img.shields.io/badge/Status-Hackathon%20Final%20Submission-purple)](#)

> **Mission:**  
> **Bayora Shield** is an adversarial security testing platform designed to evaluate AI models and applications against red-team attacks without exposing proprietary defensive rules (Blue Team), leaking sensitive canary secrets, or cross-contaminating session state between turns.

---

## 1. Problem Statement & Motivation

When testing generative AI models for vulnerabilities (prompt injection, jailbreaks, data exfiltration, system prompt leakage):
1. **Defensive Knowledge Asymmetry:** Blue teams cannot share raw proprietary defensive rules or classifiers with third-party red teams without risking rule inversion or evasion attacks.
2. **Adversarial Payload Leakage:** Red teams need proof of vulnerabilities without leaking exploit payloads to unauthorized actors prior to responsible disclosure.
3. **Session Contamination:** LLM providers frequently retain conversational cache or session context across API turns, leading to false positives or cross-test data leaks.
4. **Audit Evidence Tampering:** Without cryptographic integrity proofs, test records and compliance logs can be modified or repudiated after a breach.

### Why Bayora Shield vs. Ordinary LLM Evaluation Scripts?

Most existing AI evaluation tools (e.g. Promptfoo, DeepEval, PyRIT) run evaluations inside a single Python script or unconstrained container where all parties share access:

| Dimension | Ordinary Evaluation Scripts / Frameworks | Bayora Shield Enclave Platform |
| :--- | :--- | :--- |
| **Execution Boundary** | Single flat runtime; prompt code has full access to defense rules. | **Container Enclaves (Namespaces & Cgroups)**: Red, Blue, and Model execute in segregated namespaces. |
| **Network Reachability** | Unrestricted Internet; scripts can exfiltrate keys to arbitrary endpoints. | **L3 Segregated Bridges**: Workers have zero cross-talk route (`internal: true`). |
| **Defensive Privacy** | Red teams inspect regex/rules in memory or config files. | **Zero-Knowledge Defense**: Blue rules run in an isolated enclave; only verdict is returned. |
| **Audit Verifiability** | Plain CSV/JSON files that anyone can edit or delete. | **SHA-256 Hash Chained + Ed25519 Signed**: Tamper-evident mathematical proof. |
| **Model Context** | Session cookies and persistent memory persist between tests. | **Enforced Statelessness**: Fresh ephemeral UUID tokens per prompt; zero bleed. |
| **Evidence Custody** | Unsigned logs easily disputed during post-breach audits. | **Cryptographic Evidence Bundles**: Asymmetrically signed with Ed25519 for non-repudiation. |

---

## 2. Solution Overview & Architecture

Bayora Shield solves these challenges through **three segregated execution enclaves** mediated by a trusted **Control Plane**:

```
+─────────────────────────────────────────────────────────────────────────────+
|               Next.js Security Operations Dashboard (Port 3000)             |
+──────────────────────────────────────┬──────────────────────────────────────+
                                       │ REST / JWT Auth
+──────────────────────────────────────▼──────────────────────────────────────+
|                 Control Plane (FastAPI) & PostgreSQL (Port 8080)            |
+───────────────────┬───────────────────────────────────┬─────────────────────+
                    │                                   │
      +─────────────▼─────────────+       +─────────────▼─────────────+
      |  Audit Service (Ed25519)  |       |     Evaluator Engine      |
      +───────────────────────────+       +─────────────┬─────────────+
                                                        │
         ┌──────────────────────────────────────────────┼────────────────────────────────────────┐
         │ (red-net)                                    │ (blue-net)                             │ (gateway-net)
+────────▼────────+                            +────────▼────────+                      +────────▼────────+
| Red Team Worker |                            | Blue Team Worker|                      |  Model Gateway  |
|  (Attack Enclave|                            |  (Defense Rules)|                      |  (Stateless LLM)|
+─────────────────+                            +─────────────────+                      +─────────────────+
```

### Trust Enclaves
1. **Red Team Worker Enclave (`red-net`):**
   - Dispatches adversarial attack vectors (prompt injection, roleplay jailbreaks, credential exfiltration).
   - Confined to `red-net` (`internal: true`). Cannot reach Blue Team, PostgreSQL, or direct external Internet.
2. **Blue Team Defense Enclave (`blue-net`):**
   - Evaluates pre-inference filters (`INP-001`, `INP-002`, `INP-003`) and post-inference canary sanitization (`OUT-001`, `OUT-002`).
   - Private regex rules and detection thresholds are never exposed to red-team operators.
3. **Sandboxed Model Gateway (`gateway-net`):**
   - Proxies inference requests to local mock models or external LLM providers.
   - Enforces strict statelessness with ephemeral UUID session tokens per request.
4. **Control Plane & Audit Ledger (`control-net`):**
   - Multi-tenant RBAC (Platform Admin, Auditor, Red Lead, Red Operator, Blue Lead).
   - Tamper-evident SHA-256 hash-chaining with sequence monotonicity and Ed25519 digital checkpoint signatures.

---

## 3. Technology Stack

- **Control Plane API:** Python 3.14, FastAPI, Pydantic 2.x, SQLAlchemy 2.x (asyncpg / aiosqlite), Alembic.
- **Security Operations Dashboard:** Next.js 14 (App Router), React, Tailwind CSS, Lucide Icons.
- **Cryptography Engine:** PyCA `cryptography` (Ed25519 asymmetric signatures), `hashlib` (SHA-256 canonical hashing), `pyjwt` (HS256 JWT auth).
- **Enclave Infrastructure:** Docker Compose, Linux bridge network isolation (`internal: true`), Linux cgroup v2 quotas, read-only root filesystems (`read_only: true`).
- **Persistence:** PostgreSQL 16 Alpine (containerized) / SQLite async (offline CI/CD testing).

---

## 4. Adversarial Evaluation Pipeline Workflow

```mermaid
sequenceDiagram
    autonumber
    actor Red as Red Team Operator
    participant CP as Control Plane (FastAPI)
    participant BG as Blue Guardrail Engine
    participant MG as Model Gateway (Stateless)
    participant AS as Audit Ledger (SHA-256)

    Red->>CP: POST /api/runs (Create Run)
    Red->>CP: POST /api/runs/{id}/execute (Start Evaluation)
    
    loop For each test spec (6 tests)
        CP->>BG: evaluate_input(prompt)
        alt Attack Detected (INP-001 / INP-002 / INP-003)
            BG-->>CP: BLOCKED_INPUT (Attack dropped before LLM)
            CP->>AS: Log GUARDRAIL_BLOCKED_INPUT
        else Benign or Canary Probe
            CP->>MG: infer(prompt, session_id=ephemeral_uuid)
            MG-->>CP: Raw Completion Output
            CP->>BG: evaluate_output(output)
            alt Canary Secret Disclosed (OUT-001)
                BG-->>CP: BLOCKED_OUTPUT + [REDACTED] + CONFIRMED_BREACH
                CP->>CP: Register Security Finding (CWE-200)
                CP->>AS: Log FINDING_CONFIRMED
            else Clean Response
                BG-->>CP: PERMITTED
            end
        end
    end

    CP->>AS: Log RUN_COMPLETED (Chain updated)
    CP->>CP: Sign EvidenceBundle with Ed25519 Key
    CP-->>Red: Return Execution Summary & Signed Evidence
```

---

## 5. Prerequisites & Exact Setup Instructions

### System Requirements
- **Python:** Version 3.11 or newer (Python 3.14 verified)
- **Node.js:** Version 18 or newer (Node v25.2.0, npm 11.6.2 verified)
- **Docker & Docker Compose:** Version 20.10+ (Docker 29.1.2 verified)

### Quickstart Setup (Fresh Checkout)

```bash
# 1. Clone repository
git clone https://github.com/affanraza84/Bayora.git
cd Bayora

# 2. Verify environment prerequisites
./scripts/check-prereqs.sh

# 3. Create python virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# 4. Install dashboard dependencies
cd apps/dashboard && npm install && cd ../..

# 5. Initialize configuration
cp .env.example .env

# 6. Apply database migrations
.venv/bin/alembic upgrade head
```

---

## 6. How to Run the Security Suite & Demo

### 1. Run Automated Security Test Suite (62 Tests)
```bash
make test-security
```
Executes all 5 test suites across unit, isolation, adversarial, integration, and performance layers:
- **Unit Tests (28 tests):** SHA-256 hash chaining, sequence gap tamper detection, event deletion/reordering, KeyRegistry trusted/untrusted public key verification, key rotation historical validation, stored checkpoint tamper detection, EvidenceBundle verification, tampered payload digest detection, JWT algorithm none rejection, issuer/audience validation, RBAC boundaries.
- **Enclave Isolation Tests (11 tests):** Live Docker L3 IP routing drops, DNS failure verification, absent Docker socket, read-only root filesystems, cgroup v2 memory/CPU limits, and port binding audits.
- **Adversarial & Guardrail Tests (10 tests):** Harmless prompt injection (`INP-001`), roleplay escape (`INP-002`), credential harvesting (`INP-003`), canary disclosure redaction (`OUT-001`), system prompt leakage (`OUT-002`), zero false positives on benign queries.
- **Integration Tests (10 tests):** Control plane health, authentication, run lifecycle, duplicate execution guard, cross-tenant IDOR protection, findings, isolation lab endpoints, stored checkpoint tamper rejection, and stored evidence bundle signature verification.
- **Performance Tests (3 tests):** Latency percentiles, resource limit assertions, synthetic pipeline benchmarks.

### 2. Run the 9-Step Automated Judge Demo Script
```bash
./scripts/demo.sh
```
Executes the complete end-to-end evaluation, launches container probes, runs the adversarial pipeline, executes the 6 isolation scenarios, and verifies stored cryptographic audit checkpoints and evidence bundles against trusted public keys.

### 3. Launch the Web Dashboard
```bash
# Terminal 1: Start Control Plane
.venv/bin/uvicorn services.control_plane.main:app --port 8080

# Terminal 2: Start Next.js Dashboard
cd apps/dashboard && npm run dev
```
Open **[http://localhost:3000](http://localhost:3000)** in your browser.

---

## 7. 3-Minute Hackathon Judge Demo Script

> **Full Word-for-Word Script & Visual Actions:** See [`docs/demo-script.md`](docs/demo-script.md)

| Timing | Section | Actions & Talking Points |
| :--- | :--- | :--- |
| **0:00 - 0:25** | **Problem & Solution** | Show `docs/threat-model.md`. Explain the core dilemma: How do red teams test AI models without stealing blue team defense rules or leaking proprietary model canary tokens? Introduce Bayora Shield's multi-enclave model. |
| **0:25 - 0:55** | **Architecture & Boundaries** | Highlight Enclave Topology in dashboard. Point to 3 isolated enclaves: Red Worker, Blue Worker, and Model Gateway separated by internal Linux bridge networks with dropped kernel routes and cgroup quotas. |
| **0:55 - 1:35** | **Trigger Adversarial Evaluation** | In dashboard (or `./scripts/demo.sh`), click **"Provision New Run"** and **"Execute"**. Point out: 5 attacks blocked by Blue Guardrails before reaching LLM (`INP-001` prompt injection, `INP-002` jailbreak, `INP-003` exfiltration). |
| **1:35 - 2:05** | **Canary Finding (CWE-200)** | In Findings tab, explain Test Case 4: Canary query elicited model disclosure, but Blue Egress Guardrail `OUT-001` intercepted and redacted it to `[REDACTED_BY_BLUE_GUARDRAIL]`. Emphasize: **Model Safety Vulnerability (CWE-200)**, **NOT** an infrastructure escape (0 Enclave Breaches). |
| **2:05 - 2:35** | **Isolation Lab & Cryptographic Audit** | Run Isolation Lab: Show Red-to-Blue network probe dropped (`Errno 101`) and read-only root verified. In Audit Explorer, click **"Verify Cryptographic Chain"**: Show green `VALID` badge, unbroken SHA-256 chain, and genuine stored Ed25519 checkpoint verification against the trusted key registry. |
| **2:35 - 3:00** | **Performance, Limits & Roadmap** | Review benchmark metrics (1.4ms guardrail overhead). Explain prototype limitations (Docker cgroups vs. AWS Firecracker microVMs; mock model vs. live LLMs; local key registry vs. cloud HSM). |

---

## 8. Verified Isolation vs. Known Limitations

To maintain absolute credibility, Bayora Shield explicitly distinguishes **empirically verified controls** from **prototype limitations**:

### Empirically Verified Controls
- **L3 Kernel Routing Drops:** Docker bridge networks with `internal: true` prevent inter-enclave packet traversal even when DNS is bypassed.
- **Read-Only Roots:** Workers cannot write executable binaries or modify files outside `/tmp` (mounted with `noexec,nosuid`).
- **Cgroup Quotas:** Hard memory ceilings (512MB) and CPU quotas (1.0 CPU) verified directly in `/sys/fs/cgroup/memory.max`.
- **Zero Host Port Exposure:** Internal databases and workers bind zero public host ports.
- **Stateless LLM Context:** Successive turns generate clean ephemeral UUIDs; no prior turn memory is retained.
- **Stored Audit Verification:** Checkpoints and evidence bundles are signed at creation and verified against trusted public keys during audit (no in-flight signature forgery).

### Known Prototype Limitations & Production Roadmap
1. **Container vs. MicroVM Isolation:**  
   Docker containers share the host Linux kernel. While effective against standard application exploits, kernel privilege escalation vulnerabilities could breach container boundaries. *Production Roadmap:* Migrate worker execution to dedicated AWS Firecracker microVMs or gVisor `runsc`.
2. **Regex Baselines vs. Semantic Injection:**  
   The current Blue Team engine uses deterministic regex filters in `base_guardrails.json`. While 100% reproducible for CI/CD, regex is vulnerable to complex token obfuscation. *Production Roadmap:* Pair regex filters with local embedding-similarity classifiers and LLM-as-a-judge secondary verification.
3. **Mock Provider vs. Live LLM Sampling:**  
   The default evaluation pipeline uses a deterministic mock model provider so the system functions offline without external API keys. Benchmarked latency (<5ms) reflects local IPC overhead, not real cloud LLM generation time (300ms–2000ms).
4. **Prototype Key Custody:**  
   The prototype uses configured development Ed25519 signing keys and an in-memory trusted `KeyRegistry` supporting key rotation. In production, signing keys must be held within a FIPS 140-2 Level 3 Hardware Security Module (HSM) or AWS KMS / GCP Cloud KMS with hardware enclave attestation.

---

## 9. Deployment Decision & Cloud Security Model

### Deployment Decision: Local Evaluation by Default
For this hackathon evaluation, Bayora Shield is packaged and verified as a **reproducible local Docker Compose multi-enclave cluster**.  
**Rationale:**
1. **Zero Attack Surface:** Running locally ensures internal enclaves, the database, and audit keys remain strictly unexposed to the public Internet during evaluation.
2. **Zero Secrets in Transit:** Evaluation requires no cloud credentials or third-party API keys.
3. **Deterministic Performance:** Local execution ensures tests and latency benchmarks are reproducible without cloud network jitter.

### Production Cloud Deployment Plan (If Public URL Required)
If a public cloud deployment is required by hackathon judges, execute the following hardened deployment architecture:
1. **Ingress Layer:** Deploy Next.js Dashboard to Vercel or AWS CloudFront/S3 with TLS 1.3 termination.
2. **Control Plane:** Deploy FastAPI backend to AWS ECS Fargate or Fly.io behind an Application Load Balancer with strict rate limiting and OAuth2/OIDC.
3. **Private VPC & Subnets:**
   - Place `bayora-database` and `bayora-audit-service` in isolated private subnets with Security Groups allowing traffic *only* from the Control Plane task.
   - Run worker containers inside dedicated AWS ECS tasks with task-level IAM roles and AWS VPC CNI for per-task security group isolation.
4. **Secrets Management:** Ingest `JWT_SECRET_KEY` and `ED25519_PRIVATE_KEY` directly from AWS Secrets Manager or HashiCorp Vault.
5. **Worker Hardening:** Run worker tasks using AWS Firecracker microVMs (via AWS Fargate) to guarantee hardware-assisted hypervisor isolation rather than shared Linux container namespaces.

---

## 10. Submission Deliverables & Documentation Index

For complete raw terminal logs, failure mode analyses, and cryptographic verification evidence, inspect:
- [`docs/demo-script.md`](docs/demo-script.md) — 3-Minute timed spoken script with exact UI clicks and fallback procedures
- [`docs/security-verification-report.md`](docs/security-verification-report.md) — Independent security audit, cgroup limits, and live network probe logs
- [`docs/architecture.md`](docs/architecture.md) — Multi-enclave system design, trust boundaries, and network topology
- [`docs/threat-model.md`](docs/threat-model.md) — STRIDE threat analysis, trust boundaries, and residual risk registry
- [`docs/access-control-matrix.md`](docs/access-control-matrix.md) — RBAC role permissions, tenant isolation, and API route security
- [`docs/api-contract.md`](docs/api-contract.md) — OpenAPI REST contract schemas for all endpoints
