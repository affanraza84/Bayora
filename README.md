# Bayora Shield: Secure AI Adversarial Testing Infrastructure Platform

[![Security Tests](https://img.shields.io/badge/Security_Tests-Passing-emerald)](#)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Phase-1_Foundation_Complete-blue)](#)

> **Hackathon Mission:**
> Bayora Shield provides an isolated, multi-enclave adversarial testing platform that allows **Red Teams** to run automated security probes against target AI models without accessing **Blue Team** defensive rules, while ensuring the **Client LLM** evaluates requests without leaking model secrets or retaining cross-session context.

---

## 1. Core Architectural Innovations & Trust Enclaves

Bayora Shield segregates operations into three distinct isolated enclaves mediated by a trusted control plane:

1. **Red-Team Worker Enclave (`red-net`):**
   - Dispatches adversarial attack vectors (prompt injection, jailbreaks, canary extraction).
   - Zero access to Blue Team defense rules, model gateway direct endpoints, or relational database.
2. **Blue-Team Defense Enclave (`blue-net`):**
   - Applies pre-inference guardrails (regex, semantic filters) and post-inference output sanitizers.
   - Evaluates payloads in ephemeral memory without saving adversarial prompts to disk.
3. **Sandboxed Model Gateway (`model-net`):**
   - Proxies inference requests to local mock models or external LLM providers.
   - Enforces strict statelessness to prevent cross-session context contamination.
4. **Trusted Control Plane & Audit Service (`control-net`):**
   - Multi-tenant RBAC enforcement and run orchestration via FastAPI.
   - Append-only, SHA-256 hash-chained audit logging with periodic Ed25519 digital signatures.

```
+─────────────────────────────────────────────────────────────────────────────+
|               Next.js Security Operations Dashboard (Port 3000)             |
+──────────────────────────────────────┬──────────────────────────────────────+
                                       │ REST / mTLS
+──────────────────────────────────────▼──────────────────────────────────────+
|                 Control Plane (FastAPI) & PostgreSQL (Port 8000)            |
+───────────────────┬───────────────────────────────────┬─────────────────────+
                    │                                   │
      +─────────────▼─────────────+       +─────────────▼─────────────+
      |  Audit Service (Ed25519)  |       |    Evaluator Orchestrator   |
      +───────────────────────────+       +─────────────┬─────────────+
                                                        │
         ┌──────────────────────────────────────────────┼────────────────────────────────────────┐
         │ (red-net)                                    │ (blue-net)                             │ (model-net)
+────────▼────────+                            +────────▼────────+                      +────────▼────────+
| Red Team Worker |                            | Blue Team Worker|                      |  Model Gateway  |
+─────────────────+                            +─────────────────+                      +─────────────────+
```

---

## 2. Monorepo Structure

```
Bayora/
├── apps/
│   └── dashboard/                  # Next.js 14 + Tailwind CSS Security Operations Dashboard
├── services/
│   ├── control-plane/              # FastAPI service: RBAC, runs, findings, tenant management
│   ├── audit-service/              # Cryptographic SHA-256 hash chain & Ed25519 signing engine
│   ├── evaluator/                  # Run coordinator mediating Red, Blue, and Model Gateway
│   ├── model-gateway/              # Sandboxed egress proxy for LLM inference calls
│   └── workers/
│       ├── red-team/               # Isolated adversarial test generator
│       └── blue-team/              # Isolated defense rule & guardrail evaluator
├── infrastructure/
│   ├── compose/
│   │   └── docker-compose.yml      # Multi-network bridge topology (red-net, blue-net, etc.)
│   ├── security/
│   │   └── key_management_spec.md  # Cryptographic key specs and zero-plaintext secrets policy
│   └── policies/
│       └── base_guardrails.json    # Baseline Blue Team input/output guardrail rules
├── tests/
│   ├── unit/                       # Deterministic unit tests (Audit hash chain verification)
│   ├── integration/                # Service-to-service pipeline integration stubs
│   ├── isolation/                  # Container network boundary assertion harnesses
│   ├── adversarial/                # Prompt injection & jailbreak test cases
│   └── performance/                # Latency overhead and resource limit benchmarks
├── docs/
│   ├── architecture.md             # System components, trust zones, and sequence diagrams
│   ├── threat-model.md             # In-depth analysis of 10 primary threats and residual risks
│   ├── access-control-matrix.md    # RBAC rules for human roles and service identities
│   ├── data-model.md               # PostgreSQL DDL schema & ER diagram
│   ├── api-contract.md             # OpenAPI specifications for core platform endpoints
│   ├── acceptance-criteria.md      # Measurable Pass/Fail security criteria
│   └── dashboard-design.md         # UI layout, topology visualizer, and audit explorer specs
├── scripts/
│   └── check-prereqs.sh            # Prerequisites, dependency, and secret leak scanner
├── .env.example                    # Clean environment variable template (No raw secrets)
├── .gitignore                      # Git ignore patterns for Python, Node, Docker, and secrets
├── Makefile                        # Project automation and verification commands
└── pyproject.toml                  # Python package configuration and test runner settings
```

---

## 3. Getting Started & Verification

### Prerequisites
- **Python:** Version 3.11 or newer (Python 3.14 detected on system)
- **Node.js:** Version 18 or newer (Node v25.2.0, npm 11.6.2 detected)
- **Docker & Docker Compose:** Version 20.10+ (Docker 29.1.2 detected)

### Quickstart Commands

1. **Verify environment and prerequisites:**
   ```bash
   make check-prereqs
   ```

2. **Initialize configuration template:**
   ```bash
   make setup-env
   ```

3. **Execute unit tests (Audit cryptographic verification):**
   ```bash
   make test-unit
   ```

4. **Run all security assertions:**
   ```bash
   make test-security
   ```

5. **Start services with Docker Compose (Requires running Docker daemon):**
   ```bash
   make docker-up
   ```

6. **View the Security Dashboard:**
   Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 4. Security & Isolation Disclaimer

> **Important Boundary Disclosure:**
> In this hackathon proof-of-concept deployment, worker isolation relies on Docker bridge network namespaces, non-root user execution, and container cgroups. 
> 
> Because containers share the underlying operating system kernel, this does **not** provide mathematical or hardware-grade isolation against kernel zero-days, container escape vulnerabilities, or hardware cache-timing side channels. 
> 
> A production-grade deployment roadmap requires hardware micro-virtualization (AWS Firecracker / gVisor), dedicated physical hosts, and Hardware Security Modules (HSMs) for key custody.

---

## 5. Development Roadmap

- **Phase 1: Project Foundation, Architecture & Threat Modeling (Current - Completed)**
  - Repository structure initialized.
  - Complete architecture, threat model, RBAC matrix, schema, and API contracts documented.
  - Cryptographic SHA-256 hash chain and tamper detection unit tested.
  - Dark security dashboard foundation scaffolded.
  - Makefile and prereqs automation verified.
- **Phase 2: Core Isolation & Orchestration Implementation**
  - Implement FastAPI Control Plane endpoints (`/api/runs`, `/api/findings`, `/api/audit/*`).
  - Implement PostgreSQL migrations and SQLAlchemy repository layer.
  - Implement Evaluator state machine and step-by-step test runner.
  - Implement Red and Blue worker RPC microservices.
  - Implement automated isolation tests asserting network packet drops.
- **Phase 3: Security Operations Dashboard & Live Telemetry**
  - Connect Next.js dashboard to live backend endpoints.
  - Implement live terminal telemetry for Isolation Lab.
  - Implement block-by-block Audit Explorer with one-click cryptographic chain verification.
