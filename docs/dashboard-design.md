# Bayora Shield: Dashboard Design Specification

## 1. Visual Aesthetics & Philosophy

The Bayora Shield Security Operations Dashboard (`apps/dashboard`) is designed for operational clarity, technical depth, and high-stakes security observability.

### Aesthetic Foundation
- **Visual Palette:** Monochromatic dark mode (`#0B0F17` background, `#111827` surface cards, `#1F2937` borders) with deliberate status accents:
  - **Adversarial Red:** `#EF4444` / `#DC2626` (Red-team probes, confirmed breaches, critical CWEs)
  - **Defensive Blue:** `#3B82F6` / `#2563EB` (Blue-team rules, guardrail triggers, mitigations)
  - **Cryptographic Amber/Gold:** `#F59E0B` (Ed25519 signatures, audit checkpoints, hash continuity)
  - **Operational Emerald:** `#10B981` (Healthy services, passed isolation tests)
- **Typography:** High-legibility monospaced typeface for hashes, timestamps, and sequence numbers (`JetBrains Mono` / `Fira Code`); modern sans-serif for interface controls (`Inter`).
- **No Decorative Gimmicks:** Every element on screen corresponds directly to live database state or cryptographic verification outputs.

---

## 2. Core Operational Views & Navigation

```
+─────────────────────────────────────────────────────────────────────────────+
| [BAYORA SHIELD]   Tenant: Acme FinTech    Role: Platform Lead   (o) Healthy |
+─────────────────────────────────────────────────────────────────────────────+
| [NAV]  1. Mission Control (Overview)                                        |
|        2. Execution Topology (Red vs Blue vs Gateway)                       |
|        3. Isolation Lab (Live Sandbox Verification)                         |
|        4. Findings & Breaches (CWE & Proof)                                 |
|        5. Audit Explorer & Hash Chain Verifier                              |
|        6. Residual Risk & Threat Matrix                                     |
+─────────────────────────────────────────────────────────────────────────────+
```

### 2.1 Mission Control (Overview Metrics)
Displays high-level operational readiness and campaign metrics:
- **Active & Completed Runs:** Count, progress bar, target model identifiers.
- **Defense Efficacy Ratio:** Percentage of adversarial probes successfully neutralized by Blue guardrails (Input vs Output blocks).
- **Confirmed Breaches:** Real-time count of security findings flagged with severity badges (`CRITICAL`, `HIGH`, `MEDIUM`).
- **Cryptographic Audit Health:** Current sequence number, root SHA-256 hash preview, and Ed25519 checkpoint validity timestamp.

### 2.2 Execution Topology View
A live interactive visual map representing the three isolated enclaves:
- **Red Team Node:** Active payload generation, suite progress, isolation status (`red-net`).
- **Blue Team Node:** Active policy version (`v1.2-strict`), active regex filters, semantic firewalls (`blue-net`).
- **Model Gateway Node:** Model status (`gpt-4o-mini-mock`), token budget utilization, context freshness indicator (`model-net`).
- **Evaluator Core:** Highlights active message flows (Red -> Evaluator -> Blue -> Gateway -> Blue -> Red).

### 2.3 Isolation Lab (Interactive Security Simulation)
Enables operators and compliance officers to trigger live infrastructure assertion tests:
- **Action Button: "Test Network Boundaries"**:
  Dispatches `POST /api/isolation-tests` asserting that Red Worker cannot reach Blue Worker or the PostgreSQL database.
- **Action Button: "Test Egress Gating"**:
  Executes an outbound connection probe from within the worker container to external IP addresses.
- **Action Button: "Simulate Hash Chain Tampering"**:
  Executes a controlled test in a sandbox table to verify that an altered byte triggers an immediate `TAMPERING_DETECTED` alert.
- **Telemetry Console:** Live streaming terminal output showing exact command outcomes and exit codes.

### 2.4 Findings & Vulnerability Explorer
Structured inventory of detected flaws from adversarial test cases:
- Filterable by Severity, CWE category, and Run ID.
- Detailed drawer displaying:
  - Adversarial probe summary.
  - Guardrail response (why it was bypassed).
  - Redacted evidence snippet demonstrating the leak or injection.
  - Remediation advisory for Blue Team policy authors.

### 2.5 Audit Explorer & Verifier
A tamper-evident ledger interface:
- **Chain Visualizer:** Block-by-block representation of audit records displaying `sequence_number`, `actor`, `action`, `previous_hash`, and `event_hash`.
- **Integrity Verification Button ("Verify Entire Chain")**:
  Invokes `POST /api/audit/verify`. Upon completion, renders a green cryptographic verification badge with the verified Ed25519 signature and timestamp.
- **Export Evidence Bundle:** Download signed audit package and SHA-256 checksum for external audit submission.

### 2.6 Residual Risk & Known Limitations Page
A dedicated transparency view documenting:
- Shared kernel container limitations vs MicroVM isolation.
- Known side-channel risks (e.g., timing side channels).
- Active assumptions regarding upstream LLM provider infrastructure.

---

## 3. Technology Stack for Dashboard (apps/dashboard)

- **Framework:** Next.js (App Router, React 19 / TypeScript).
- **Styling:** Tailwind CSS with custom dark color tokens (`slate-950`, `zinc-900`, `red-500`, `blue-500`, `emerald-500`).
- **Icons:** Lucide React (`Shield`, `Terminal`, `Lock`, `AlertTriangle`, `CheckCircle2`, `Activity`).
- **Data Fetching:** Native fetch with React Server Components + client-side SWR/TanStack Query for live polling of run telemetry.
