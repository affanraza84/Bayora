'use client';

import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Terminal, 
  Lock, 
  AlertTriangle, 
  CheckCircle2, 
  Activity, 
  Cpu, 
  Layers, 
  FileCheck,
  Server,
  Network
} from 'lucide-react';

export default function DashboardHome() {
  const [healthStatus, setHealthStatus] = useState<{
    status: string;
    version: string;
    services: Record<string, string>;
  } | null>(null);

  const [activeTab, setActiveTab] = useState<'overview' | 'topology' | 'isolation' | 'findings' | 'audit' | 'risk'>('overview');

  useEffect(() => {
    // Probe backend health endpoint (default local fallback for dev preview)
    const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    fetch(`${apiUrl}/api/health`)
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data) setHealthStatus(data);
      })
      .catch(() => {
        // Backend not running in static preview; keep default state
      });
  }, []);

  return (
    <div className="min-h-screen flex flex-col bg-[#0B0F17] text-gray-200">
      {/* Top Header */}
      <header className="border-b border-[#1F2937] bg-[#111827]/80 backdrop-blur px-6 py-4 flex items-center justify-between sticky top-0 z-50">
        <div className="flex items-center space-x-3">
          <div className="w-9 h-9 rounded bg-red-600/20 border border-red-500/40 flex items-center justify-center text-red-400">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-white tracking-wider text-lg">BAYORA SHIELD</span>
              <span className="text-xs font-mono uppercase px-2 py-0.5 rounded bg-gray-800 text-gray-400 border border-gray-700">
                Phase 1 Foundation
              </span>
            </div>
            <p className="text-xs text-gray-400 font-mono">Multi-Enclave AI Adversarial Testing Infrastructure</p>
          </div>
        </div>

        <div className="flex items-center space-x-6">
          <div className="flex items-center space-x-2 text-xs font-mono">
            <span className="text-gray-400">TENANT:</span>
            <span className="text-gray-200 font-semibold bg-gray-800 px-2 py-1 rounded">acme-fintech-sec</span>
          </div>

          <div className="flex items-center space-x-2 text-xs font-mono">
            <span className="text-gray-400">SYSTEM:</span>
            <span className="flex items-center space-x-1.5 text-emerald-400 font-semibold">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              <span>{healthStatus?.status ? healthStatus.status.toUpperCase() : 'INITIALIZED'}</span>
            </span>
          </div>
        </div>
      </header>

      {/* Main Navigation Tabs */}
      <nav className="border-b border-[#1F2937] bg-[#0E1420] px-6 flex space-x-6">
        {[
          { id: 'overview', label: 'Mission Control', icon: Activity },
          { id: 'topology', label: 'Enclave Topology', icon: Network },
          { id: 'isolation', label: 'Isolation Lab', icon: Lock },
          { id: 'findings', label: 'Findings & Breaches', icon: AlertTriangle },
          { id: 'audit', label: 'Audit Explorer', icon: FileCheck },
          { id: 'risk', label: 'Residual Risk', icon: Shield },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center space-x-2 py-3.5 px-1 border-b-2 font-mono text-xs uppercase tracking-wider transition-colors ${
                isActive
                  ? 'border-red-500 text-white font-semibold'
                  : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Main Content Area */}
      <main className="flex-1 p-6 max-w-7xl w-full mx-auto space-y-6">
        {/* Foundation Notice Banner */}
        <div className="bg-gradient-to-r from-blue-950/40 via-purple-950/20 to-red-950/30 border border-blue-800/40 rounded-lg p-4 flex items-start justify-between">
          <div className="flex space-x-3">
            <Layers className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
            <div className="space-y-1">
              <h3 className="text-sm font-semibold text-white">Phase 1 Architecture Foundation Active</h3>
              <p className="text-xs text-gray-300 leading-relaxed">
                Repository structure, threat modeling, network segregation policies, and SHA-256 hash chaining specifications established. Real-time run execution and live test workers are scheduled for Phase 2 implementation.
              </p>
            </div>
          </div>
          <span className="text-xs font-mono text-blue-400 bg-blue-950/80 px-2.5 py-1 rounded border border-blue-700/50 flex-shrink-0 ml-4">
            v0.1.0-alpha
          </span>
        </div>

        {/* Overview Tab Content */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Metric Cards Grid */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-[#111827] border border-[#1F2937] p-5 rounded-lg space-y-2">
                <span className="text-xs font-mono uppercase text-gray-400">Target Models</span>
                <div className="text-2xl font-bold font-mono text-white">gpt-4o-mini-mock</div>
                <div className="text-xs text-gray-500">Sandboxed via model-gateway</div>
              </div>

              <div className="bg-[#111827] border border-[#1F2937] p-5 rounded-lg space-y-2">
                <span className="text-xs font-mono uppercase text-gray-400">Blue Guardrail Status</span>
                <div className="text-2xl font-bold font-mono text-blue-400">v1.2-strict</div>
                <div className="text-xs text-gray-500">Pre & Post Sanitization Active</div>
              </div>

              <div className="bg-[#111827] border border-[#1F2937] p-5 rounded-lg space-y-2">
                <span className="text-xs font-mono uppercase text-gray-400">Network Segregation</span>
                <div className="text-2xl font-bold font-mono text-emerald-400">5 Bridges</div>
                <div className="text-xs text-gray-500">red-net & blue-net isolated</div>
              </div>

              <div className="bg-[#111827] border border-[#1F2937] p-5 rounded-lg space-y-2">
                <span className="text-xs font-mono uppercase text-gray-400">Audit Ledger</span>
                <div className="text-2xl font-bold font-mono text-amber-400">SHA-256 Chain</div>
                <div className="text-xs text-gray-500">Ed25519 Checkpoints Ready</div>
              </div>
            </div>

            {/* Architectural Trust Boundaries */}
            <div className="bg-[#111827] border border-[#1F2937] rounded-lg p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-[#1F2937] pb-3">
                <div className="flex items-center space-x-2">
                  <Server className="w-4 h-4 text-gray-400" />
                  <h3 className="font-semibold text-sm uppercase tracking-wider text-white">
                    Platform Service Enclaves & Boundaries
                  </h3>
                </div>
                <span className="text-xs font-mono text-gray-400">Specification Defined</span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
                {/* Red Team Enclave */}
                <div className="bg-[#0B0F17] border border-red-900/40 rounded-lg p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold font-mono text-red-400 uppercase tracking-wide">
                      Red Team Worker
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-950/80 text-red-400 border border-red-800/40">
                      red-net (isolated)
                    </span>
                  </div>
                  <p className="text-xs text-gray-400 leading-relaxed">
                    Executes automated attack suites (prompt injection, jailbreaks, canary exfiltration). Strictly denied access to Blue Team defense rules, model gateway, and database.
                  </p>
                  <div className="text-[11px] font-mono text-gray-500 pt-2 border-t border-gray-800">
                    Mount: /artifacts/red:ro | Egress: Disabled
                  </div>
                </div>

                {/* Blue Team Enclave */}
                <div className="bg-[#0B0F17] border border-blue-900/40 rounded-lg p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold font-mono text-blue-400 uppercase tracking-wide">
                      Blue Team Worker
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-950/80 text-blue-400 border border-blue-800/40">
                      blue-net (isolated)
                    </span>
                  </div>
                  <p className="text-xs text-gray-400 leading-relaxed">
                    Houses proprietary regex rules, semantic classifiers, and output sanitizers. Evaluates input probes in ephemeral memory without persisting adversarial prompts.
                  </p>
                  <div className="text-[11px] font-mono text-gray-500 pt-2 border-t border-gray-800">
                    Mount: /artifacts/blue:ro | Egress: Disabled
                  </div>
                </div>

                {/* Model Gateway Enclave */}
                <div className="bg-[#0B0F17] border border-purple-900/40 rounded-lg p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold font-mono text-purple-400 uppercase tracking-wide">
                      Model Gateway
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-950/80 text-purple-400 border border-purple-800/40">
                      model-net
                    </span>
                  </div>
                  <p className="text-xs text-gray-400 leading-relaxed">
                    Proxies inferences to local mock LLMs or cloud endpoints. Enforces token budgets, request timeouts, and stateless session isolation to prevent cross-turn contamination.
                  </p>
                  <div className="text-[11px] font-mono text-gray-500 pt-2 border-t border-gray-800">
                    Session: Stateless | Rate Limit: 100 req/min
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Topology Tab Content */}
        {activeTab === 'topology' && (
          <div className="bg-[#111827] border border-[#1F2937] rounded-lg p-6 space-y-4">
            <h3 className="font-semibold text-sm uppercase tracking-wider text-white">Docker Network Segmentation Matrix</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#0B0F17] text-gray-400 uppercase border-b border-[#1F2937]">
                  <tr>
                    <th className="p-3">Network Name</th>
                    <th className="p-3">Connected Services</th>
                    <th className="p-3">Egress Internet</th>
                    <th className="p-3">Isolation Invariant</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1F2937] text-gray-300">
                  <tr>
                    <td className="p-3 font-semibold text-red-400">red-net</td>
                    <td className="p-3">evaluator, worker-red-team</td>
                    <td className="p-3 text-red-400">Blocked (internal: true)</td>
                    <td className="p-3">Cannot reach blue-net, model-net, or database</td>
                  </tr>
                  <tr>
                    <td className="p-3 font-semibold text-blue-400">blue-net</td>
                    <td className="p-3">evaluator, worker-blue-team</td>
                    <td className="p-3 text-red-400">Blocked (internal: true)</td>
                    <td className="p-3">Cannot reach red-net, model-net, or database</td>
                  </tr>
                  <tr>
                    <td className="p-3 font-semibold text-purple-400">model-net</td>
                    <td className="p-3">evaluator, model-gateway</td>
                    <td className="p-3 text-emerald-400">Gated Model Egress</td>
                    <td className="p-3">Accepts inference calls exclusively from evaluator</td>
                  </tr>
                  <tr>
                    <td className="p-3 font-semibold text-amber-400">control-net</td>
                    <td className="p-3">dashboard, control-plane, database, audit-service</td>
                    <td className="p-3 text-gray-400">Standard Host Bridge</td>
                    <td className="p-3">PostgreSQL accessible only inside control-net</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Isolation Lab Content */}
        {activeTab === 'isolation' && (
          <div className="bg-[#111827] border border-[#1F2937] rounded-lg p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-[#1F2937] pb-3">
              <div className="flex items-center space-x-2">
                <Lock className="w-4 h-4 text-red-400" />
                <h3 className="font-semibold text-sm uppercase tracking-wider text-white">Isolation Lab & Security Assertion Harness</h3>
              </div>
              <span className="text-xs font-mono text-gray-400">Live Verification Tests</span>
            </div>
            <p className="text-xs text-gray-400">
              Trigger automated runtime assertions to verify that container boundaries, network routing tables, and tenant isolation policies match the security specification.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
              <div className="bg-[#0B0F17] p-4 rounded border border-gray-800 space-y-2">
                <span className="text-xs font-mono text-gray-300 font-semibold">Test 1: Red-to-Blue Network Probe</span>
                <p className="text-xs text-gray-500">Asserts TCP connection from worker-red to worker-blue:8002 is dropped.</p>
                <button 
                  onClick={() => alert("Isolation test execution runner scheduled for Phase 2 implementation.")}
                  className="w-full mt-2 py-1.5 px-3 bg-gray-800 hover:bg-gray-700 text-xs font-mono text-white rounded border border-gray-700 transition"
                >
                  Run Assertion Probe
                </button>
              </div>

              <div className="bg-[#0B0F17] p-4 rounded border border-gray-800 space-y-2">
                <span className="text-xs font-mono text-gray-300 font-semibold">Test 2: Worker Egress Lock</span>
                <p className="text-xs text-gray-500">Asserts outbound DNS & HTTP calls to external IPs are blocked.</p>
                <button 
                  onClick={() => alert("Isolation test execution runner scheduled for Phase 2 implementation.")}
                  className="w-full mt-2 py-1.5 px-3 bg-gray-800 hover:bg-gray-700 text-xs font-mono text-white rounded border border-gray-700 transition"
                >
                  Run Assertion Probe
                </button>
              </div>

              <div className="bg-[#0B0F17] p-4 rounded border border-gray-800 space-y-2">
                <span className="text-xs font-mono text-gray-300 font-semibold">Test 3: Audit Tamper Simulation</span>
                <p className="text-xs text-gray-500">Injects a modified byte into an audit event and tests detection.</p>
                <button 
                  onClick={() => alert("Isolation test execution runner scheduled for Phase 2 implementation.")}
                  className="w-full mt-2 py-1.5 px-3 bg-gray-800 hover:bg-gray-700 text-xs font-mono text-white rounded border border-gray-700 transition"
                >
                  Run Assertion Probe
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Findings & Breaches Tab */}
        {activeTab === 'findings' && (
          <div className="bg-[#111827] border border-[#1F2937] rounded-lg p-6 space-y-4">
            <h3 className="font-semibold text-sm uppercase tracking-wider text-white">Vulnerability Findings & Breach Catalog</h3>
            <p className="text-xs text-gray-400">
              Confirmed security findings discovered during evaluation runs are indexed with CWE classifications, redacted proofs, and remediation recommendations.
            </p>
            <div className="border border-dashed border-gray-800 rounded p-8 text-center space-y-2">
              <CheckCircle2 className="w-8 h-8 text-gray-600 mx-auto" />
              <div className="text-sm font-mono text-gray-400">No active run in progress.</div>
              <div className="text-xs text-gray-600">Findings will populate automatically when evaluation runs are dispatched in Phase 2.</div>
            </div>
          </div>
        )}

        {/* Audit Explorer Tab */}
        {activeTab === 'audit' && (
          <div className="bg-[#111827] border border-[#1F2937] rounded-lg p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-[#1F2937] pb-3">
              <div className="flex items-center space-x-2">
                <FileCheck className="w-4 h-4 text-amber-400" />
                <h3 className="font-semibold text-sm uppercase tracking-wider text-white">Audit Explorer & Cryptographic Verifier</h3>
              </div>
              <span className="text-xs font-mono text-amber-400 bg-amber-950/60 px-2 py-0.5 rounded border border-amber-800/40">
                Ed25519 & SHA-256
              </span>
            </div>
            <p className="text-xs text-gray-400">
              Audit events form an unbroken SHA-256 hash chain with periodic Ed25519 digital signatures.
            </p>
            <div className="bg-[#0B0F17] p-4 rounded border border-gray-800 font-mono text-xs text-gray-300 space-y-2">
              <div className="text-gray-500">// Canonical Hash Formula</div>
              <div className="text-amber-400">
                H_n = SHA-256(H_n-1 || seq_n || timestamp || actor || action || resource || payload_digest)
              </div>
            </div>
          </div>
        )}

        {/* Residual Risk Tab */}
        {activeTab === 'risk' && (
          <div className="bg-[#111827] border border-[#1F2937] rounded-lg p-6 space-y-4">
            <div className="flex items-center space-x-2 border-b border-[#1F2937] pb-3">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              <h3 className="font-semibold text-sm uppercase tracking-wider text-white">Residual Risk & Isolation Boundary Disclosure</h3>
            </div>
            <div className="space-y-3 text-xs text-gray-300 leading-relaxed">
              <p>
                <strong className="text-white">Proof of Concept Boundary Notice:</strong> Bayora Shield employs Docker container network namespaces and non-root users to isolate adversarial workers in the hackathon proof of concept. 
              </p>
              <p>
                Because all containers share the underlying operating system kernel, container isolation does not protect against zero-day Linux kernel vulnerabilities, physical host compromises, or microarchitectural cache-timing side channels.
              </p>
              <p>
                <strong className="text-white">Production Mitigation Roadmap:</strong> In production environments, worker enclaves will be provisioned using MicroVM virtualization (AWS Firecracker / gVisor) with per-run encrypted block storage and hardware security modules (HSM) for Ed25519 key storage.
              </p>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-[#1F2937] bg-[#0E1420] px-6 py-4 text-center text-xs text-gray-500 font-mono">
        Bayora Shield — Phase 1 Architecture & Cryptographic Foundations
      </footer>
    </div>
  );
}
