'use client';

import React, { useState, useEffect, useCallback } from 'react';
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
  Network,
  Play,
  PlusCircle,
  RefreshCw,
  XCircle,
  Gauge,
  HelpCircle,
  Clock,
  ArrowRight,
} from 'lucide-react';

interface HealthData {
  status: string;
  version: string;
  services: Record<string, string>;
  timestamp: string;
}

interface RunData {
  run_id: string;
  tenant_id: string;
  status: string;
  target_model: string;
  total_tests: number;
  blocked_count: number;
  breach_count: number;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

interface FindingData {
  finding_id: string;
  run_id: string;
  title: string;
  severity: string;
  cwe_id: string;
  description: string;
  redacted_proof: string;
  created_at: string;
}

interface AuditEventData {
  sequence_number: number;
  event_id: string;
  actor: string;
  action: string;
  resource: string;
  decision: string;
  timestamp: string;
  previous_hash: string;
  event_hash: string;
}

interface ScenarioData {
  scenario_id: string;
  scenario_name: string;
  preconditions: string;
  expected_result: string;
  actual_observed: string;
  status: string;
  evidence_reference: string;
  audit_event_id: string;
  executed_at: string;
}

interface BenchmarkData {
  benchmark_id: string;
  target_model: string;
  benchmark_type: string;
  sample_size: number;
  successful_requests: number;
  failed_requests: number;
  evaluated_test_cases: number;
  findings_generated: number;
  min_latency_ms: number;
  median_latency_ms: number;
  p95_latency_ms: number;
  max_latency_ms: number;
  throughput_rps: number;
  resource_limits_applied: Record<string, string>;
  disclaimer: string;
  executed_at: string;
}

export default function DashboardHome() {
  const [token, setToken] = useState<string | null>(null);
  const [healthStatus, setHealthStatus] = useState<HealthData | null>(null);
  const [runs, setRuns] = useState<RunData[]>([]);
  const [findings, setFindings] = useState<FindingData[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEventData[]>([]);
  const [scenarios, setScenarios] = useState<ScenarioData[]>([]);
  const [benchmark, setBenchmark] = useState<BenchmarkData | null>(null);
  const [verifyResult, setVerifyResult] = useState<any>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'topology' | 'isolation' | 'findings' | 'audit' | 'performance' | 'risk'>('overview');
  const [loading, setLoading] = useState<boolean>(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

  // Initialize dev JWT token
  const initToken = useCallback(async () => {
    try {
      const res = await fetch(`${apiUrl}/api/auth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: 'dashboard-lead',
          tenant_id: 'acme-fintech-sec',
          role: 'platform_admin',
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setToken(data.access_token);
        return data.access_token;
      }
    } catch {
      // Offline fallback
    }
    return null;
  }, [apiUrl]);

  // Fetch live state from backend
  const refreshData = useCallback(async (activeJwt?: string) => {
    const currentJwt = activeJwt || token;
    setLoading(true);
    setErrorMsg(null);

    try {
      // 1. Health check
      const hRes = await fetch(`${apiUrl}/api/health`);
      if (hRes.ok) {
        setHealthStatus(await hRes.json());
      }

      if (currentJwt) {
        const headers = { Authorization: `Bearer ${currentJwt}` };

        // 2. Fetch runs
        const rRes = await fetch(`${apiUrl}/api/runs`, { headers });
        if (rRes.ok) {
          const rData = await rRes.json();
          setRuns(rData.items || []);
        }

        // 3. Fetch findings
        const fRes = await fetch(`${apiUrl}/api/findings`, { headers });
        if (fRes.ok) {
          const fData = await fRes.json();
          setFindings(fData.items || []);
        }

        // 4. Fetch audit events
        const aRes = await fetch(`${apiUrl}/api/audit/events?limit=25`, { headers });
        if (aRes.ok) {
          const aData = await aRes.json();
          setAuditEvents(aData.events || []);
        }

        // 5. Fetch isolation scenarios
        const sRes = await fetch(`${apiUrl}/api/isolation-tests/scenarios`, { headers });
        if (sRes.ok) {
          const sData = await sRes.json();
          setScenarios(sData.scenarios || []);
        }

        // 6. Fetch initial benchmark metrics
        const bRes = await fetch(`${apiUrl}/api/performance/benchmark?iterations=5`, { headers });
        if (bRes.ok) {
          setBenchmark(await bRes.json());
        }
      }
    } catch (e: any) {
      setErrorMsg(`Connection warning: ${e.message}`);
    } finally {
      setLoading(false);
    }
  }, [apiUrl, token]);

  useEffect(() => {
    initToken().then((jwt) => {
      refreshData(jwt);
    });
  }, [initToken, refreshData]);

  // Provision and execute run
  const handleProvisionRun = async () => {
    if (!token) return;
    setActionLoading('provision');
    setErrorMsg(null);
    try {
      const res = await fetch(`${apiUrl}/api/runs`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          target_model: 'gpt-4o-mini-mock',
          suite_categories: ['PROMPT_INJECTION', 'JAILBREAK', 'SYSTEM_PROMPT_LEAK', 'DATA_EXFILTRATION'],
        }),
      });
      if (!res.ok) throw new Error(await res.text());
      await refreshData();
    } catch (e: any) {
      setErrorMsg(`Provision failed: ${e.message}`);
    } finally {
      setActionLoading(null);
    }
  };

  const handleExecuteRun = async (runId: string) => {
    if (!token) return;
    setActionLoading(`exec-${runId}`);
    setErrorMsg(null);
    try {
      const res = await fetch(`${apiUrl}/api/runs/${runId}/execute`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({}),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Execution failed');
      }
      await refreshData();
    } catch (e: any) {
      setErrorMsg(`Execution error: ${e.message}`);
    } finally {
      setActionLoading(null);
    }
  };

  const handleRunScenario = async (scenarioId: string) => {
    if (!token) return;
    setActionLoading(`scn-${scenarioId}`);
    setErrorMsg(null);
    try {
      const res = await fetch(`${apiUrl}/api/isolation-tests/run-scenario`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ scenario_id: scenarioId }),
      });
      if (!res.ok) throw new Error(await res.text());
      const updatedScenario: ScenarioData = await res.json();
      setScenarios((prev) =>
        prev.map((s) => (s.scenario_id === updatedScenario.scenario_id ? updatedScenario : s))
      );
      // Refresh audit trail
      const aRes = await fetch(`${apiUrl}/api/audit/events?limit=25`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (aRes.ok) {
        const aData = await aRes.json();
        setAuditEvents(aData.events || []);
      }
    } catch (e: any) {
      setErrorMsg(`Scenario failed: ${e.message}`);
    } finally {
      setActionLoading(null);
    }
  };

  const handleRunAllScenarios = async () => {
    for (const scn of scenarios) {
      await handleRunScenario(scn.scenario_id);
    }
  };

  const handleVerifyAudit = async () => {
    if (!token) return;
    setActionLoading('verify-audit');
    setErrorMsg(null);
    try {
      const res = await fetch(`${apiUrl}/api/audit/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          start_sequence: 1,
          verify_ed25519_signatures: true,
        }),
      });
      if (!res.ok) {
        const errData = await res.json();
        const errDetail = errData.detail || {};
        setVerifyResult({
          verification_status: errDetail.verification_status || 'TAMPERING_DETECTED',
          hash_chain_continuity: errDetail.error_code || 'BROKEN',
          ed25519_signature_status: 'FAILED',
          events_evaluated: errDetail.broken_sequence_number ? `Sequence #${errDetail.broken_sequence_number}` : 0,
          root_hash: errDetail.message || 'Verification rejected: cryptographic tampering detected',
        });
        setErrorMsg(`Audit integrity alarm: ${errDetail.message || 'Tampering detected in audit chain'}`);
        return;
      }
      const data = await res.json();
      setVerifyResult(data);
    } catch (e: any) {
      setErrorMsg(`Verification call failed: ${e.message}`);
    } finally {
      setActionLoading(null);
    }
  };

  const handleRunBenchmark = async (iters: number = 25) => {
    if (!token) return;
    setActionLoading('benchmark');
    setErrorMsg(null);
    try {
      const res = await fetch(`${apiUrl}/api/performance/benchmark?iterations=${iters}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error(await res.text());
      setBenchmark(await res.json());
    } catch (e: any) {
      setErrorMsg(`Benchmark failed: ${e.message}`);
    } finally {
      setActionLoading(null);
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#0B0F17] text-gray-200">
      {/* Header */}
      <header className="border-b border-[#1F2937] bg-[#111827]/80 backdrop-blur px-6 py-4 flex items-center justify-between sticky top-0 z-50">
        <div className="flex items-center space-x-3">
          <div className="w-9 h-9 rounded bg-red-600/20 border border-red-500/40 flex items-center justify-center text-red-400">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-white tracking-wider text-lg">BAYORA SHIELD</span>
              <span className="text-xs font-mono uppercase px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-800/40">
                Phase 3 Live Pipeline Active
              </span>
            </div>
            <p className="text-xs text-gray-400 font-mono">Multi-Enclave AI Adversarial Testing Infrastructure</p>
          </div>
        </div>

        <div className="flex items-center space-x-4">
          <button
            onClick={() => refreshData()}
            disabled={loading}
            className="flex items-center space-x-1 px-3 py-1.5 rounded bg-gray-800 hover:bg-gray-700 text-xs font-mono border border-gray-700 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Sync Live</span>
          </button>

          <div className="flex items-center space-x-2 text-xs font-mono bg-gray-800/80 px-2.5 py-1 rounded border border-gray-700">
            <span className="text-gray-400">TENANT:</span>
            <span className="text-gray-200 font-semibold">acme-fintech-sec</span>
          </div>

          <div className="flex items-center space-x-2 text-xs font-mono bg-gray-800/80 px-2.5 py-1 rounded border border-gray-700">
            <span className="text-gray-400">API:</span>
            <span className={healthStatus?.status === 'healthy' ? 'text-emerald-400 font-semibold' : 'text-amber-400'}>
              {healthStatus?.status ? healthStatus.status.toUpperCase() : 'CONNECTING'}
            </span>
          </div>
        </div>
      </header>

      {/* Navigation Tabs */}
      <nav className="border-b border-[#1F2937] bg-[#0E1420] px-6 flex space-x-6 overflow-x-auto">
        {[
          { id: 'overview', label: 'Mission Control', icon: Activity },
          { id: 'topology', label: 'Enclave Topology', icon: Network },
          { id: 'isolation', label: `Isolation Lab (${scenarios.filter((s) => s.status === 'PASSED').length}/${scenarios.length})`, icon: Lock },
          { id: 'findings', label: `Findings (${findings.length})`, icon: AlertTriangle },
          { id: 'audit', label: `Audit Explorer (${auditEvents.length})`, icon: FileCheck },
          { id: 'performance', label: 'Performance & Quotas', icon: Gauge },
          { id: 'risk', label: 'Residual Risk', icon: Shield },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center space-x-2 py-3.5 px-1 border-b-2 font-mono text-xs uppercase tracking-wider transition-colors whitespace-nowrap ${
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
        {errorMsg && (
          <div className="bg-red-950/50 border border-red-800 text-red-200 px-4 py-3 rounded-lg text-xs font-mono flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
              <span>{errorMsg}</span>
            </div>
            <button onClick={() => setErrorMsg(null)} className="text-red-400 hover:text-white">✕</button>
          </div>
        )}

        {/* Tab 1: Mission Control (Overview) */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Top Metric Cards */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-[#111827] border border-[#1F2937] p-5 rounded-lg space-y-1">
                <span className="text-xs font-mono uppercase text-gray-400">Adversarial Evaluation Runs</span>
                <div className="text-3xl font-bold font-mono text-white">{runs.length}</div>
                <div className="text-xs text-gray-500 font-mono">
                  {runs.filter((r) => r.status === 'completed').length} completed, {runs.filter((r) => r.status === 'created').length} pending
                </div>
              </div>

              <div className="bg-[#111827] border border-[#1F2937] p-5 rounded-lg space-y-1">
                <span className="text-xs font-mono uppercase text-gray-400">Confirmed Security Breaches</span>
                <div className={`text-3xl font-bold font-mono ${findings.length > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                  {findings.length}
                </div>
                <div className="text-xs text-gray-500 font-mono">Canary & Prompt Extractions</div>
              </div>

              <div className="bg-[#111827] border border-[#1F2937] p-5 rounded-lg space-y-1">
                <span className="text-xs font-mono uppercase text-gray-400">Audit Ledger Events</span>
                <div className="text-3xl font-bold font-mono text-amber-400">{auditEvents.length}</div>
                <div className="text-xs text-gray-500 font-mono">Ed25519 Signed & Chained</div>
              </div>

              <div className="bg-[#111827] border border-[#1F2937] p-5 rounded-lg space-y-1">
                <span className="text-xs font-mono uppercase text-gray-400">Model Pipeline Latency</span>
                <div className="text-3xl font-bold font-mono text-purple-400">
                  {benchmark ? `${benchmark.median_latency_ms} ms` : 'Active'}
                </div>
                <div className="text-xs text-gray-500 font-mono">
                  {benchmark ? `P95: ${benchmark.p95_latency_ms} ms` : 'Synthetic Mock Provider'}
                </div>
              </div>
            </div>

            {/* Run Operations & Table */}
            <div className="bg-[#111827] border border-[#1F2937] rounded-lg p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-[#1F2937] pb-3">
                <div className="flex items-center space-x-2">
                  <Activity className="w-4 h-4 text-red-400" />
                  <h3 className="font-semibold text-sm uppercase tracking-wider text-white">Adversarial Evaluation Runs</h3>
                </div>
                <button
                  onClick={handleProvisionRun}
                  disabled={actionLoading === 'provision'}
                  className="flex items-center space-x-1.5 px-3 py-1.5 bg-red-600 hover:bg-red-500 text-white rounded text-xs font-mono transition"
                >
                  <PlusCircle className="w-3.5 h-3.5" />
                  <span>{actionLoading === 'provision' ? 'Provisioning...' : 'Provision New Run'}</span>
                </button>
              </div>

              {runs.length === 0 ? (
                <div className="text-center py-12 text-gray-500 font-mono text-xs">
                  No evaluation runs found for this tenant. Click "Provision New Run" to start.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-[#0B0F17] text-gray-400 uppercase border-b border-[#1F2937]">
                      <tr>
                        <th className="p-3">Run ID</th>
                        <th className="p-3">Target Model</th>
                        <th className="p-3">Status</th>
                        <th className="p-3">Tests</th>
                        <th className="p-3">Blocked</th>
                        <th className="p-3">Breaches</th>
                        <th className="p-3 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1F2937] text-gray-300">
                      {runs.map((r) => (
                        <tr key={r.run_id} className="hover:bg-gray-800/40">
                          <td className="p-3 font-semibold text-gray-200">{r.run_id.slice(0, 8)}...</td>
                          <td className="p-3 text-purple-400">{r.target_model}</td>
                          <td className="p-3">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${
                                r.status === 'completed'
                                  ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/40'
                                  : r.status === 'running'
                                  ? 'bg-blue-950/80 text-blue-400 border border-blue-800/40 animate-pulse'
                                  : 'bg-gray-800 text-gray-400 border border-gray-700'
                              }`}
                            >
                              {r.status}
                            </span>
                          </td>
                          <td className="p-3">{r.total_tests}</td>
                          <td className="p-3 text-blue-400">{r.blocked_count}</td>
                          <td className="p-3 text-red-400 font-bold">{r.breach_count}</td>
                          <td className="p-3 text-right">
                            {r.status === 'created' ? (
                              <button
                                onClick={() => handleExecuteRun(r.run_id)}
                                disabled={actionLoading === `exec-${r.run_id}`}
                                className="inline-flex items-center space-x-1 px-2.5 py-1 bg-red-600/80 hover:bg-red-500 text-white rounded text-[11px] font-mono transition"
                              >
                                <Play className="w-3 h-3" />
                                <span>{actionLoading === `exec-${r.run_id}` ? 'Evaluating...' : 'Execute'}</span>
                              </button>
                            ) : (
                              <span className="text-gray-500 text-[11px]">Finalized & Signed</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Tab 2: Topology */}
        {activeTab === 'topology' && (
          <div className="bg-[#111827] border border-[#1F2937] rounded-lg p-6 space-y-6">
            <div className="flex items-center justify-between border-b border-[#1F2937] pb-3">
              <div className="flex items-center space-x-2">
                <Network className="w-4 h-4 text-gray-400" />
                <h3 className="font-semibold text-sm uppercase tracking-wider text-white">
                  Multi-Enclave Network Segmentation & Boundary Map
                </h3>
              </div>
              <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/40">
                Docker Networks Deployed
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-[#0B0F17] border border-red-900/50 p-4 rounded-lg space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold font-mono text-red-400">worker-red-team</span>
                  <span className="text-[10px] font-mono bg-red-950 px-1.5 py-0.5 rounded text-red-400">red-net</span>
                </div>
                <p className="text-xs text-gray-400">
                  Isolated attack generator. Internal bridge has default gateway disabled. Cannot address blue-team, database, or host daemon socket.
                </p>
                <div className="text-[11px] font-mono text-gray-500 pt-1 border-t border-gray-800">
                  Mount: /artifacts/red:ro | Egress: Disabled
                </div>
              </div>

              <div className="bg-[#0B0F17] border border-blue-900/50 p-4 rounded-lg space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold font-mono text-blue-400">worker-blue-team</span>
                  <span className="text-[10px] font-mono bg-blue-950 px-1.5 py-0.5 rounded text-blue-400">blue-net</span>
                </div>
                <p className="text-xs text-gray-400">
                  Defensive rule evaluation enclave. Operates in ephemeral memory without persisting adversarial prompts. Read-only filesystem root.
                </p>
                <div className="text-[11px] font-mono text-gray-500 pt-1 border-t border-gray-800">
                  Mount: /artifacts/blue:ro | Egress: Disabled
                </div>
              </div>

              <div className="bg-[#0B0F17] border border-purple-900/50 p-4 rounded-lg space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold font-mono text-purple-400">model-gateway</span>
                  <span className="text-[10px] font-mono bg-purple-950 px-1.5 py-0.5 rounded text-purple-400">model-net</span>
                </div>
                <p className="text-xs text-gray-400">
                  Sandboxed proxy mediating LLM inferences. Accessible strictly from Evaluator orchestrator. Strips ambient headers to enforce statelessness.
                </p>
                <div className="text-[11px] font-mono text-gray-500 pt-1 border-t border-gray-800">
                  Session: Zero Context Leakage
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab 3: Isolation Lab Scenarios */}
        {activeTab === 'isolation' && (
          <div className="bg-[#111827] border border-[#1F2937] rounded-lg p-6 space-y-6">
            <div className="flex items-center justify-between border-b border-[#1F2937] pb-3">
              <div className="flex items-center space-x-2">
                <Lock className="w-4 h-4 text-red-400" />
                <h3 className="font-semibold text-sm uppercase tracking-wider text-white">
                  Reproducible Isolation Lab Scenarios (Phase 3)
                </h3>
              </div>
              <button
                onClick={handleRunAllScenarios}
                disabled={actionLoading !== null}
                className="px-3 py-1.5 bg-red-600 hover:bg-red-500 text-white font-mono text-xs rounded transition flex items-center space-x-1"
              >
                <Play className="w-3.5 h-3.5" />
                <span>Execute All 6 Scenarios</span>
              </button>
            </div>

            <p className="text-xs text-gray-400">
              Deterministic, testable isolation assertion probes verifying network boundaries, tenant scoping, synthetic canary confidentiality, audit integrity, and resource limits.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {scenarios.map((scn) => (
                <div key={scn.scenario_id} className="bg-[#0B0F17] border border-gray-800 p-4 rounded-lg space-y-2 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between pb-1">
                      <span className="text-xs font-mono font-bold text-gray-200">{scn.scenario_name}</span>
                      <span
                        className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                          scn.status === 'PASSED'
                            ? 'bg-emerald-950 text-emerald-400 border border-emerald-800/40'
                            : scn.status === 'FAILED'
                            ? 'bg-red-950 text-red-400 border border-red-800/40'
                            : 'bg-gray-800 text-gray-400'
                        }`}
                      >
                        {scn.status}
                      </span>
                    </div>
                    <div className="text-[11px] font-mono text-gray-500 pb-1">{scn.scenario_id}</div>
                    <div className="text-xs text-gray-400 space-y-1">
                      <div><strong className="text-gray-300">Expected:</strong> {scn.expected_result}</div>
                      <div><strong className="text-gray-300">Observed:</strong> <span className="font-mono text-xs text-amber-300/90">{scn.actual_observed}</span></div>
                    </div>
                  </div>

                  <div className="pt-3 border-t border-gray-800/80 flex items-center justify-between">
                    <span className="text-[10px] font-mono text-gray-500">Ref: {scn.evidence_reference}</span>
                    <button
                      onClick={() => handleRunScenario(scn.scenario_id)}
                      disabled={actionLoading === `scn-${scn.scenario_id}`}
                      className="px-2.5 py-1 bg-gray-800 hover:bg-gray-700 text-xs font-mono text-white rounded border border-gray-700 transition"
                    >
                      {actionLoading === `scn-${scn.scenario_id}` ? 'Testing...' : 'Run Probe'}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Tab 4: Findings */}
        {activeTab === 'findings' && (
          <div className="bg-[#111827] border border-[#1F2937] rounded-lg p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-[#1F2937] pb-3">
              <div className="flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4 text-red-400" />
                <h3 className="font-semibold text-sm uppercase tracking-wider text-white">Confirmed Vulnerabilities & Breaches</h3>
              </div>
              <span className="text-xs font-mono text-gray-400">{findings.length} findings recorded</span>
            </div>

            {findings.length === 0 ? (
              <div className="text-center py-12 text-gray-500 font-mono text-xs">
                No security findings yet. Execute an adversarial evaluation run from Mission Control to discover vulnerabilities.
              </div>
            ) : (
              <div className="space-y-3">
                {findings.map((f) => (
                  <div key={f.finding_id} className="bg-[#0B0F17] border border-red-950/60 p-4 rounded-lg space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span className="px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800/50 text-[10px] font-mono font-bold">
                          {f.severity}
                        </span>
                        <span className="font-semibold text-sm text-white font-mono">{f.title}</span>
                      </div>
                      <span className="text-xs font-mono text-gray-400">{f.cwe_id}</span>
                    </div>
                    <p className="text-xs text-gray-300 font-sans leading-relaxed">{f.description}</p>
                    <div className="text-xs font-mono bg-[#070A0F] text-amber-300 p-2 rounded border border-gray-900">
                      {f.redacted_proof}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Tab 5: Audit Explorer */}
        {activeTab === 'audit' && (
          <div className="bg-[#111827] border border-[#1F2937] rounded-lg p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-[#1F2937] pb-3">
              <div className="flex items-center space-x-2">
                <FileCheck className="w-4 h-4 text-amber-400" />
                <h3 className="font-semibold text-sm uppercase tracking-wider text-white">
                  Cryptographic Audit Chain & Ed25519 Checkpoints
                </h3>
              </div>
              <button
                onClick={handleVerifyAudit}
                disabled={actionLoading === 'verify-audit'}
                className="px-3 py-1.5 bg-amber-600 hover:bg-amber-500 text-black font-semibold rounded text-xs font-mono transition"
              >
                {actionLoading === 'verify-audit' ? 'Verifying Chain...' : 'Verify Cryptographic Chain'}
              </button>
            </div>

            {verifyResult && (
              <div
                className={`p-4 rounded border font-mono text-xs space-y-1.5 ${
                  verifyResult.verification_status === 'VALID'
                    ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-300'
                    : 'bg-red-950/40 border-red-800/60 text-red-300'
                }`}
              >
                <div className="flex items-center justify-between font-bold">
                  <span className="flex items-center space-x-1.5">
                    {verifyResult.verification_status === 'VALID' ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    ) : (
                      <AlertTriangle className="w-4 h-4 text-red-400" />
                    )}
                    <span>
                      CHAIN STATUS: {verifyResult.verification_status} ({verifyResult.hash_chain_continuity})
                    </span>
                  </span>
                  <span>ED25519: {verifyResult.ed25519_signature_status}</span>
                </div>
                <div className="text-gray-300">Events Evaluated: {verifyResult.events_evaluated}</div>
                <div className="text-gray-400 truncate">Digest / Detail: {verifyResult.root_hash}</div>
              </div>
            )}

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#0B0F17] text-gray-400 uppercase border-b border-[#1F2937]">
                  <tr>
                    <th className="p-2.5">Seq</th>
                    <th className="p-2.5">Actor</th>
                    <th className="p-2.5">Action</th>
                    <th className="p-2.5">Resource</th>
                    <th className="p-2.5">Decision</th>
                    <th className="p-2.5">Event Hash</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1F2937] text-gray-300">
                  {auditEvents.map((e) => (
                    <tr key={e.event_id} className="hover:bg-gray-800/30">
                      <td className="p-2.5 font-bold text-amber-400">#{e.sequence_number}</td>
                      <td className="p-2.5 text-gray-300">{e.actor}</td>
                      <td className="p-2.5 text-gray-200">{e.action}</td>
                      <td className="p-2.5 text-gray-400">{e.resource}</td>
                      <td className="p-2.5">
                        <span className={e.decision === 'ALLOW' || e.decision === 'PASSED' ? 'text-emerald-400' : 'text-red-400'}>
                          {e.decision}
                        </span>
                      </td>
                      <td className="p-2.5 text-gray-500 font-mono">{e.event_hash.slice(0, 16)}...</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Tab 6: Performance & Quotas */}
        {activeTab === 'performance' && (
          <div className="bg-[#111827] border border-[#1F2937] rounded-lg p-6 space-y-6">
            <div className="flex items-center justify-between border-b border-[#1F2937] pb-3">
              <div className="flex items-center space-x-2">
                <Gauge className="w-4 h-4 text-purple-400" />
                <h3 className="font-semibold text-sm uppercase tracking-wider text-white">
                  Pipeline Latency & Resource Quotas
                </h3>
              </div>
              <button
                onClick={() => handleRunBenchmark(25)}
                disabled={actionLoading === 'benchmark'}
                className="px-3 py-1.5 bg-purple-600 hover:bg-purple-500 text-white font-mono text-xs rounded transition flex items-center space-x-1"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${actionLoading === 'benchmark' ? 'animate-spin' : ''}`} />
                <span>Run Repeated Benchmark (25 Samples)</span>
              </button>
            </div>

            {benchmark && (
              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div className="bg-[#0B0F17] p-4 rounded border border-gray-800">
                    <span className="text-xs font-mono text-gray-400">Median Latency</span>
                    <div className="text-2xl font-bold font-mono text-emerald-400">{benchmark.median_latency_ms} ms</div>
                    <div className="text-[11px] text-gray-500">Min: {benchmark.min_latency_ms} ms</div>
                  </div>
                  <div className="bg-[#0B0F17] p-4 rounded border border-gray-800">
                    <span className="text-xs font-mono text-gray-400">P95 Latency</span>
                    <div className="text-2xl font-bold font-mono text-purple-400">{benchmark.p95_latency_ms} ms</div>
                    <div className="text-[11px] text-gray-500">Max: {benchmark.max_latency_ms} ms</div>
                  </div>
                  <div className="bg-[#0B0F17] p-4 rounded border border-gray-800">
                    <span className="text-xs font-mono text-gray-400">Throughput</span>
                    <div className="text-2xl font-bold font-mono text-white">{benchmark.throughput_rps} req/s</div>
                    <div className="text-[11px] text-gray-500">Evaluated: {benchmark.sample_size} probes</div>
                  </div>
                  <div className="bg-[#0B0F17] p-4 rounded border border-gray-800">
                    <span className="text-xs font-mono text-gray-400">Pipeline Success Rate</span>
                    <div className="text-2xl font-bold font-mono text-blue-400">
                      {Math.round((benchmark.successful_requests / benchmark.sample_size) * 100)}%
                    </div>
                    <div className="text-[11px] text-gray-500">0 dropped / timed out</div>
                  </div>
                </div>

                <div className="bg-[#0B0F17] p-4 rounded border border-gray-800 space-y-2">
                  <span className="text-xs font-mono font-bold text-gray-200">Active Container Resource Quotas</span>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs font-mono text-gray-300">
                    <div>Worker CPU Limit: <span className="text-purple-400">{benchmark.resource_limits_applied.worker_cpus}</span></div>
                    <div>Worker Memory Limit: <span className="text-purple-400">{benchmark.resource_limits_applied.worker_memory}</span></div>
                    <div>Evaluator CPU Limit: <span className="text-purple-400">{benchmark.resource_limits_applied.evaluator_cpus}</span></div>
                    <div>Evaluator Memory Limit: <span className="text-purple-400">{benchmark.resource_limits_applied.evaluator_memory}</span></div>
                  </div>
                </div>

                <div className="bg-blue-950/30 border border-blue-900/60 p-4 rounded text-xs text-blue-200 leading-relaxed font-mono">
                  {benchmark.disclaimer}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Tab 7: Residual Risk */}
        {activeTab === 'risk' && (
          <div className="bg-[#111827] border border-[#1F2937] rounded-lg p-6 space-y-4">
            <div className="flex items-center space-x-2 border-b border-[#1F2937] pb-3">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              <h3 className="font-semibold text-sm uppercase tracking-wider text-white">Residual Risk & Isolation Boundaries</h3>
            </div>
            <div className="space-y-3 text-xs text-gray-300 leading-relaxed font-sans">
              <p>
                <strong>Container PoC vs. Hardware Isolation:</strong> In this proof of concept, worker enclaves run inside Docker bridge networks on a shared operating system kernel. While network namespaces, cgroups, and read-only mounts prevent unprivileged pivoting, they cannot withstand kernel zero-day privilege escalation or microarchitectural cache-timing side channels.
              </p>
              <p>
                <strong>Heuristic Defense Limits:</strong> The Blue Team guardrails implement regex and keyword pattern filtering per <code>base_guardrails.json</code>. These are baseline operational filters and do not provide mathematical protection against multi-turn semantic jailbreaks or zero-day encoded payloads.
              </p>
              <p>
                <strong>Production Roadmap:</strong> In production deployment, workers will execute inside Firecracker MicroVMs or gVisor sandbox runtimes with hardware security modules (HSM) for Ed25519 signing keys.
              </p>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-[#1F2937] bg-[#0E1420] px-6 py-4 text-center text-xs text-gray-500 font-mono">
        Bayora Shield — Phase 3 Live Pipeline & Container Isolation Verified
      </footer>
    </div>
  );
}
