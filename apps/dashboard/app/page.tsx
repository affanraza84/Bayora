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

export default function DashboardHome() {
  const [token, setToken] = useState<string | null>(null);
  const [healthStatus, setHealthStatus] = useState<HealthData | null>(null);
  const [runs, setRuns] = useState<RunData[]>([]);
  const [findings, setFindings] = useState<FindingData[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEventData[]>([]);
  const [verifyResult, setVerifyResult] = useState<any>(null);
  const [isolationResult, setIsolationResult] = useState<any>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'topology' | 'isolation' | 'findings' | 'audit' | 'risk'>('overview');
  const [loading, setLoading] = useState<boolean>(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

  // Initialize or fetch dev authentication token
  const initToken = useCallback(async () => {
    try {
      const res = await fetch(`${apiUrl}/api/auth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: 'dashboard-lead',
          tenant_id: 'acme-fintech-sec',
          role: 'red_lead',
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setToken(data.access_token);
        return data.access_token;
      }
    } catch {
      // Backend not running locally
    }
    return null;
  }, [apiUrl]);

  // Fetch live state from backend
  const refreshData = useCallback(async (activeJwt?: string) => {
    const currentJwt = activeJwt || token;
    setLoading(true);
    setErrorMsg(null);

    try {
      // Health check
      const hRes = await fetch(`${apiUrl}/api/health`);
      if (hRes.ok) {
        setHealthStatus(await hRes.json());
      }

      if (currentJwt) {
        const headers = { Authorization: `Bearer ${currentJwt}` };

        // Fetch runs
        const rRes = await fetch(`${apiUrl}/api/runs`, { headers });
        if (rRes.ok) {
          const rData = await rRes.json();
          setRuns(rData.items || []);
        }

        // Fetch findings
        const fRes = await fetch(`${apiUrl}/api/findings`, { headers });
        if (fRes.ok) {
          const fData = await fRes.json();
          setFindings(fData.items || []);
        }

        // Fetch audit events
        const aRes = await fetch(`${apiUrl}/api/audit/events?limit=25`, { headers });
        if (aRes.ok) {
          const aData = await aRes.json();
          setAuditEvents(aData.events || []);
        }
      }
    } catch (e: any) {
      setErrorMsg(`Failed to connect to backend: ${e.message}`);
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
          suite_categories: ['PROMPT_INJECTION', 'JAILBREAK', 'SYSTEM_PROMPT_LEAK'],
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
      const data = await res.json();
      setVerifyResult(data);
    } catch (e: any) {
      setErrorMsg(`Verification call failed: ${e.message}`);
    } finally {
      setActionLoading(null);
    }
  };

  const handleRunIsolation = async (suite: string) => {
    if (!token) return;
    setActionLoading(`iso-${suite}`);
    setErrorMsg(null);
    try {
      // Switch to platform_admin token for isolation test
      const adminTokenRes = await fetch(`${apiUrl}/api/auth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: 'dashboard-admin',
          tenant_id: 'acme-fintech-sec',
          role: 'platform_admin',
        }),
      });
      const adminData = await adminTokenRes.json();

      const res = await fetch(`${apiUrl}/api/isolation-tests`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${adminData.access_token}`,
        },
        body: JSON.stringify({
          test_suite: suite,
          target_worker: 'worker-red-team',
        }),
      });
      const data = await res.json();
      setIsolationResult(data);
    } catch (e: any) {
      setErrorMsg(`Isolation probe failed: ${e.message}`);
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
              <span className="text-xs font-mono uppercase px-2 py-0.5 rounded bg-blue-950/80 text-blue-400 border border-blue-800/40">
                Phase 2 Core Active
              </span>
            </div>
            <p className="text-xs text-gray-400 font-mono">Isolated AI Adversarial Security Platform</p>
          </div>
        </div>

        <div className="flex items-center space-x-4">
          <button
            onClick={() => refreshData()}
            disabled={loading}
            className="flex items-center space-x-1 px-3 py-1.5 rounded bg-gray-800 hover:bg-gray-700 text-xs font-mono border border-gray-700 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Sync</span>
          </button>

          <div className="flex items-center space-x-2 text-xs font-mono bg-gray-800/80 px-2.5 py-1 rounded border border-gray-700">
            <span className="text-gray-400">TENANT:</span>
            <span className="text-gray-200 font-semibold">acme-fintech-sec</span>
          </div>

          <div className="flex items-center space-x-2 text-xs font-mono bg-gray-800/80 px-2.5 py-1 rounded border border-gray-700">
            <span className="text-gray-400">DB:</span>
            <span className={healthStatus?.services?.database === 'connected' ? 'text-emerald-400 font-semibold' : 'text-amber-400'}>
              {healthStatus?.services?.database || 'CONNECTING'}
            </span>
          </div>
        </div>
      </header>

      {/* Tabs */}
      <nav className="border-b border-[#1F2937] bg-[#0E1420] px-6 flex space-x-6">
        {[
          { id: 'overview', label: 'Mission Control', icon: Activity },
          { id: 'topology', label: 'Enclave Topology', icon: Network },
          { id: 'isolation', label: 'Isolation Lab', icon: Lock },
          { id: 'findings', label: `Findings (${findings.length})`, icon: AlertTriangle },
          { id: 'audit', label: `Audit Explorer (${auditEvents.length})`, icon: FileCheck },
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

      {/* Main Container */}
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

        {/* Overview Tab */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Top Metric Cards */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-[#111827] border border-[#1F2937] p-5 rounded-lg space-y-1">
                <span className="text-xs font-mono uppercase text-gray-400">Total Evaluation Runs</span>
                <div className="text-3xl font-bold font-mono text-white">{runs.length}</div>
                <div className="text-xs text-gray-500 font-mono">
                  {runs.filter((r) => r.status === 'completed').length} completed, {runs.filter((r) => r.status === 'created').length} created
                </div>
              </div>

              <div className="bg-[#111827] border border-[#1F2937] p-5 rounded-lg space-y-1">
                <span className="text-xs font-mono uppercase text-gray-400">Confirmed Breaches</span>
                <div className={`text-3xl font-bold font-mono ${findings.length > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                  {findings.length}
                </div>
                <div className="text-xs text-gray-500 font-mono">Canary & Prompt Leaks</div>
              </div>

              <div className="bg-[#111827] border border-[#1F2937] p-5 rounded-lg space-y-1">
                <span className="text-xs font-mono uppercase text-gray-400">Audit Ledger Events</span>
                <div className="text-3xl font-bold font-mono text-amber-400">{auditEvents.length}</div>
                <div className="text-xs text-gray-500 font-mono">SHA-256 Chained Links</div>
              </div>

              <div className="bg-[#111827] border border-[#1F2937] p-5 rounded-lg space-y-1">
                <span className="text-xs font-mono uppercase text-gray-400">Model Gateway</span>
                <div className="text-3xl font-bold font-mono text-purple-400">Stateless</div>
                <div className="text-xs text-gray-500 font-mono">Zero Context Leakage</div>
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
                              <span className="text-gray-500 text-[11px]">Finalized</span>
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

        {/* Isolation Lab Tab */}
        {activeTab === 'isolation' && (
          <div className="bg-[#111827] border border-[#1F2937] rounded-lg p-6 space-y-6">
            <div className="flex items-center justify-between border-b border-[#1F2937] pb-3">
              <div className="flex items-center space-x-2">
                <Lock className="w-4 h-4 text-red-400" />
                <h3 className="font-semibold text-sm uppercase tracking-wider text-white">Live Isolation Lab Probes</h3>
              </div>
              <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/40">
                Connected to Control Plane
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-[#0B0F17] p-4 rounded border border-gray-800 space-y-3">
                <span className="text-xs font-mono text-gray-200 font-bold">1. Network Boundary Assertion</span>
                <p className="text-xs text-gray-400">Verifies Docker network namespaces drop direct packets between worker-red and worker-blue.</p>
                <button
                  onClick={() => handleRunIsolation('NETWORK_BOUNDARIES')}
                  disabled={actionLoading === 'iso-NETWORK_BOUNDARIES'}
                  className="w-full py-2 bg-gray-800 hover:bg-gray-700 text-xs font-mono text-white rounded border border-gray-700 transition"
                >
                  {actionLoading === 'iso-NETWORK_BOUNDARIES' ? 'Probing...' : 'Probe Network Boundaries'}
                </button>
              </div>

              <div className="bg-[#0B0F17] p-4 rounded border border-gray-800 space-y-3">
                <span className="text-xs font-mono text-gray-200 font-bold">2. Egress Gating Check</span>
                <p className="text-xs text-gray-400">Asserts worker containers have default gateways disabled (internal: true).</p>
                <button
                  onClick={() => handleRunIsolation('EGRESS_GATING')}
                  disabled={actionLoading === 'iso-EGRESS_GATING'}
                  className="w-full py-2 bg-gray-800 hover:bg-gray-700 text-xs font-mono text-white rounded border border-gray-700 transition"
                >
                  {actionLoading === 'iso-EGRESS_GATING' ? 'Probing...' : 'Probe Egress Gating'}
                </button>
              </div>

              <div className="bg-[#0B0F17] p-4 rounded border border-gray-800 space-y-3">
                <span className="text-xs font-mono text-gray-200 font-bold">3. Audit Tamper Simulation</span>
                <p className="text-xs text-gray-400">Simulates unauthorized DB row mutation and tests sequence-level hash alert.</p>
                <button
                  onClick={() => handleRunIsolation('TAMPER_SIMULATION')}
                  disabled={actionLoading === 'iso-TAMPER_SIMULATION'}
                  className="w-full py-2 bg-gray-800 hover:bg-gray-700 text-xs font-mono text-white rounded border border-gray-700 transition"
                >
                  {actionLoading === 'iso-TAMPER_SIMULATION' ? 'Simulating...' : 'Simulate Tampering'}
                </button>
              </div>
            </div>

            {isolationResult && (
              <div className="bg-[#0B0F17] p-4 rounded border border-gray-800 font-mono text-xs space-y-2">
                <div className="flex items-center justify-between text-gray-400">
                  <span>PROBE RESULT [{isolationResult.test_suite}]</span>
                  <span className={isolationResult.result === 'PASSED' ? 'text-emerald-400 font-bold' : 'text-red-400'}>
                    STATUS: {isolationResult.result}
                  </span>
                </div>
                <pre className="text-gray-300 overflow-x-auto bg-[#070A0F] p-3 rounded">
                  {JSON.stringify(isolationResult.details, null, 2)}
                </pre>
              </div>
            )}
          </div>
        )}

        {/* Findings Tab */}
        {activeTab === 'findings' && (
          <div className="bg-[#111827] border border-[#1F2937] rounded-lg p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-[#1F2937] pb-3">
              <div className="flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4 text-red-400" />
                <h3 className="font-semibold text-sm uppercase tracking-wider text-white">Confirmed Vulnerabilities</h3>
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

        {/* Audit Tab */}
        {activeTab === 'audit' && (
          <div className="bg-[#111827] border border-[#1F2937] rounded-lg p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-[#1F2937] pb-3">
              <div className="flex items-center space-x-2">
                <FileCheck className="w-4 h-4 text-amber-400" />
                <h3 className="font-semibold text-sm uppercase tracking-wider text-white">
                  Cryptographic Audit Chain & Ed25519 Signatures
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
              <div className="bg-[#0B0F17] p-4 rounded border border-amber-900/60 font-mono text-xs space-y-1">
                <div className="flex items-center justify-between text-amber-400 font-bold">
                  <span>CHAIN VERIFICATION: {verifyResult.verification_status}</span>
                  <span>SIGNATURE: {verifyResult.ed25519_signature_status}</span>
                </div>
                <div className="text-gray-400">Events Evaluated: {verifyResult.events_evaluated}</div>
                <div className="text-gray-400 truncate">Root Hash: {verifyResult.root_hash}</div>
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
                        <span className={e.decision === 'ALLOW' ? 'text-emerald-400' : 'text-red-400'}>
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

        {/* Topology Tab */}
        {activeTab === 'topology' && (
          <div className="bg-[#111827] border border-[#1F2937] rounded-lg p-6 space-y-4">
            <h3 className="font-semibold text-sm uppercase tracking-wider text-white">Docker Network Isolation Topology</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
              <div className="bg-[#0B0F17] border border-red-900/40 p-4 rounded space-y-2">
                <span className="text-xs font-mono font-bold text-red-400">worker-red-team</span>
                <p className="text-xs text-gray-400">Enclave: red-net. Egress: Disabled. Read-only filesystem root.</p>
              </div>
              <div className="bg-[#0B0F17] border border-blue-900/40 p-4 rounded space-y-2">
                <span className="text-xs font-mono font-bold text-blue-400">worker-blue-team</span>
                <p className="text-xs text-gray-400">Enclave: blue-net. Egress: Disabled. Read-only filesystem root.</p>
              </div>
              <div className="bg-[#0B0F17] border border-purple-900/40 p-4 rounded space-y-2">
                <span className="text-xs font-mono font-bold text-purple-400">model-gateway</span>
                <p className="text-xs text-gray-400">Enclave: model-net. Gated egress to upstream model provider.</p>
              </div>
            </div>
          </div>
        )}

        {/* Residual Risk Tab */}
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
                <strong>Production Roadmap:</strong> In Phase 3 and production deployment, workers will execute inside Firecracker MicroVMs or gVisor sandbox runtimes with hardware security modules (HSM) for Ed25519 signing keys.
              </p>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-[#1F2937] bg-[#0E1420] px-6 py-4 text-center text-xs text-gray-500 font-mono">
        Bayora Shield — Phase 2 Functional Backend Core & Security Verified
      </footer>
    </div>
  );
}
