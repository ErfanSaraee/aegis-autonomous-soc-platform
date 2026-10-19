"use client";

import React, { useEffect, useState, useCallback } from "react";
import {
    ShieldAlert,
    ShieldCheck,
    Cpu,
    Terminal,
    Activity,
    Lock,
    Play,
    CheckCircle2,
    AlertTriangle,
    Database,
    Sparkles,
    Network,
    RefreshCw,
    Code2,
    Eye,
    Zap,
} from "lucide-react";

const API_BASE =
    process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

interface NeuralAnomalyReport {
    pytorch_reconstruction_error: number;
    pytorch_attention_score: number;
    top_salient_log_tokens: Record<string, number>;
    xgboost_threat_probability: number;
    isolation_forest_anomaly: boolean;
    composite_anomaly_score: number;
    predicted_severity: string;
}

interface LogGuardrailReport {
    log_injection_detected: boolean;
    shannon_entropy: number;
    is_obfuscated_payload: boolean;
    pii_redacted_entities: string[];
    sanitized_log_payload: string;
    guardrail_notes: string[];
}

interface MITREIntelligenceHit {
    technique_id: string;
    technique_name: string;
    tactic: string;
    rrf_score: number;
    dense_vector_score: number;
    bm25_lexical_score: number;
    description: string;
    recommended_countermeasure: string;
}

interface ASTPlaybookVerification {
    is_safe: boolean;
    cyclomatic_complexity: number;
    violations: string[];
    inspected_nodes: string[];
}

interface DSPyTriageCalibration {
    false_positive_likelihood: number;
    calibrated_confidence: number;
    compiled_triage_rationale: string;
    applied_security_invariants: string[];
}

interface AgentExecutionStep {
    step_index: number;
    agent_name: string;
    framework: string;
    protocol: string;
    status: string;
    summary: string;
    latency_ms: number;
}

interface SOCIncidentResponse {
    incident_id: string;
    title: string;
    source_ip: string;
    target_host: string;
    event_source: string;
    severity: string;
    status: string;
    llm_provider_used: string;
    neural_anomaly: NeuralAnomalyReport;
    log_guardrail: LogGuardrailReport;
    mitre_tactic: string;
    mitre_technique_id: string;
    cti_rag_hits: MITREIntelligenceHit[];
    crewai_osint_report: string;
    dspy_calibration: DSPyTriageCalibration;
    executive_rca_summary: string;
    remediation_actions: string[];
    soar_python_playbook: string;
    ast_verification: ASTPlaybookVerification;
    hitl_approval_required: boolean;
    agent_trace: AgentExecutionStep[];
    created_at: string;
}

interface DashboardMetrics {
    total_incidents_analyzed: number;
    critical_p0_count: number;
    auto_contained_count: number;
    awaiting_hitl_count: number;
    false_positives_filtered: number;
    log_injections_blocked: number;
    mean_time_to_respond_ms: number;
    mitre_tactic_distribution: Record<string, number>;
}

const SCENARIO_BUTTONS = [
    {
        key: "apt29_log_injection_lsass",
        label: "APT-29 LSASS Dump + Log Prompt Injection",
        tag: "P0 CRITICAL",
        color: "border-rose-500/50 bg-rose-500/10 hover:bg-rose-500/20 text-rose-200",
    },
    {
        key: "ransomware_vssadmin_psexec",
        label: "BlackBasta Shadow Copy Delete + SMB PsExec",
        tag: "RANSOMWARE",
        color: "border-amber-500/50 bg-amber-500/10 hover:bg-amber-500/20 text-amber-200",
    },
    {
        key: "cobaltstrike_c2_exfiltration",
        label: "Cobalt Strike HTTP C2 Beacon + Exfiltration",
        tag: "C2 EXFIL",
        color: "border-purple-500/50 bg-purple-500/10 hover:bg-purple-500/20 text-purple-200",
    },
    {
        key: "benign_infra_backup_cron",
        label: "Nightly pg_dump Cron & Prometheus Probe",
        tag: "BENIGN (DSPy FP Filter)",
        color: "border-emerald-500/50 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-200",
    },
];

export default function AEGISSOCCommandCenter() {
    const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
    const [incidents, setIncidents] = useState<SOCIncidentResponse[]>([]);
    const [selectedIncident, setSelectedIncident] =
        useState<SOCIncidentResponse | null>(null);
    const [selectedProvider, setSelectedProvider] = useState<string>("anthropic");
    const [isLoading, setIsLoading] = useState<boolean>(false);
    const [hitlBanner, setHitlBanner] = useState<string | null>(null);

    const fetchSOCData = useCallback(async (selectLatest = false) => {
        try {
            const [metricsRes, incRes] = await Promise.all([
                fetch(`${API_BASE}/api/v1/soc/dashboard-metrics`),
                fetch(`${API_BASE}/api/v1/soc/incidents?limit=15`),
            ]);
            if (metricsRes.ok) {
                setMetrics(await metricsRes.json());
            }
            if (incRes.ok) {
                const list: SOCIncidentResponse[] = await incRes.json();
                setIncidents(list);
                if (list.length > 0 && (selectLatest || !selectedIncident)) {
                    setSelectedIncident(list[0]);
                }
            }
        } catch (err) {
            console.error("Failed to fetch SOC telemetry from FastAPI backend:", err);
        }
    }, [selectedIncident]);

    useEffect(() => {
        fetchSOCData(true);
    }, []);

    const handleSimulateScenario = async (scenarioKey: string) => {
        setIsLoading(true);
        setHitlBanner(null);
        try {
            const res = await fetch(
                `${API_BASE}/api/v1/soc/simulate/${scenarioKey}?llm_provider=${selectedProvider}`,
                { method: "POST" }
            );
            if (res.ok) {
                const newIncident: SOCIncidentResponse = await res.json();
                await fetchSOCData(false);
                setSelectedIncident(newIncident);
            }
        } finally {
            setIsLoading(false);
        }
    };

    const handleHITLApprove = async (incidentId: string, approve: boolean) => {
        setIsLoading(true);
        try {
            const res = await fetch(
                `${API_BASE}/api/v1/soc/incidents/${incidentId}/hitl-approve`,
                {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        responder_name: "Erfan Saraee (Principal SOC Commander)",
                        approve_containment: approve,
                        commander_notes: approve
                            ? "Verified MITRE ATT&CK chain and AST-safe SOAR script. Dispatched FastMCP Firewall + EDR quarantine."
                            : "Marked as false positive override by SOC Commander.",
                    }),
                }
            );
            if (res.ok) {
                const receipt = await res.json();
                setHitlBanner(
                    approve
                        ? `SOAR Containment Enforced via FastMCP & Celery! Status: ${receipt.status}`
                        : `Containment Rejected. Incident marked as ${receipt.status}`
                );
                await fetchSOCData(false);
                const detailRes = await fetch(
                    `${API_BASE}/api/v1/soc/incidents/${incidentId}`
                );
                if (detailRes.ok) {
                    setSelectedIncident(await detailRes.json());
                }
            }
        } finally {
            setIsLoading(false);
        }
    };

    const severityBadge = (sev: string) => {
        if (sev.includes("P0"))
            return "bg-rose-500/20 text-rose-300 border-rose-500/50";
        if (sev.includes("P1"))
            return "bg-amber-500/20 text-amber-300 border-amber-500/50";
        if (sev.includes("P2"))
            return "bg-yellow-500/20 text-yellow-300 border-yellow-500/50";
        if (sev.includes("BENIGN"))
            return "bg-emerald-500/20 text-emerald-300 border-emerald-500/50";
        return "bg-sky-500/20 text-sky-300 border-sky-500/50";
    };

    return (
        <div className="min-h-screen bg-[#060911] text-slate-100 flex flex-col">
            {/* Top Cyber Command Header */}
            <header className="border-b border-slate-800/80 bg-[#0b1120]/90 backdrop-blur sticky top-0 z-30 px-6 py-4">
                <div className="max-w-[1600px] mx-auto flex flex-wrap items-center justify-between gap-4">
                    <div className="flex items-center gap-3">
                        <div className="p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                            <ShieldAlert className="w-7 h-7" />
                        </div>
                        <div>
                            <div className="flex items-center gap-2.5">
                                <h1 className="text-xl font-bold tracking-tight text-white">
                                    AEGIS AUTONOMOUS SOC & SOAR COMMAND CENTER
                                </h1>
                                <span className="text-[11px] font-mono uppercase px-2.5 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                                    7-Node LangGraph • PyTorch • FastMCP
                                </span>
                            </div>
                            <p className="text-xs text-slate-400 mt-0.5">
                                Neural SIEM Anomaly Detection • Zero-Trust Log-Injection Guardrail • Hybrid MITRE ATT&CK RRF RAG • CrewAI OSINT • DSPy Calibration • Python AST Sandbox
                            </p>
                        </div>
                    </div>

                    {/* Multi-Provider LLM Router Switch */}
                    <div className="flex items-center gap-3">
                        <div className="flex items-center gap-2 bg-slate-900/90 border border-slate-700/80 rounded-lg px-3 py-1.5">
                            <Sparkles className="w-4 h-4 text-purple-400" />
                            <span className="text-xs text-slate-300 font-medium">
                                Active LLM Gateway:
                            </span>
                            <select
                                value={selectedProvider}
                                onChange={(e) => setSelectedProvider(e.target.value)}
                                className="bg-transparent text-xs font-mono font-semibold text-emerald-300 focus:outline-none cursor-pointer"
                            >
                                <option value="anthropic" className="bg-slate-900">
                                    Anthropic Claude 3.7 Sonnet
                                </option>
                                <option value="openai" className="bg-slate-900">
                                    OpenAI GPT-4o (Structured JSON)
                                </option>
                                <option value="gemini" className="bg-slate-900">
                                    Google Gemini 2.5 Flash
                                </option>
                                <option value="ollama" className="bg-slate-900">
                                    Ollama Local (Llama-3.3-8B Air-Gapped)
                                </option>
                                <option value="vllm" className="bg-slate-900">
                                    vLLM Cluster (Llama-3.3-70B)
                                </option>
                            </select>
                        </div>

                        <button
                            onClick={() => fetchSOCData(false)}
                            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 text-xs font-medium text-slate-200 transition"
                        >
                            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin" : ""}`} />
                            Sync Telemetry
                        </button>
                    </div>
                </div>
            </header>

            <main className="max-w-[1600px] w-full mx-auto px-6 py-6 space-y-6 flex-1">
                {/* KPI Telemetry Strip */}
                <section className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3.5">
                    <div className="bg-[#0b1120] border border-slate-800/90 rounded-xl p-4">
                        <div className="text-xs text-slate-400 flex items-center justify-between">
                            <span>SIEM Alerts Investigated</span>
                            <Activity className="w-4 h-4 text-sky-400" />
                        </div>
                        <div className="text-2xl font-bold font-mono text-white mt-1.5">
                            {metrics?.total_incidents_analyzed ?? incidents.length}
                        </div>
                        <div className="text-[11px] text-sky-400 mt-1">
                            100% Autonomous Triage
                        </div>
                    </div>

                    <div className="bg-[#0b1120] border border-rose-900/50 rounded-xl p-4">
                        <div className="text-xs text-slate-400 flex items-center justify-between">
                            <span>P0 Critical Intrusions</span>
                            <ShieldAlert className="w-4 h-4 text-rose-400" />
                        </div>
                        <div className="text-2xl font-bold font-mono text-rose-400 mt-1.5">
                            {metrics?.critical_p0_count ?? 0}
                        </div>
                        <div className="text-[11px] text-rose-300/80 mt-1">
                            PyTorch + XGBoost Consensus
                        </div>
                    </div>

                    <div className="bg-[#0b1120] border border-amber-900/50 rounded-xl p-4">
                        <div className="text-xs text-slate-400 flex items-center justify-between">
                            <span>Log Injections Blocked</span>
                            <Lock className="w-4 h-4 text-amber-400" />
                        </div>
                        <div className="text-2xl font-bold font-mono text-amber-300 mt-1.5">
                            {metrics?.log_injections_blocked ?? 0}
                        </div>
                        <div className="text-[11px] text-amber-300/80 mt-1">
                            Zero-Trust Prompt Firewall
                        </div>
                    </div>

                    <div className="bg-[#0b1120] border border-emerald-900/50 rounded-xl p-4">
                        <div className="text-xs text-slate-400 flex items-center justify-between">
                            <span>DSPy False Positives Filtered</span>
                            <ShieldCheck className="w-4 h-4 text-emerald-400" />
                        </div>
                        <div className="text-2xl font-bold font-mono text-emerald-400 mt-1.5">
                            {metrics?.false_positives_filtered ?? 0}
                        </div>
                        <div className="text-[11px] text-emerald-300/80 mt-1">
                            Alert Fatigue Eliminated
                        </div>
                    </div>

                    <div className="bg-[#0b1120] border border-purple-900/50 rounded-xl p-4">
                        <div className="text-xs text-slate-400 flex items-center justify-between">
                            <span>SOAR Contained / HITL</span>
                            <Zap className="w-4 h-4 text-purple-400" />
                        </div>
                        <div className="text-2xl font-bold font-mono text-purple-300 mt-1.5">
                            {metrics?.auto_contained_count ?? 0}{" "}
                            <span className="text-xs text-slate-400 font-normal">
                                ({metrics?.awaiting_hitl_count ?? 0} pending)
                            </span>
                        </div>
                        <div className="text-[11px] text-purple-300/80 mt-1">
                            AST-Verified FastMCP Playbooks
                        </div>
                    </div>

                    <div className="bg-[#0b1120] border border-slate-800/90 rounded-xl p-4">
                        <div className="text-xs text-slate-400 flex items-center justify-between">
                            <span>Mean Time To Respond</span>
                            <Cpu className="w-4 h-4 text-teal-400" />
                        </div>
                        <div className="text-2xl font-bold font-mono text-teal-300 mt-1.5">
                            {metrics?.mean_time_to_respond_ms ?? 14.2} ms
                        </div>
                        <div className="text-[11px] text-teal-300/80 mt-1">
                            7-Node Async StateGraph
                        </div>
                    </div>
                </section>

                {/* One-Click APT Simulation Launcher */}
                <section className="bg-[#0b1120] border border-slate-800/90 rounded-xl p-4">
                    <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
                        <div className="flex items-center gap-2">
                            <Terminal className="w-4 h-4 text-emerald-400" />
                            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-200">
                                Live Cyber Range & APT Telemetry Simulator (One-Click LangGraph Trigger)
                            </h2>
                        </div>
                        <span className="text-[11px] text-slate-400">
                            Click any scenario to stream raw SIEM telemetry through PyTorch, MITRE RAG, CrewAI, DSPy & AST Sandbox
                        </span>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                        {SCENARIO_BUTTONS.map((btn) => (
                            <button
                                key={btn.key}
                                disabled={isLoading}
                                onClick={() => handleSimulateScenario(btn.key)}
                                className={`text-left p-3 rounded-lg border transition flex flex-col justify-between gap-2 ${btn.color} disabled:opacity-50`}
                            >
                                <div className="flex items-center justify-between w-full">
                                    <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-black/40">
                                        {btn.tag}
                                    </span>
                                    <Play className="w-3.5 h-3.5 opacity-80" />
                                </div>
                                <div className="text-xs font-semibold leading-snug">
                                    {btn.label}
                                </div>
                            </button>
                        ))}
                    </div>
                </section>

                {hitlBanner && (
                    <div className="bg-emerald-500/15 border border-emerald-500/40 text-emerald-200 px-4 py-3 rounded-xl text-xs font-mono flex items-center justify-between">
                        <span>✅ {hitlBanner}</span>
                        <button
                            onClick={() => setHitlBanner(null)}
                            className="text-emerald-300 hover:underline"
                        >
                            Dismiss
                        </button>
                    </div>
                )}

                {/* Main Split Workspace: Left Incident Queue (4 cols) + Right Forensic Deep-Dive (8 cols) */}
                <section className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                    {/* Left Column: Investigated Incident Queue */}
                    <div className="lg:col-span-4 space-y-3">
                        <div className="flex items-center justify-between px-1">
                            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                                <Database className="w-4 h-4 text-sky-400" />
                                SIEM Incident Queue ({incidents.length})
                            </h3>
                            <span className="text-[11px] text-slate-400 font-mono">
                                SQLAlchemy 2.0 Async
                            </span>
                        </div>

                        <div className="space-y-2.5 max-h-[820px] overflow-y-auto pr-1">
                            {incidents.map((inc) => {
                                const isSelected =
                                    selectedIncident?.incident_id === inc.incident_id;
                                return (
                                    <div
                                        key={inc.incident_id}
                                        onClick={() => setSelectedIncident(inc)}
                                        className={`p-3.5 rounded-xl border cursor-pointer transition ${isSelected
                                            ? "bg-slate-800/90 border-emerald-500/60 shadow-lg shadow-emerald-950/30"
                                            : "bg-[#0b1120] border-slate-800/80 hover:border-slate-700"
                                            }`}
                                    >
                                        <div className="flex items-center justify-between gap-2 mb-1.5">
                                            <span
                                                className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${severityBadge(
                                                    inc.severity
                                                )}`}
                                            >
                                                {inc.severity}
                                            </span>
                                            <span className="text-[10px] font-mono text-slate-400">
                                                {inc.mitre_technique_id} • {inc.llm_provider_used.toUpperCase()}
                                            </span>
                                        </div>

                                        <h4 className="text-xs font-semibold text-white line-clamp-2 leading-relaxed">
                                            {inc.title}
                                        </h4>

                                        <div className="mt-2.5 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-400">
                                            <span>{inc.source_ip}</span>
                                            <span className="text-slate-300 truncate max-w-[150px]">
                                                {inc.target_host}
                                            </span>
                                        </div>

                                        <div className="mt-2 flex items-center justify-between text-[10px] font-mono">
                                            <span className="text-sky-400">
                                                Score:{" "}
                                                {(
                                                    inc.neural_anomaly.composite_anomaly_score * 100
                                                ).toFixed(1)}
                                                %
                                            </span>
                                            <span
                                                className={
                                                    inc.status.includes("AWAITING")
                                                        ? "text-amber-300 font-semibold"
                                                        : inc.status.includes("CONTAINED")
                                                            ? "text-emerald-300"
                                                            : "text-slate-400"
                                                }
                                            >
                                                {inc.status}
                                            </span>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    </div>

                    {/* Right Column: Deep Multi-Agent Forensic Workbench */}
                    <div className="lg:col-span-8 space-y-5">
                        {selectedIncident ? (
                            <>
                                {/* Incident Banner & HITL Governance Action Bar */}
                                <div className="bg-[#0b1120] border border-slate-800 rounded-xl p-5 space-y-4">
                                    <div className="flex flex-wrap items-start justify-between gap-4">
                                        <div>
                                            <div className="flex flex-wrap items-center gap-2 mb-2">
                                                <span
                                                    className={`text-xs font-mono font-bold px-2.5 py-0.5 rounded border ${severityBadge(
                                                        selectedIncident.severity
                                                    )}`}
                                                >
                                                    {selectedIncident.severity}
                                                </span>
                                                <span className="text-xs font-mono px-2.5 py-0.5 rounded bg-slate-800 text-sky-300 border border-slate-700">
                                                    {selectedIncident.mitre_tactic} (
                                                    {selectedIncident.mitre_technique_id})
                                                </span>
                                                <span className="text-xs font-mono px-2.5 py-0.5 rounded bg-purple-500/15 text-purple-300 border border-purple-500/30">
                                                    LLM: {selectedIncident.llm_provider_used.toUpperCase()}
                                                </span>
                                                {selectedIncident.log_guardrail
                                                    .log_injection_detected && (
                                                        <span className="text-xs font-mono px-2.5 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">
                                                            🚨 LOG PROMPT INJECTION NEUTRALIZED
                                                        </span>
                                                    )}
                                            </div>
                                            <h2 className="text-base font-bold text-white">
                                                {selectedIncident.title}
                                            </h2>
                                            <p className="text-xs font-mono text-slate-400 mt-1">
                                                Incident ID: {selectedIncident.incident_id} | Source IP:{" "}
                                                <span className="text-rose-300">
                                                    {selectedIncident.source_ip}
                                                </span>{" "}
                                                → Target Host:{" "}
                                                <span className="text-sky-300">
                                                    {selectedIncident.target_host}
                                                </span>
                                            </p>
                                        </div>

                                        {/* HITL Approval Buttons */}
                                        {selectedIncident.hitl_approval_required && (
                                            <div className="flex items-center gap-2.5 bg-amber-500/10 border border-amber-500/40 p-3 rounded-xl">
                                                <div>
                                                    <div className="text-xs font-bold text-amber-300 flex items-center gap-1.5">
                                                        <AlertTriangle className="w-4 h-4" />
                                                        HITL Commander Gate Active
                                                    </div>
                                                    <div className="text-[11px] text-slate-300 mt-0.5">
                                                        Approve FastMCP Firewall Block & EDR Host Isolation?
                                                    </div>
                                                </div>
                                                <button
                                                    onClick={() =>
                                                        handleHITLApprove(selectedIncident.incident_id, true)
                                                    }
                                                    disabled={isLoading}
                                                    className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold transition"
                                                >
                                                    Approve SOAR
                                                </button>
                                                <button
                                                    onClick={() =>
                                                        handleHITLApprove(
                                                            selectedIncident.incident_id,
                                                            false
                                                        )
                                                    }
                                                    disabled={isLoading}
                                                    className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition"
                                                >
                                                    Reject
                                                </button>
                                            </div>
                                        )}
                                    </div>

                                    {/* Executive RCA Summary */}
                                    <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-3.5">
                                        <div className="text-[11px] font-mono uppercase text-emerald-400 font-semibold mb-1">
                                            Tier-3 Executive Root Cause Analysis (CoT + ReAct Synthesis)
                                        </div>
                                        <p className="text-xs text-slate-200 leading-relaxed">
                                            {selectedIncident.executive_rca_summary}
                                        </p>
                                    </div>
                                </div>

                                {/* Neural Anomaly & DSPy Calibration Grid */}
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    {/* PyTorch, XGBoost & IsolationForest Card */}
                                    <div className="bg-[#0b1120] border border-slate-800 rounded-xl p-4 space-y-3">
                                        <div className="flex items-center justify-between">
                                            <h3 className="text-xs font-bold uppercase tracking-wider text-sky-400 flex items-center gap-1.5">
                                                <Cpu className="w-4 h-4" />
                                                PyTorch Autoencoder & XGBoost Telemetry
                                            </h3>
                                            <span className="text-xs font-mono font-bold text-white">
                                                Composite:{" "}
                                                {(
                                                    selectedIncident.neural_anomaly
                                                        .composite_anomaly_score * 100
                                                ).toFixed(1)}
                                                %
                                            </span>
                                        </div>

                                        <div className="space-y-2 text-xs font-mono">
                                            <div>
                                                <div className="flex justify-between text-slate-300 mb-1">
                                                    <span>PyTorch Reconstruction Error (Autoencoder)</span>
                                                    <span>
                                                        {(
                                                            selectedIncident.neural_anomaly
                                                                .pytorch_reconstruction_error * 100
                                                        ).toFixed(1)}
                                                        %
                                                    </span>
                                                </div>
                                                <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                                                    <div
                                                        className="h-full bg-rose-500"
                                                        style={{
                                                            width: `${Math.min(
                                                                selectedIncident.neural_anomaly
                                                                    .pytorch_reconstruction_error * 100,
                                                                100
                                                            )}%`,
                                                        }}
                                                    />
                                                </div>
                                            </div>

                                            <div>
                                                <div className="flex justify-between text-slate-300 mb-1">
                                                    <span>PyTorch Multi-Head Self-Attention Score</span>
                                                    <span>
                                                        {(
                                                            selectedIncident.neural_anomaly
                                                                .pytorch_attention_score * 100
                                                        ).toFixed(1)}
                                                        %
                                                    </span>
                                                </div>
                                                <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                                                    <div
                                                        className="h-full bg-amber-500"
                                                        style={{
                                                            width: `${Math.min(
                                                                selectedIncident.neural_anomaly
                                                                    .pytorch_attention_score * 100,
                                                                100
                                                            )}%`,
                                                        }}
                                                    />
                                                </div>
                                            </div>

                                            <div>
                                                <div className="flex justify-between text-slate-300 mb-1">
                                                    <span>XGBoost Supervised Threat Probability</span>
                                                    <span>
                                                        {(
                                                            selectedIncident.neural_anomaly
                                                                .xgboost_threat_probability * 100
                                                        ).toFixed(1)}
                                                        %
                                                    </span>
                                                </div>
                                                <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                                                    <div
                                                        className="h-full bg-sky-500"
                                                        style={{
                                                            width: `${Math.min(
                                                                selectedIncident.neural_anomaly
                                                                    .xgboost_threat_probability * 100,
                                                                100
                                                            )}%`,
                                                        }}
                                                    />
                                                </div>
                                            </div>
                                        </div>
                                    </div>

                                    {/* DSPy False-Positive Calibration & Zero-Trust Log Guardrail */}
                                    <div className="bg-[#0b1120] border border-slate-800 rounded-xl p-4 space-y-3">
                                        <div className="flex items-center justify-between">
                                            <h3 className="text-xs font-bold uppercase tracking-wider text-purple-400 flex items-center gap-1.5">
                                                <Eye className="w-4 h-4" />
                                                DSPy Calibration & Zero-Trust Log Firewall
                                            </h3>
                                            <span className="text-xs font-mono text-emerald-300">
                                                Confidence:{" "}
                                                {(
                                                    selectedIncident.dspy_calibration
                                                        .calibrated_confidence * 100
                                                ).toFixed(1)}
                                                %
                                            </span>
                                        </div>

                                        <div className="text-xs space-y-1.5 font-mono text-slate-300">
                                            <div className="flex justify-between">
                                                <span>DSPy False-Positive Likelihood:</span>
                                                <span className="text-amber-300">
                                                    {(
                                                        selectedIncident.dspy_calibration
                                                            .false_positive_likelihood * 100
                                                    ).toFixed(1)}
                                                    %
                                                </span>
                                            </div>
                                            <div className="flex justify-between">
                                                <span>Shannon Entropy (Obfuscation Gate):</span>
                                                <span className="text-sky-300">
                                                    {selectedIncident.log_guardrail.shannon_entropy} bits/char
                                                </span>
                                            </div>
                                            <div className="flex justify-between">
                                                <span>PII / Secrets Redacted:</span>
                                                <span className="text-emerald-300">
                                                    {
                                                        selectedIncident.log_guardrail.pii_redacted_entities
                                                            .length
                                                    }{" "}
                                                    artifact(s)
                                                </span>
                                            </div>
                                        </div>

                                        <div className="p-2.5 rounded bg-slate-900/90 border border-slate-800 text-[11px] font-mono text-slate-300 max-h-24 overflow-y-auto">
                                            <span className="text-slate-400 block mb-0.5">
                                                Sanitized Log Payload:
                                            </span>
                                            {selectedIncident.log_guardrail.sanitized_log_payload}
                                        </div>
                                    </div>
                                </div>

                                {/* 7-Node LangGraph Execution Timeline */}
                                <div className="bg-[#0b1120] border border-slate-800 rounded-xl p-4">
                                    <h3 className="text-xs font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-2 mb-3">
                                        <Network className="w-4 h-4" />
                                        7-Node LangGraph Stateful SOC Execution Trace
                                    </h3>
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                                        {selectedIncident.agent_trace.map((step) => (
                                            <div
                                                key={step.step_index}
                                                className="p-3 rounded-lg bg-slate-900/80 border border-slate-800/90 flex flex-col justify-between"
                                            >
                                                <div className="flex items-center justify-between gap-2">
                                                    <span className="text-xs font-bold text-white">
                                                        #{step.step_index} {step.agent_name}
                                                    </span>
                                                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300">
                                                        {step.latency_ms} ms
                                                    </span>
                                                </div>
                                                <div className="text-[10px] font-mono text-sky-400 mt-1">
                                                    {step.framework}
                                                </div>
                                                <p className="text-[11px] text-slate-300 mt-1.5 font-mono">
                                                    {step.summary}
                                                </p>
                                            </div>
                                        ))}
                                    </div>
                                </div>

                                {/* Hybrid MITRE ATT&CK RAG + CrewAI OSINT + AST SOAR Script */}
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    {/* Hybrid RAG & CrewAI OSINT */}
                                    <div className="bg-[#0b1120] border border-slate-800 rounded-xl p-4 space-y-3">
                                        <h3 className="text-xs font-bold uppercase tracking-wider text-amber-400">
                                            Hybrid MITRE ATT&CK RAG (Dense + BM25 RRF) & CrewAI OSINT
                                        </h3>
                                        <div className="space-y-2">
                                            {selectedIncident.cti_rag_hits.slice(0, 2).map((hit) => (
                                                <div
                                                    key={hit.technique_id}
                                                    className="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800 text-xs"
                                                >
                                                    <div className="flex justify-between font-mono font-bold text-amber-300">
                                                        <span>
                                                            [{hit.technique_id}] {hit.technique_name}
                                                        </span>
                                                        <span>RRF: {hit.rrf_score}</span>
                                                    </div>
                                                    <p className="text-[11px] text-slate-300 mt-1">
                                                        {hit.recommended_countermeasure}
                                                    </p>
                                                </div>
                                            ))}
                                        </div>

                                        <div className="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800 text-[11px] font-mono text-slate-300 whitespace-pre-line">
                                            <span className="text-sky-400 font-bold block mb-1">
                                                CrewAI 3-Agent OSINT Report:
                                            </span>
                                            {selectedIncident.crewai_osint_report}
                                        </div>
                                    </div>

                                    {/* Formal Python AST Sandbox & SOAR Playbook */}
                                    <div className="bg-[#0b1120] border border-slate-800 rounded-xl p-4 space-y-3">
                                        <div className="flex items-center justify-between">
                                            <h3 className="text-xs font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                                                <Code2 className="w-4 h-4" />
                                                AST-Verified SOAR Python Playbook
                                            </h3>
                                            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 flex items-center gap-1">
                                                <CheckCircle2 className="w-3 h-3" />
                                                AST SAFE={String(selectedIncident.ast_verification.is_safe)}
                                            </span>
                                        </div>

                                        <pre className="p-3 rounded-lg bg-[#05080f] border border-slate-800 text-[11px] font-mono text-emerald-300 overflow-x-auto leading-relaxed">
                                            {selectedIncident.soar_python_playbook}
                                        </pre>

                                        <div className="space-y-1">
                                            <div className="text-[11px] font-semibold text-slate-300">
                                                Concrete SOAR Remediation Actions:
                                            </div>
                                            {selectedIncident.remediation_actions.map((act, idx) => (
                                                <div
                                                    key={idx}
                                                    className="text-[11px] text-slate-300 flex items-start gap-1.5"
                                                >
                                                    <span className="text-emerald-400 font-mono">
                                                        {idx + 1}.
                                                    </span>
                                                    <span>{act}</span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                </div>
                            </>
                        ) : (
                            <div className="bg-[#0b1120] border border-slate-800 rounded-xl p-12 text-center text-slate-400 text-sm">
                                Select an incident from the queue or click an APT Simulation button above to launch the 7-node LangGraph SOC Commander.
                            </div>
                        )}
                    </div>
                </section>
            </main>
        </div>
    );
}