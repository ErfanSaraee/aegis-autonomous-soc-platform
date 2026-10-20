"""FastAPI v1 endpoints for AEGIS Autonomous SOC investigations, APT simulations, HITL SOAR, and metrics."""

from collections import Counter
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.langgraph_soc_commander import langgraph_soc_commander
from app.api.v1.presets import APT_SIMULATION_PRESETS
from app.core.logging import get_logger
from app.db.session import get_db_session
from app.models.soc_models import (
    IncidentSeverity,
    IncidentStatus,
    LLMProviderChoice,
    SOARPlaybookExecutionLog,
    SOCIncidentRecord,
)
from app.schemas.soc import (
    AgentExecutionStep,
    ASTPlaybookVerification,
    DSPyTriageCalibration,
    HITLApprovalRequest,
    LogGuardrailReport,
    MITREIntelligenceHit,
    NeuralAnomalyReport,
    SIEMTelemetryIngestRequest,
    SOCDashboardMetricsResponse,
    SOCIncidentResponse,
)
from app.security.ast_soar_sandbox import soar_ast_sandbox
from app.workers.celery_app import dispatch_soar_containment_task

logger = get_logger(__name__)
router = APIRouter()


async def persist_incident_response(
    session: AsyncSession,
    raw_log: str,
    response: SOCIncidentResponse,
) -> SOCIncidentRecord:
    """Persist a completed LangGraph SOC investigation into the async SQLAlchemy database."""
    record = SOCIncidentRecord(
        id=response.incident_id,
        title=response.title,
        source_ip=response.source_ip,
        target_host=response.target_host,
        Event_source=response.event_source,
        raw_log_payload=raw_log,
        sanitized_log_payload=response.log_guardrail.sanitized_log_payload,
        severity=response.severity,
        status=response.status,
        pytorch_Reconstruction_error=response.neural_anomaly.pytorch_reconstruction_error,
        pytorch_attention_score=response.neural_anomaly.pytorch_attention_score,
        xgboost_threat_probability=response.neural_anomaly.xgboost_threat_probability,
        isolation_forest_anomaly=response.neural_anomaly.isolation_forest_anomaly,
        composite_anomaly_score=response.neural_anomaly.composite_anomaly_score,
        log_injection_detected=response.log_guardrail.log_injection_detected,
        shannon_entropy=response.log_guardrail.shannon_entropy,
        pii_redacted_count=len(response.log_guardrail.pii_redacted_entities),
        mitre_tactic=response.mitre_tactic,
        mitre_technique_id=response.mitre_technique_id,
        cti_rag_citations=[hit.model_dump(mode="json")
                           for hit in response.cti_rag_hits],
        crewai_osint_report=response.crewai_osint_report,
        llm_provider_used=response.llm_provider_used,
        dspy_false_positive_likelihood=response.dspy_calibration.false_positive_likelihood,
        executive_rca_summary=response.executive_rca_summary,
        remediation_actions=response.remediation_actions,
        soar_python_playbook=response.soar_python_playbook,
        ast_playbook_verified=response.ast_verification.is_safe,
        ast_violations=response.ast_verification.violations,
        hitl_approval_required=response.hitl_approval_required,
        agent_trace_log=[step.model_dump(mode="json")
                         for step in response.agent_trace],
    )
    session.add(record)
    await session.commit()
    return record


def _orm_to_incident_response(row: SOCIncidentRecord) -> SOCIncidentResponse:
    """Reconstruct full SOCIncidentResponse schema from an ORM record."""
    trace_steps = [AgentExecutionStep(**step)
                   for step in (row.agent_trace_log or [])]
    rag_hits = [MITREIntelligenceHit(**hit)
                for hit in (row.cti_rag_citations or [])]

    return SOCIncidentResponse(
        incident_id=row.id,
        title=row.title,
        source_ip=row.source_ip,
        target_host=row.target_host,
        event_source=row.Event_source,
        severity=row.severity,
        status=row.status,
        llm_provider_used=row.llm_provider_used,
        neural_anomaly=NeuralAnomalyReport(
            pytorch_reconstruction_error=row.pytorch_Reconstruction_error,
            pytorch_attention_score=row.pytorch_attention_score,
            top_salient_log_tokens={},
            xgboost_threat_probability=row.xgboost_threat_probability,
            isolation_forest_anomaly=row.isolation_forest_anomaly,
            composite_anomaly_score=row.composite_anomaly_score,
            predicted_severity=row.severity,
        ),
        log_guardrail=LogGuardrailReport(
            log_injection_detected=row.log_injection_detected,
            shannon_entropy=row.shannon_entropy,
            is_obfuscated_payload=row.shannon_entropy >= 4.40,
            pii_redacted_entities=["REDACTED"] * row.pii_redacted_count,
            sanitized_log_payload=row.sanitized_log_payload,
            guardrail_notes=["Reconstructed from SOC immutable audit store."],
        ),
        mitre_tactic=row.mitre_tactic,
        mitre_technique_id=row.mitre_technique_id,
        cti_rag_hits=rag_hits,
        crewai_osint_report=row.crewai_osint_report,
        dspy_calibration=DSPyTriageCalibration(
            false_positive_likelihood=row.dspy_false_positive_likelihood,
            calibrated_confidence=round(
                1.0 - row.dspy_false_positive_likelihood, 4),
            compiled_triage_rationale="Calibrated via DSPy teleprompter invariants.",
            applied_security_invariants=[],
        ),
        executive_rca_summary=row.executive_rca_summary,
        remediation_actions=row.remediation_actions,
        soar_python_playbook=row.soar_python_playbook,
        ast_verification=ASTPlaybookVerification(
            is_safe=row.ast_playbook_verified,
            cyclomatic_complexity=1,
            violations=row.ast_violations,
            inspected_nodes=["FunctionDef", "Return"],
        ),
        hitl_approval_required=row.hitl_approval_required,
        agent_trace=trace_steps,
        created_at=row.created_at,
    )


@router.get(
    "/soc/Presets",
    summary="List curated APT cyberattack and benign SIEM simulation scenarios",
)
async def list_simulation_presets() -> dict[str, Any]:
    """Return available one-click simulation presets for the Next.js SOC Command Center."""
    return {
        key: {
            "scenario_key": key,
            "title": preset.title,
            "source_ip": preset.source_ip,
            "target_host": preset.target_host,
            "event_source": preset.event_source,
            "preferred_llm_provider": preset.preferred_llm_provider.value,
            "raw_log_payload": preset.raw_log_payload,
        }
        for key, preset in APT_SIMULATION_PRESETS.items()
    }


@router.post(
    "/soc/investigate",
    response_model=SOCIncidentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Execute full 7-node LangGraph autonomous SOC investigation on SIEM telemetry",
)
async def investigate_siem_telemetry(
    payload: SIEMTelemetryIngestRequest,
    session: AsyncSession = Depends(get_db_session),
) -> SOCIncidentResponse:
    """Run Zero-Trust Guardrail, PyTorch/XGBoost, Hybrid MITRE RAG, CrewAI, DSPy, and Multi-LLM RCA."""
    response = await langgraph_soc_commander.investigate_incident(payload)
    await persist_incident_response(
        session=session,
        raw_log=payload.raw_log_payload,
        response=response,
    )
    return response


@router.post(
    "/soc/simulate/{scenario_key}",
    response_model=SOCIncidentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Trigger a curated APT or benign simulation scenario by key",
)
async def simulate_apt_scenario(
    scenario_key: str,
    llm_provider: LLMProviderChoice | None = None,
    session: AsyncSession = Depends(get_db_session),
) -> SOCIncidentResponse:
    """Execute one of the 4 preset SOC scenarios and persist the investigation record."""
    if scenario_key not in APT_SIMULATION_PRESETS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown scenario_key '{scenario_key}'. Valid keys: {list(APT_SIMULATION_PRESETS.keys())}",
        )

    base_preset = APT_SIMULATION_PRESETS[scenario_key]
    req = base_preset.model_copy(
        update={
            "preferred_llm_provider": llm_provider or base_preset.preferred_llm_provider}
    )
    response = await langgraph_soc_commander.investigate_incident(req)
    await persist_incident_response(
        session=session,
        raw_log=req.raw_log_payload,
        response=response,
    )
    return response


@router.get(
    "/soc/incidents",
    response_model=list[SOCIncidentResponse],
    summary="List recent autonomous SOC incident investigations",
)
async def list_soc_incidents(
    limit: int = 20,
    session: AsyncSession = Depends(get_db_session),
) -> list[SOCIncidentResponse]:
    """Return ordered list of investigated SOC incidents."""
    stmt = (
        select(SOCIncidentRecord)
        .order_by(SOCIncidentRecord.created_at.desc())
        .limit(min(limit, 100))
    )
    result = await session.execute(stmt)
    rows = list(result.scalars().all())
    return [_orm_to_incident_response(row) for row in rows]


@router.get(
    "/soc/incidents/{incident_id}",
    response_model=SOCIncidentResponse,
    summary="Retrieve full forensic details for a specific SOC incident",
)
async def get_soc_incident_detail(
    incident_id: str,
    session: AsyncSession = Depends(get_db_session),
) -> SOCIncidentResponse:
    """Fetch a single SOC incident record by ID."""
    stmt = select(SOCIncidentRecord).where(SOCIncidentRecord.id == incident_id)
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"SOC Incident '{incident_id}' not found.",
        )
    return _orm_to_incident_response(row)


@router.post(
    "/soc/incidents/{incident_id}/hitl-approve",
    summary="Human-in-the-Loop (HITL) commander approval dispatching FastMCP & Celery SOAR containment",
)
async def approve_hitl_soar_containment(
    incident_id: str,
    approval: HITLApprovalRequest,
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Approve or reject high-impact SOAR containment and dispatch Celery + FastMCP tools."""
    stmt = select(SOCIncidentRecord).where(SOCIncidentRecord.id == incident_id)
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"SOC Incident '{incident_id}' not found.",
        )

    if not approval.approve_containment:
        row.status = IncidentStatus.FALSE_POSITIVE_CLOSED
        row.hitl_approval_required = False
        await session.commit()
        return {
            "incident_id": incident_id,
            "status": row.status.value,
            "responder": approval.responder_name,
            "message": "Containment rejected by SOC Commander; incident marked as closed.",
        }

    # Dispatch distributed Celery worker invoking FastMCP Firewall & EDR isolation tools
    worker_output = dispatch_soar_containment_task(
        incident_id=row.id,
        source_ip=row.source_ip,
        target_host=row.target_host,
        approved_by=approval.responder_name,
    )

    row.status = IncidentStatus.CONTAINED_HITL_APPROVED
    row.hitl_approval_required = False

    audit_log = SOARPlaybookExecutionLog(
        incident_id=row.id,
        action_type="PERIMETER_FIREWALL_DROP_AND_EDR_ISOLATION",
        target_entity=f"{row.source_ip} -> {row.target_host}",
        approved_by=approval.responder_name,
        ast_verified=row.ast_playbook_verified,
        execution_status="ENFORCED_VIA_FASTMCP",
        mcp_tool_output=worker_output,
    )
    session.add(audit_log)
    await session.commit()

    return {
        "incident_id": row.id,
        "status": row.status.value,
        "approved_by": approval.responder_name,
        "commander_notes": approval.commander_notes,
        "soar_execution_receipt": worker_output,
    }


@router.post(
    "/soc/verify-ast",
    response_model=ASTPlaybookVerification,
    summary="Statically verify a Python SOAR playbook snippet inside the formal AST sandbox",
)
async def verify_soar_script_ast(
    code: str = Body(..., embed=True,
                     description="Python SOAR script to verify."),
) -> ASTPlaybookVerification:
    """Inspect Python code via AST NodeVisitor for forbidden OS imports, eval/exec, or dunder escapes."""
    return soar_ast_sandbox.verify_playbook(code)


@router.get(
    "/soc/dashboard-metrics",
    response_model=SOCDashboardMetricsResponse,
    summary="Retrieve aggregated KPI telemetry for the Next.js SOC Command Center",
)
async def get_soc_dashboard_metrics(
    session: AsyncSession = Depends(get_db_session),
) -> SOCDashboardMetricsResponse:
    """Compute real-time SOC KPIs, MITRE tactic distribution, and recent incident summaries."""
    stmt = select(SOCIncidentRecord).order_by(
        SOCIncidentRecord.created_at.desc())
    result = await session.execute(stmt)
    rows = list(result.scalars().all())

    total = len(rows)
    p0_count = sum(1 for r in rows if r.severity ==
                   IncidentSeverity.P0_CRITICAL)
    auto_contained = sum(
        1
        for r in rows
        if r.status in {IncidentStatus.CONTAINED_AUTO, IncidentStatus.CONTAINED_HITL_APPROVED}
    )
    awaiting_hitl = sum(
        1 for r in rows if r.status == IncidentStatus.AWAITING_HITL_APPROVAL
    )
    fp_filtered = sum(
        1 for r in rows if r.status == IncidentStatus.FALSE_POSITIVE_CLOSED
    )
    injections_blocked = sum(1 for r in rows if r.log_injection_detected)

    # Calculate average pipeline execution latency across trace steps
    latencies: list[float] = []
    tactic_counter: Counter[str] = Counter()
    for r in rows:
        tactic_counter[r.mitre_tactic.value] += 1
        step_sum = sum(float(step.get("latency_ms", 2.0))
                       for step in (r.agent_trace_log or []))
        if step_sum > 0:
            latencies.append(step_sum)

    mttr_ms = round(sum(latencies) / max(len(latencies), 1),
                    2) if latencies else 14.4

    recent_list = [
        {
            "incident_id": r.id,
            "title": r.title,
            "source_ip": r.source_ip,
            "target_host": r.target_host,
            "severity": r.severity.value,
            "status": r.status.value,
            "composite_anomaly_score": r.composite_anomaly_score,
            "pytorch_reconstruction_error": r.pytorch_Reconstruction_error,
            "xgboost_threat_probability": r.xgboost_threat_probability,
            "log_injection_detected": r.log_injection_detected,
            "mitre_tactic": r.mitre_tactic.value,
            "mitre_technique_id": r.mitre_technique_id,
            "llm_provider_used": r.llm_provider_used.value,
            "dspy_false_positive_likelihood": r.dspy_false_positive_likelihood,
            "hitl_approval_required": r.hitl_approval_required,
            "created_at": r.created_at.isoformat() if isinstance(r.created_at, datetime) else str(r.created_at),
        }
        for r in rows[:15]
    ]

    return SOCDashboardMetricsResponse(
        total_incidents_analyzed=total,
        critical_p0_count=p0_count,
        auto_contained_count=auto_contained,
        awaiting_hitl_count=awaiting_hitl,
        false_positives_filtered=fp_filtered,
        log_injections_blocked=injections_blocked,
        mean_time_to_respond_ms=mttr_ms,
        mitre_tactic_distribution=dict(tactic_counter),
        recent_incidents=recent_list,
    )
