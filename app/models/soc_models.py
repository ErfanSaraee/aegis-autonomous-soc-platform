"""SQLAlchemy 2.0 Async ORM models for SIEM incidents, MITRE ATT&CK chains, and SOAR playbooks."""

import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Enum, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class IncidentSeverity(str, enum.Enum):
    """Standardized SOC incident severity tiers."""

    P0_CRITICAL = "P0_CRITICAL"
    P1_HIGH = "P1_HIGH"
    P2_MEDIUM = "P2_MEDIUM"
    P3_LOW = "P3_LOW"
    BENIGN = "BENIGN"


class IncidentStatus(str, enum.Enum):
    """Lifecycle states of an autonomous SOC investigation."""

    OPEN_TRIAGE = "OPEN_TRIAGE"
    INVESTIGATING = "INVESTIGATING"
    AWAITING_HITL_APPROVAL = "AWAITING_HITL_APPROVAL"
    CONTAINED_AUTO = "CONTAINED_AUTO"
    CONTAINED_HITL_APPROVED = "CONTAINED_HITL_APPROVED"
    FALSE_POSITIVE_CLOSED = "FALSE_POSITIVE_CLOSED"


class MITRETactic(str, enum.Enum):
    """Primary MITRE ATT&CK Enterprise tactics detected in telemetry."""

    INITIAL_ACCESS = "TA0001: Initial Access"
    EXECUTION = "TA0002: Execution"
    PRIVILEGE_ESCALATION = "TA0004: Privilege Escalation"
    CREDENTIAL_ACCESS = "TA0006: Credential Access"
    LATERAL_MOVEMENT = "TA0008: Lateral Movement"
    COMMAND_AND_CONTROL = "TA0011: Command and Control (C2)"
    EXFILTRATION = "TA0010: Exfiltration"
    NONE = "NONE (Benign Activity)"


class LLMProviderChoice(str, enum.Enum):
    """Supported multi-provider foundation model backends."""

    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    GEMINI = "gemini"
    OLLAMA = "ollama"
    VLLM = "vllm"


class SOCIncidentRecord(Base):
    """Persists end-to-end multi-agent SOC investigation, ML/DL scores, MITRE RAG, and SOAR remediation."""

    __tablename__ = "soc_incident_records"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    title: Mapped[str] = mapped_column(String(220), nullable=False)
    source_ip: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True)
    target_host: Mapped[str] = mapped_column(
        String(120), nullable=False, index=True)
    Event_source: Mapped[str] = mapped_column(
        String(80), default="EDR_SIEM_STREAM", nullable=False)
    raw_log_payload: Mapped[str] = mapped_column(Text, nullable=False)
    sanitized_log_payload: Mapped[str] = mapped_column(Text, nullable=False)

    severity: Mapped[IncidentSeverity] = mapped_column(
        Enum(IncidentSeverity), nullable=False, index=True
    )
    status: Mapped[IncidentStatus] = mapped_column(
        Enum(IncidentStatus), nullable=False, index=True
    )

    # Layer 1: PyTorch Deep Learning, XGBoost & IsolationForest Telemetry
    pytorch_Reconstruction_error: Mapped[float] = mapped_column(
        Float, nullable=False)
    pytorch_attention_score: Mapped[float] = mapped_column(
        Float, nullable=False)
    xgboost_threat_probability: Mapped[float] = mapped_column(
        Float, nullable=False)
    isolation_forest_anomaly: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False)
    composite_anomaly_score: Mapped[float] = mapped_column(
        Float, nullable=False)

    # Layer 2: Zero-Trust Log-Injection Guardrail & PII Redaction
    log_injection_detected: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False)
    shannon_entropy: Mapped[float] = mapped_column(Float, nullable=False)
    pii_redacted_count: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False)

    # Layer 3: Hybrid CTI RAG (pgvector/Pinecone/Chroma + BM25 RRF) & CrewAI OSINT
    mitre_tactic: Mapped[MITRETactic] = mapped_column(
        Enum(MITRETactic), default=MITRETactic.NONE, nullable=False
    )
    mitre_technique_id: Mapped[str] = mapped_column(
        String(40), default="NONE", nullable=False)
    cti_rag_citations: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=list, nullable=False)
    crewai_osint_report: Mapped[str] = mapped_column(
        Text, default="", nullable=False)

    # Layer 4: Multi-LLM RCA, DSPy Calibration & AST-Verified SOAR Playbook
    llm_provider_used: Mapped[LLMProviderChoice] = mapped_column(
        Enum(LLMProviderChoice), default=LLMProviderChoice.ANTHROPIC, nullable=False
    )
    dspy_false_positive_likelihood: Mapped[float] = mapped_column(
        Float, default=0.0, nullable=False)
    executive_rca_summary: Mapped[str] = mapped_column(Text, nullable=False)
    remediation_actions: Mapped[list[str]] = mapped_column(
        JSON, default=list, nullable=False)
    soar_python_playbook: Mapped[str] = mapped_column(Text, nullable=False)
    ast_playbook_verified: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False)
    ast_violations: Mapped[list[str]] = mapped_column(
        JSON, default=list, nullable=False)
    hitl_approval_required: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False)
    agent_trace_log: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=list, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class SOARPlaybookExecutionLog(Base):
    """Audit trail of automated or HITL-approved SOAR containment actions executed via FastMCP."""

    __tablename__ = "soar_playbook_execution_logs"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    incident_id: Mapped[str] = mapped_column(
        String(36), nullable=False, index=True)
    action_type: Mapped[str] = mapped_column(String(80), nullable=False)
    target_entity: Mapped[str] = mapped_column(String(120), nullable=False)
    approved_by: Mapped[str] = mapped_column(
        String(80), default="AEGIS_AUTONOMOUS_SOAR", nullable=False)
    ast_verified: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False)
    execution_status: Mapped[str] = mapped_column(
        String(40), default="SUCCESS", nullable=False)
    mcp_tool_output: Mapped[dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False)

    executed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
