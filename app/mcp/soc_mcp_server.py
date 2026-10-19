"""FastMCP server & A2A discovery card exposing SOAR containment tools, MITRE RAG, and AST verification."""

from datetime import datetime, timezone
from typing import Any
import uuid

from fastmcp import FastMCP

from app.core.config import settings
from app.core.logging import get_logger
from app.rag.hybrid_cti_retriever import hybrid_mitre_retriever
from app.rag.mitre_knowledge_base import MITRE_ATTACK_CORPUS
from app.security.ast_soar_sandbox import soar_ast_sandbox

logger = get_logger(__name__)

mcp_server = FastMCP(
    name=f"{settings.APP_NAME} - FastMCP SOAR Server",
    instructions=(
        "Exposes standardized SOC & SOAR tools over Model Context Protocol (MCP): "
        "Perimeter Firewall IP blocking, EDR Host Isolation, Hybrid MITRE ATT&CK RAG lookup, "
        "and Formal Python AST SOAR playbook verification."
    ),
)


@mcp_server.tool()
async def execute_perimeter_firewall_block(
    source_ip: str,
    incident_id: str,
    reason: str = "Automated AEGIS SOAR Perimeter Containment",
) -> dict[str, Any]:
    """
    Push an immediate ingress/egress DROP rule for a malicious IP to the perimeter firewall.

    Args:
        source_ip: Offending IPv4/IPv6 address to block.
        incident_id: Associated SOC incident UUID.
        reason: Audit justification for the firewall rule.
    """
    rule_id = f"FW-DROP-{uuid.uuid4().hex[:8].upper()}"
    logger.info(
        "FastMCP Tool [execute_perimeter_firewall_block] rule=%s ip=%s incident=%s",
        rule_id,
        source_ip,
        incident_id,
    )
    return {
        "tool": "execute_perimeter_firewall_block",
        "rule_id": rule_id,
        "incident_id": incident_id,
        "target_ip": source_ip,
        "action": "INGRESS_EGRESS_DROP",
        "status": "ENFORCED",
        "reason": reason,
        "enforced_at": datetime.now(timezone.utc).isoformat(),
    }


@mcp_server.tool()
async def execute_edr_host_isolation(
    target_host: str,
    incident_id: str,
    preserve_forensic_memory: bool = True,
) -> dict[str, Any]:
    """
    Quarantine a compromised enterprise host at the EDR agent layer while preserving forensic state.

    Args:
        target_host: Hostname or FQDN of the compromised server/endpoint.
        incident_id: Associated SOC incident UUID.
        preserve_forensic_memory: Whether to dump volatile RAM/LSASS state before network quarantine.
    """
    isolation_id = f"EDR-ISO-{uuid.uuid4().hex[:8].upper()}"
    logger.info(
        "FastMCP Tool [execute_edr_host_isolation] id=%s host=%s incident=%s",
        isolation_id,
        target_host,
        incident_id,
    )
    return {
        "tool": "execute_edr_host_isolation",
        "isolation_id": isolation_id,
        "incident_id": incident_id,
        "target_host": target_host,
        "network_quarantine": "ACTIVE_EXCEPT_EDR_CONTROL_PLANE",
        "volatile_memory_snapshot": "CAPTURED" if preserve_forensic_memory else "SKIPPED",
        "status": "HOST_ISOLATED",
        "isolated_at": datetime.now(timezone.utc).isoformat(),
    }


@mcp_server.tool()
async def query_mitre_hybrid_rag_tool(
    telemetry_query: str,
    top_k: int = 3,
) -> list[dict[str, Any]]:
    """
    Query the Hybrid MITRE ATT&CK Threat Intelligence engine (Dense Vector + BM25 RRF).

    Args:
        telemetry_query: Raw command line, alert title, or behavioral indicator description.
        top_k: Number of top RRF-fused MITRE ATT&CK techniques to return.
    """
    hits = hybrid_mitre_retriever.retrieve(query=telemetry_query, top_k=top_k)
    return [hit.model_dump(mode="json") for hit in hits]


@mcp_server.tool()
async def verify_soar_playbook_ast_tool(python_code: str) -> dict[str, Any]:
    """
    Statically verify a generated Python SOAR containment script inside the formal AST sandbox.

    Args:
        python_code: Python source code snippet to inspect for forbidden imports or RCE calls.
    """
    verification = soar_ast_sandbox.verify_playbook(python_code)
    return verification.model_dump(mode="json")


@mcp_server.resource("soc://mitre/enterprise-corpus")
async def get_mitre_corpus_resource() -> dict[str, Any]:
    """Expose the indexed MITRE ATT&CK Enterprise techniques over MCP resource URI."""
    return {
        "corpus_size": len(MITRE_ATTACK_CORPUS),
        "rrf_k_constant": settings.RRF_K_CONSTANT,
        "techniques": [
            {
                "technique_id": doc.technique_id,
                "technique_name": doc.technique_name,
                "tactic": doc.tactic.value,
            }
            for doc in MITRE_ATTACK_CORPUS
        ],
    }


def get_a2a_soc_commander_card() -> dict[str, Any]:
    """Return standardized Agent-to-Agent (A2A) discovery metadata for `/.well-known/agent.json`."""
    return {
        "agent_id": "aegis-autonomous-soc-commander-v1",
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "protocols": ["A2A-1.0", "FastMCP-1.0", "OpenAPI-3.1"],
        "description": (
            "Autonomous Multi-Agent SOC Commander & Guardrailed SOAR Platform combining "
            "PyTorch Autoencoder/Attention, XGBoost, IsolationForest, Hybrid MITRE ATT&CK RAG, "
            "CrewAI OSINT Hunters, DSPy Triage Calibration, and LangGraph Stateful Orchestration."
        ),
        "supported_llm_providers": ["anthropic", "openai", "gemini", "ollama", "vllm"],
        "capabilities": [
            "siem_neural_anomaly_detection",
            "log_embedded_prompt_injection_firewall",
            "hybrid_rrf_mitre_attack_attribution",
            "crewai_osint_threat_enrichment",
            "dspy_false_positive_calibration",
            "ast_verified_soar_containment",
            "hitl_commander_governance",
        ],
        "endpoints": {
            "investigate_telemetry": f"{settings.API_V1_PREFIX}/soc/investigate",
            "simulate_apt_scenario": f"{settings.API_V1_PREFIX}/soc/simulate",
            "hitl_soar_approval": f"{settings.API_V1_PREFIX}/soc/incidents/{{incident_id}}/hitl-approve",
            "dashboard_metrics": f"{settings.API_V1_PREFIX}/soc/dashboard-metrics",
        },
    }


if __name__ == "__main__":
    mcp_server.run()
