"""FastAPI application entrypoint for the AEGIS Autonomous Agentic SOC & SOAR Platform."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select

from app.agents.langgraph_soc_commander import langgraph_soc_commander
from app.api.v1.presets import APT_SIMULATION_PRESETS
from app.api.v1.soc_endpoints import persist_incident_response
from app.api.v1.soc_endpoints import router as soc_v1_router
from app.core.config import settings
from app.core.logging import get_logger, setup_logging
from app.db.session import AsyncSessionLocal, engine, init_db
from app.mcp.soc_mcp_server import get_a2a_soc_commander_card
from app.models.soc_models import SOCIncidentRecord

setup_logging()
logger = get_logger(__name__)


async def _seed_initial_soc_telemetry() -> None:
    """Pre-populate the database with the 4 canonical APT & benign scenarios if empty."""
    async with AsyncSessionLocal() as session:
        count_stmt = select(func.count()).select_from(SOCIncidentRecord)
        total = (await session.execute(count_stmt)).scalar_one()
        if total > 0:
            return

        logger.info(
            "Seeding AEGIS SOC database with initial APT & benign telemetry scenarios...")
        for key, preset in APT_SIMULATION_PRESETS.items():
            response = await langgraph_soc_commander.investigate_incident(preset)
            await persist_incident_response(
                session=session,
                raw_log=preset.raw_log_payload,
                response=response,
            )
            logger.info("Seeded scenario '%s' -> severity=%s",
                        key, response.severity.value)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    """Initialize async database tables and seed baseline SOC incidents on startup."""
    logger.info("Starting %s v%s (%s)...", settings.APP_NAME,
                settings.APP_VERSION, settings.APP_ENV)
    await init_db()
    if settings.APP_ENV != "testing":
        await _seed_initial_soc_telemetry()
    yield
    logger.info("Shutting down %s...", settings.APP_NAME)
    await engine.dispose()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Autonomous Multi-Agent SOC, Neural SIEM Anomaly Detection (PyTorch + XGBoost + IsolationForest), "
        "Hybrid MITRE ATT&CK RAG (pgvector/Pinecone + BM25 RRF), CrewAI OSINT, DSPy Calibration, "
        "and AST-Guardrailed SOAR Platform."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(
    soc_v1_router,
    prefix=settings.API_V1_PREFIX,
    tags=["AEGIS Autonomous SOC, MITRE RAG & Guardrailed SOAR"],
)


@app.get(
    "/.well-known/agent.json",
    tags=["A2A Protocol Discovery"],
    summary="Standardized Agent-to-Agent (A2A) SOC Commander discovery card",
)
async def a2a_agent_discovery() -> dict[str, Any]:
    """Expose peer-to-peer A2A agent capabilities, supported LLMs, and endpoints."""
    return get_a2a_soc_commander_card()


@app.get(
    "/health",
    tags=["Diagnostics"],
    summary="Platform readiness and multi-engine operational status",
)
async def healthcheck() -> dict[str, Any]:
    """Verify operational status across Neural ML, RAG, LangGraph, CrewAI, DSPy, and FastMCP."""
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "engines": {
            "pytorch_autoencoder_attention": "online",
            "xgboost_and_isolation_forest": "online",
            "zero_trust_log_injection_firewall": "online",
            "hybrid_rrf_mitre_attack_rag": "online",
            "crewai_osint_threat_hunters": "online",
            "dspy_false_positive_compiler": "online",
            "langgraph_7node_soc_commander": "online",
            "fastmcp_and_celery_soar": "online",
        },
    }
