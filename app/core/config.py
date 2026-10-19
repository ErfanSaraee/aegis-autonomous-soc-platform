"""Centralized Pydantic v2 configuration for the AEGIS Autonomous SOC & SOAR Platform."""

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Type-safe configuration across Multi-LLM providers, Databases, Celery, ML/DL, and SOC Guardrails."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Application & Server ---
    APP_NAME: str = "AEGIS Autonomous Agentic SOC & SOAR Platform"
    APP_VERSION: str = "1.0.0"
    APP_ENV: Literal["development", "staging",
                     "production", "testing"] = "development"
    DEBUG: bool = False
    API_V1_PREFIX: str = "/api/v1"
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    NEXT_PUBLIC_API_BASE_URL: str = "http://localhost:8000"

    # --- Database & Migrations (SQLAlchemy 2.0 Async + Alembic + pgvector) ---
    DATABASE_URL: str = "sqlite+aiosqlite:///./aegis_soc_telemetry.db"
    POSTGRES_PGVECTOR_URL: str = "postgresql+asyncpg://aegis:aegis_secret@localhost:5432/aegis_soc"

    # --- Distributed Task Queue (Redis & Celery) ---
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/1"
    CELERY_TASK_ALWAYS_EAGER: bool = True

    # --- Multi-Provider LLM Gateway (OpenAI, Anthropic, Gemini, Ollama, vLLM, HuggingFace) ---
    DEFAULT_LLM_PROVIDER: Literal[
        "openai", "anthropic", "gemini", "ollama", "vllm", "huggingface"
    ] = "anthropic"
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o"
    ANTHROPIC_API_KEY: str = ""
    ANTHROPIC_MODEL: str = "claude-3-7-sonnet-latest"
    GOOGLE_GEMINI_API_KEY: str = ""
    GOOGLE_GEMINI_MODEL: str = "gemini-2.5-flash"
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3.3:8b"
    VLLM_BASE_URL: str = "http://localhost:8001/v1"
    VLLM_MODEL: str = "meta-llama/Llama-3.3-70B-Instruct"
    HUGGINGFACE_API_TOKEN: str = ""

    # --- LangSmith Tracing & Observability ---
    LANGCHAIN_TRACING_V2: str = "false"
    LANGCHAIN_ENDPOINT: str = "https://api.smith.langchain.com"
    LANGCHAIN_API_KEY: str = ""
    LANGCHAIN_PROJECT: str = "aegis-autonomous-soc"

    # --- Hybrid Vector Threat Intelligence (Pinecone, ChromaDB, pgvector & RRF) ---
    PINECONE_API_KEY: str = ""
    PINECONE_INDEX_NAME: str = "mitre-attack-cti-index"
    CHROMA_PERSIST_DIR: str = "./chroma_db"
    RRF_K_CONSTANT: int = 60

    # --- Neural Anomaly Detection & Zero-Trust SOC Guardrails ---
    PYTORCH_ANOMALY_THRESHOLD: float = 0.65
    SHANNON_ENTROPY_THRESHOLD: float = 4.40
    AST_MAX_COMPLEXITY: int = 12
    AUTO_ISOLATE_CONFIDENCE_THRESHOLD: float = 0.88
    DSPY_OPTIMIZATION_ROUNDS: int = 3


@lru_cache
def get_settings() -> Settings:
    """Return cached singleton instance of application settings."""
    return Settings()


settings = get_settings()
