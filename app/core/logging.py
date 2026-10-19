"""Structured SOC telemetry logging with trace correlation support."""

import logging
import sys

from app.core.config import settings


def setup_logging() -> None:
    """Configure standardized structured console logging across all SOC services and agents."""
    log_format = (
        "%(asctime)s | %(levelname)-8s | [AEGIS-SOC] %(name)s:%(funcName)s:%(lineno)d - %(message)s"
    )
    logging.basicConfig(
        level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
        format=log_format,
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,
    )
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger instance for a specific SOC module."""
    return logging.getLogger(name)
