"""Celery & Redis distributed background worker for high-throughput SIEM batch ingestion & SOAR dispatch."""

import asyncio
from typing import Any

from celery import Celery

from app.core.config import settings
from app.core.logging import get_logger
from app.mcp.soc_mcp_server import (
    execute_edr_host_isolation,
    execute_perimeter_firewall_block,
)

logger = get_logger(__name__)

celery_app = Celery(
    "aegis_soc_worker",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_always_eager=settings.CELERY_TASK_ALWAYS_EAGER,
    task_eager_propagates=True,
)


@celery_app.task(name="aegis.workers.dispatch_soar_containment_task")
def dispatch_soar_containment_task(
    incident_id: str,
    source_ip: str,
    target_host: str,
    approved_by: str = "AEGIS_AUTONOMOUS_SOAR",
) -> dict[str, Any]:
    """
    Execute asynchronous SOAR containment (Perimeter Firewall IP Block + EDR Host Isolation)
    via FastMCP tools inside a Celery background worker.
    """
    logger.info(
        "Celery Worker dispatching SOAR containment for incident=%s (IP=%s, Host=%s)",
        incident_id,
        source_ip,
        target_host,
    )

    async def _run_mcp_actions() -> dict[str, Any]:
        fw_res = await execute_perimeter_firewall_block(
            source_ip=source_ip,
            incident_id=incident_id,
            reason=f"Approved by {approved_by}",
        )
        edr_res = await execute_edr_host_isolation(
            target_host=target_host,
            incident_id=incident_id,
            preserve_forensic_memory=True,
        )
        return {
            "incident_id": incident_id,
            "approved_by": approved_by,
            "firewall_action": fw_res,
            "edr_action": edr_res,
            "worker_status": "CONTAINMENT_COMPLETED",
        }

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # Safe fallback when invoked inside an active event loop in eager mode
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(lambda: asyncio.run(_run_mcp_actions())).result()

    return asyncio.run(_run_mcp_actions())
