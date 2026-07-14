"""
Background job functions run by APScheduler. Each job opens its own DB
session (since it runs outside the request lifecycle) and iterates over all
active assets, running the relevant checks and logging its own run in
SchedulerJob for observability.
"""
from datetime import datetime, timezone

from app.database import SessionLocal
from app.models.asset import Asset
from app.models.scheduler_job import SchedulerJob
from app.services.scan_orchestrator import run_full_scan
from app.utils.logger import logger


def _run_job(job_name: str, fn) -> None:
    db = SessionLocal()
    job_record = SchedulerJob(job_name=job_name, status="running")
    db.add(job_record)
    db.commit()
    db.refresh(job_record)

    try:
        details = fn(db)
        job_record.status = "success"
        job_record.details = details
    except Exception as exc:
        logger.exception("Scheduler job '%s' failed: %s", job_name, exc)
        job_record.status = "failed"
        job_record.details = str(exc)
    finally:
        job_record.finished_at = datetime.now(timezone.utc)
        db.commit()
        db.close()


def _scan_all_active_assets(db) -> str:
    assets = db.query(Asset).filter(Asset.is_active == "active").all()
    for asset in assets:
        run_full_scan(db, asset)
    return f"Scanned {len(assets)} active asset(s)."


def scheduled_full_scan() -> None:
    """Run the full scan pipeline (DNS, WHOIS, SSL, ports, headers, reputation,
    threat score, alerts) for every active asset. This single job covers all
    of: SSL expiry checks, WHOIS refresh, DNS refresh, reputation checks,
    threat score recalculation, and alert generation."""
    _run_job("full_scan", _scan_all_active_assets)
