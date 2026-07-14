"""APScheduler setup: schedules the periodic full-scan job."""
from apscheduler.schedulers.background import BackgroundScheduler

from app.config import settings
from app.scheduler.jobs import scheduled_full_scan
from app.utils.logger import logger

scheduler = BackgroundScheduler()


def start_scheduler() -> None:
    if not settings.scheduler_enabled:
        logger.info("Scheduler disabled via configuration (SCHEDULER_ENABLED=false).")
        return

    scheduler.add_job(
        scheduled_full_scan,
        "interval",
        hours=settings.scan_interval_hours,
        id="scheduled_full_scan",
        replace_existing=True,
        next_run_time=None,  # first run scheduled at interval, not immediately
    )
    scheduler.start()
    logger.info("Scheduler started: full scan every %s hour(s).", settings.scan_interval_hours)


def shutdown_scheduler() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("Scheduler shut down.")
