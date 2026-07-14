from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, Text

from app.database import Base


class SchedulerJob(Base):
    """Log of background scheduler job executions (for observability/audit)."""

    __tablename__ = "scheduler_jobs"

    id = Column(Integer, primary_key=True, index=True)
    job_name = Column(String(100), nullable=False)  # ssl_check, whois_refresh, dns_refresh, ...
    status = Column(String(20), default="success")  # success, failed
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    finished_at = Column(DateTime, nullable=True)
    details = Column(Text, nullable=True)
