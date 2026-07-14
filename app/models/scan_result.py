from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.database import Base


class ScanResult(Base):
    """A single high-level scan run against an asset, aggregating findings."""

    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    scan_type = Column(String(50), nullable=False)  # full, dns, ssl, whois, ports, headers, reputation
    status = Column(String(20), default="completed")  # pending, running, completed, failed
    summary = Column(Text, nullable=True)
    findings_count = Column(Integer, default=0)
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    finished_at = Column(DateTime, nullable=True)

    asset = relationship("Asset", back_populates="scan_results")
