from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from app.database import Base


class PortScanResult(Base):
    __tablename__ = "port_scan_results"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    port = Column(Integer, nullable=False)
    is_open = Column(Boolean, default=False)
    service_guess = Column(String(100), nullable=True)
    banner = Column(String(500), nullable=True)
    checked_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    asset = relationship("Asset", back_populates="port_scan_results")
