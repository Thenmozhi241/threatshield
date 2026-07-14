from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.database import Base


class SSLResult(Base):
    __tablename__ = "ssl_results"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    issuer = Column(String(255), nullable=True)
    subject = Column(String(255), nullable=True)
    valid_from = Column(DateTime, nullable=True)
    valid_to = Column(DateTime, nullable=True)
    days_remaining = Column(Integer, nullable=True)
    is_valid = Column(Boolean, default=True)
    is_expired = Column(Boolean, default=False)
    protocol = Column(String(20), nullable=True)
    serial_number = Column(String(255), nullable=True)
    error_message = Column(Text, nullable=True)
    checked_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    asset = relationship("Asset", back_populates="ssl_results")
