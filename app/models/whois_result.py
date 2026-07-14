from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.database import Base


class WhoisResult(Base):
    __tablename__ = "whois_results"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    registrar = Column(String(255), nullable=True)
    registrant_org = Column(String(255), nullable=True)
    creation_date = Column(DateTime, nullable=True)
    expiration_date = Column(DateTime, nullable=True)
    updated_date = Column(DateTime, nullable=True)
    name_servers = Column(Text, nullable=True)  # comma-separated
    raw_data = Column(Text, nullable=True)
    checked_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    asset = relationship("Asset", back_populates="whois_results")
