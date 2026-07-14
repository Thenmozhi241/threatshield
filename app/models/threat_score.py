from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.database import Base


class ThreatScore(Base):
    """Computed risk/threat score for an asset at a point in time (0-100, higher = riskier)."""

    __tablename__ = "threat_scores"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    score = Column(Float, nullable=False, default=0.0)
    risk_level = Column(String(20), nullable=False, default="low")  # low, medium, high, critical
    factors = Column(Text, nullable=True)  # JSON-encoded breakdown of contributing factors
    calculated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    asset = relationship("Asset", back_populates="threat_scores")
