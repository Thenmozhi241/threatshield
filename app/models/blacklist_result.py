from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from app.database import Base


class BlacklistResult(Base):
    """Per-provider DNSBL check result for an asset, recorded on each scan."""

    __tablename__ = "blacklist_results"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    provider = Column(String(255), nullable=False)
    is_listed = Column(Boolean, default=False)
    checked_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    asset = relationship("Asset", back_populates="blacklist_results")
