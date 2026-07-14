from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from app.database import Base


class DNSRecord(Base):
    __tablename__ = "dns_records"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    record_type = Column(String(10), nullable=False)  # A, AAAA, MX, TXT, NS, CNAME, SOA
    value = Column(String(500), nullable=False)
    ttl = Column(Integer, nullable=True)
    checked_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    asset = relationship("Asset", back_populates="dns_records")
