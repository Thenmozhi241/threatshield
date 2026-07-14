from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.database import Base


class AssetType(Base):
    """Lookup table: domain, ip, subnet, url, etc."""

    __tablename__ = "asset_types"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False)  # domain, ip, url
    description = Column(String(255), nullable=True)

    assets = relationship("Asset", back_populates="asset_type")


class Asset(Base):
    """A monitored asset: domain, IP address, or URL owned/managed by the organization."""

    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)  # e.g. example.com or 1.2.3.4
    asset_type_id = Column(Integer, ForeignKey("asset_types.id"), nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    description = Column(Text, nullable=True)
    tags = Column(String(255), nullable=True)  # comma-separated
    is_active = Column(String(10), default="active")  # active / paused / archived
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    asset_type = relationship("AssetType", back_populates="assets")
    owner = relationship("User", back_populates="assets")

    dns_records = relationship("DNSRecord", back_populates="asset", cascade="all, delete-orphan")
    whois_results = relationship("WhoisResult", back_populates="asset", cascade="all, delete-orphan")
    ssl_results = relationship("SSLResult", back_populates="asset", cascade="all, delete-orphan")
    port_scan_results = relationship("PortScanResult", back_populates="asset", cascade="all, delete-orphan")
    scan_results = relationship("ScanResult", back_populates="asset", cascade="all, delete-orphan")
    threat_scores = relationship("ThreatScore", back_populates="asset", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="asset", cascade="all, delete-orphan")
    blacklist_results = relationship("BlacklistResult", back_populates="asset", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Asset {self.name}>"
