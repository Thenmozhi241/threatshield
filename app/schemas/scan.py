from datetime import datetime

from pydantic import BaseModel


class ScanRequest(BaseModel):
    asset_id: int
    scan_type: str = "full"  # full, dns, ssl, whois, ports, headers, reputation


class ScanResultOut(BaseModel):
    id: int
    asset_id: int
    scan_type: str
    status: str
    summary: str | None
    findings_count: int
    started_at: datetime
    finished_at: datetime | None

    class Config:
        from_attributes = True


class ThreatScoreOut(BaseModel):
    id: int
    asset_id: int
    score: float
    risk_level: str
    factors: str | None
    calculated_at: datetime

    class Config:
        from_attributes = True
