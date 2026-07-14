from datetime import datetime

from pydantic import BaseModel


class AlertOut(BaseModel):
    id: int
    asset_id: int
    severity: str
    category: str
    title: str
    message: str
    is_resolved: bool
    created_at: datetime
    resolved_at: datetime | None

    class Config:
        from_attributes = True


class AlertUpdate(BaseModel):
    is_resolved: bool
