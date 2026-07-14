from datetime import datetime

from pydantic import BaseModel


class ReportRequest(BaseModel):
    asset_id: int | None = None  # None = org-wide report
    report_type: str = "pdf"  # pdf, csv, xlsx


class ReportOut(BaseModel):
    id: int
    generated_by: int
    asset_id: int | None
    report_type: str
    title: str
    file_path: str
    created_at: datetime

    class Config:
        from_attributes = True
