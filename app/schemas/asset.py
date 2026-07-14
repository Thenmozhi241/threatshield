from datetime import datetime

from pydantic import BaseModel, Field


class AssetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    asset_type_id: int
    description: str | None = None
    tags: str | None = None


class AssetUpdate(BaseModel):
    description: str | None = None
    tags: str | None = None
    is_active: str | None = None


class AssetOut(BaseModel):
    id: int
    name: str
    asset_type_id: int
    owner_id: int
    description: str | None
    tags: str | None
    is_active: str
    created_at: datetime
    updated_at: datetime | None

    class Config:
        from_attributes = True
