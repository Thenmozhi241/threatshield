"""Dashboard route: monitoring summary stats and per-asset blacklist history."""
from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.dependencies import get_current_user
from app.models.asset import Asset
from app.models.blacklist_result import BlacklistResult
from app.models.user import User
from app.services.reputation_service import get_blacklist_summary

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/dashboard", tags=["ui"])
def dashboard(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    assets = db.query(Asset).order_by(Asset.created_at.desc()).all()
    total_assets = len(assets)
    monitoring_enabled = sum(1 for a in assets if a.is_active == "active")
    alert_channels_enabled = sum(
        [settings.email_alerts_enabled, settings.telegram_alerts_enabled, settings.slack_alerts_enabled]
    )

    asset_summaries = []
    currently_blacklisted = 0
    for asset in assets:
        summary = get_blacklist_summary(db, asset.id)
        if summary["total_count"] > 0:
            if summary["listed_count"] > 0:
                currently_blacklisted += 1
            asset_summaries.append({"asset": asset, **summary})

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "total_assets": total_assets,
            "monitoring_enabled": monitoring_enabled,
            "alert_channels_enabled": alert_channels_enabled,
            "currently_blacklisted": currently_blacklisted,
            "asset_summaries": asset_summaries,
        },
    )
