"""System settings routes (admin only): view/edit key-value settings."""
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette import status

from app.database import get_db
from app.dependencies import require_admin
from app.models.setting import Setting
from app.models.user import User
from app.services.audit_service import log_action

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

DEFAULT_SETTINGS = {
    "scan_interval_hours": ("24", "How often (hours) the scheduler runs automatic scans"),
    "email_alerts_enabled": ("false", "Enable email alert delivery"),
    "telegram_alerts_enabled": ("false", "Enable Telegram alert delivery"),
    "slack_alerts_enabled": ("false", "Enable Slack alert delivery"),
}


def _ensure_defaults(db: Session) -> None:
    for key, (value, description) in DEFAULT_SETTINGS.items():
        if not db.query(Setting).filter(Setting.key == key).first():
            db.add(Setting(key=key, value=value, description=description))
    db.commit()


@router.get("/settings", tags=["ui"])
def settings_page(request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    _ensure_defaults(db)
    settings_list = db.query(Setting).order_by(Setting.key).all()
    return templates.TemplateResponse("settings.html", {"request": request, "user": user, "settings": settings_list})


@router.post("/settings/update", tags=["ui"])
def update_settings(request: Request, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    return RedirectResponse(url="/settings", status_code=status.HTTP_302_FOUND)


@router.post("/settings/{key}/update", tags=["ui"])
def update_setting(key: str, value: str = Form(...), db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    setting = db.query(Setting).filter(Setting.key == key).first()
    if setting:
        setting.value = value
        db.commit()
        log_action(db, admin.id, "update_setting", resource=f"setting:{key}", details=value)
    return RedirectResponse(url="/settings", status_code=status.HTTP_302_FOUND)
