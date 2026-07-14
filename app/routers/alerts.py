"""Alert routes: list, filter, and resolve alerts."""
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette import status
from datetime import datetime, timezone

from app.database import get_db
from app.dependencies import get_current_user
from app.models.alert import Alert
from app.models.user import User
from app.schemas.alert import AlertOut, AlertUpdate
from app.services.audit_service import log_action

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/alerts", tags=["ui"])
def alerts_page(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    alerts = db.query(Alert).order_by(Alert.created_at.desc()).limit(200).all()
    return templates.TemplateResponse("alerts.html", {"request": request, "user": user, "alerts": alerts})


@router.post("/alerts/{alert_id}/resolve", tags=["ui"])
def resolve_alert_ui(alert_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.is_resolved = True
    alert.resolved_at = datetime.now(timezone.utc)
    db.commit()
    log_action(db, user.id, "resolve_alert", resource=f"alert:{alert_id}")
    return RedirectResponse(url="/alerts", status_code=status.HTTP_302_FOUND)


@router.get("/api/alerts", response_model=list[AlertOut], tags=["alerts"])
def api_list_alerts(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return db.query(Alert).order_by(Alert.created_at.desc()).limit(500).all()


@router.patch("/api/alerts/{alert_id}", response_model=AlertOut, tags=["alerts"])
def api_update_alert(alert_id: int, payload: AlertUpdate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.is_resolved = payload.is_resolved
    alert.resolved_at = datetime.now(timezone.utc) if payload.is_resolved else None
    db.commit()
    db.refresh(alert)
    log_action(db, user.id, "resolve_alert", resource=f"alert:{alert_id}")
    return alert
