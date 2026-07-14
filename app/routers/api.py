"""Miscellaneous REST API endpoints: health check, asset types, audit logs, stats."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user, require_admin
from app.models.alert import Alert
from app.models.asset import Asset, AssetType
from app.models.audit_log import AuditLog
from app.models.user import User

router = APIRouter()


@router.get("/api/health", tags=["system"])
def health_check():
    return {"status": "ok"}


@router.get("/api/asset-types", tags=["assets"])
def list_asset_types(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    types = db.query(AssetType).all()
    return [{"id": t.id, "name": t.name, "description": t.description} for t in types]


@router.get("/api/audit-logs", tags=["system"])
def list_audit_logs(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(500).all()
    return [
        {
            "id": log.id,
            "user_id": log.user_id,
            "action": log.action,
            "resource": log.resource,
            "ip_address": log.ip_address,
            "details": log.details,
            "created_at": log.created_at,
        }
        for log in logs
    ]


@router.get("/api/dashboard/stats", tags=["system"])
def dashboard_stats(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    total_assets = db.query(Asset).count()
    open_alerts = db.query(Alert).filter(Alert.is_resolved.is_(False)).count()
    critical_alerts = db.query(Alert).filter(Alert.is_resolved.is_(False), Alert.severity == "critical").count()
    return {
        "total_assets": total_assets,
        "open_alerts": open_alerts,
        "critical_alerts": critical_alerts,
    }
