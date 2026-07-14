"""Audit logging service: records security-relevant actions taken by users."""
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog


def log_action(
    db: Session,
    user_id: int | None,
    action: str,
    resource: str | None = None,
    ip_address: str | None = None,
    details: str | None = None,
) -> AuditLog:
    entry = AuditLog(
        user_id=user_id,
        action=action,
        resource=resource,
        ip_address=ip_address,
        details=details,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry
