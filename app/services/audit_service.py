from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog


def create_audit_log(
    db: Session,
    performed_by_id: int | None,
    action: str,
    target_user_id: int | None = None,
    details: str | None = None
):
    """Record an administrative action."""

    audit_log = AuditLog(
        performed_by_id=performed_by_id,
        action=action,
        target_user_id=target_user_id,
        details=details
    )

    db.add(audit_log)
    db.commit()
    db.refresh(audit_log)

    return audit_log

def get_audit_logs(
    db: Session,
    action: str | None = None,
    target_user_id: int | None = None,
    limit: int = 100
):
    """Retrieve audit logs with optional filters."""

    query = db.query(AuditLog)

    if action:
        query = query.filter(AuditLog.action == action.upper())

    if target_user_id:
        query = query.filter(
            AuditLog.target_user_id == target_user_id
        )

    return (
        query
        .order_by(AuditLog.created_at.desc())
        .limit(limit)
        .all()
    )