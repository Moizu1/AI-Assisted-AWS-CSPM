from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database.dependencies import get_db
from app.core.dependencies import require_roles
from app.models.user import User

from app.schemas.audit import AuditLogResponse
from app.services.audit_service import get_audit_logs


router = APIRouter()


@router.get(
    "/",
    response_model=list[AuditLogResponse]
)
def list_audit_logs(
    action: str | None = Query(default=None),
    target_user_id: int | None = Query(default=None, ge=1),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("SUPER_ADMIN", "ADMIN")
    )
):
    return get_audit_logs(
        db=db,
        action=action,
        target_user_id=target_user_id,
        limit=limit
    )