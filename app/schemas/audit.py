from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    performed_by_id: int | None
    action: str
    target_user_id: int | None
    details: str | None
    created_at: datetime