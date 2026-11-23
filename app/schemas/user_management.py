from pydantic import BaseModel, Field
from typing import Literal, Optional


class UserApprovalRequest(BaseModel):
    role: Literal["ADMIN", "ANALYST", "VIEWER"]


class UserRejectionRequest(BaseModel):
    reason: Optional[str] = Field(default=None, max_length=500)


class UserRoleUpdate(BaseModel):
    role: Literal["ADMIN", "ANALYST", "VIEWER"]


class UserManagementResponse(BaseModel):
    id: int
    full_name: str
    email: str
    role: str
    status: str
    approved_by_id: Optional[int] = None
    rejection_reason: Optional[str] = None