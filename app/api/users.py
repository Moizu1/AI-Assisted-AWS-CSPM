from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.database.dependencies import get_db
from app.core.dependencies import get_current_user, require_roles

from app.models.user import User

from app.schemas.user_management import (
    UserApprovalRequest,
    UserRejectionRequest,
    UserRoleUpdate,
    UserManagementResponse
)

from app.services.user_management_service import (
    get_pending_users,
    approve_user,
    reject_user,
    update_user_role,
    get_all_users,
    deactivate_user,
    activate_user
)


router = APIRouter()

@router.get(
    "/",
    response_model=list[UserManagementResponse]
)
def list_all_users(
    role: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    search: str | None = Query(default=None, min_length=1),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("SUPER_ADMIN", "ADMIN")
    )
):
    return get_all_users(
        db=db,
        role=role,
        status=status_filter,
        search=search
    )


@router.get(
    "/pending",
    response_model=list[UserManagementResponse]
)
def list_pending_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("SUPER_ADMIN", "ADMIN")
    )
):
    return get_pending_users(db)


@router.post(
    "/{user_id}/approve",
    response_model=UserManagementResponse
)
def approve_registration(
    user_id: int,
    request: UserApprovalRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("SUPER_ADMIN", "ADMIN")
    )
):
    try:
        user = approve_user(
            db,
            user_id,
            current_user,
            request.role
        )

    except PermissionError as error:
        raise HTTPException(
            status_code=403,
            detail=str(error)
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="Pending user not found"
        )

    return user


@router.post(
    "/{user_id}/reject",
    response_model=UserManagementResponse
)
def reject_registration(
    user_id: int,
    request: UserRejectionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("SUPER_ADMIN", "ADMIN")
    )
):
    try:
        user = reject_user(
            db,
            user_id,
            current_user,
            request.reason
        )

    except PermissionError as error:
        raise HTTPException(
            status_code=403,
            detail=str(error)
        )

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="Pending user not found"
        )

    return user


@router.patch(
    "/{user_id}/role",
    response_model=UserManagementResponse
)
def change_user_role(
    user_id: int,
    request: UserRoleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("SUPER_ADMIN", "ADMIN")
    )
):
    try:
        user = update_user_role(
            db,
            user_id,
            current_user,
            request.role
        )

    except PermissionError as error:
        raise HTTPException(
            status_code=403,
            detail=str(error)
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="Active user not found"
        )

    return user

@router.patch(
    "/{user_id}/deactivate",
    response_model=UserManagementResponse
)
def deactivate_user_account(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("SUPER_ADMIN", "ADMIN")
    )
):
    try:
        user = deactivate_user(
            db,
            user_id,
            current_user
        )

    except PermissionError as error:
        raise HTTPException(status_code=403, detail=str(error))

    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))

    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    return user

@router.patch(
    "/{user_id}/activate",
    response_model=UserManagementResponse
)
def activate_user_account(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("SUPER_ADMIN", "ADMIN")
    )
):
    try:
        user = activate_user(
            db,
            user_id,
            current_user
        )

    except PermissionError as error:
        raise HTTPException(status_code=403, detail=str(error))

    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))

    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    return user