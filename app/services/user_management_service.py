from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.user import User
from app.services.audit_service import create_audit_log


def get_pending_users(db: Session):
    """Return all pending registrations."""

    return (
        db.query(User)
        .filter(User.status == "PENDING")
        .order_by(User.created_at.asc())
        .all()
    )


def approve_user(
    db: Session,
    user_id: int,
    admin: User,
    assigned_role: str
):
    """Approve a pending user and assign a permitted role."""

    user = db.query(User).filter(User.id == user_id).first()

    if not user or user.status != "PENDING":
        return None

    allowed_roles = ["ADMIN", "ANALYST", "VIEWER"]

    if assigned_role not in allowed_roles:
        raise ValueError("Invalid role assignment")

    if assigned_role == "ADMIN" and admin.role != "SUPER_ADMIN":
        raise PermissionError("Only Super Admin can assign Admin role")

    if admin.role not in ["SUPER_ADMIN", "ADMIN"]:
        raise PermissionError("Insufficient permissions")

    user.role = assigned_role
    user.status = "ACTIVE"
    user.approved_by_id = admin.id
    user.approved_at = datetime.now(timezone.utc)
    user.rejection_reason = None

    db.commit()

    create_audit_log(
    db=db,
    performed_by_id=admin.id,
    action="USER_APPROVED",
    target_user_id=user.id,
    details=f"User approved with role {assigned_role}"
  )

    db.refresh(user)

    return user


def reject_user(
    db: Session,
    user_id: int,
    admin: User,
    reason: str | None = None
):
    """Reject a pending registration."""

    user = db.query(User).filter(User.id == user_id).first()

    if not user or user.status != "PENDING":
        return None

    if admin.role not in ["SUPER_ADMIN", "ADMIN"]:
        raise PermissionError("Insufficient permissions")

    user.status = "REJECTED"
    user.approved_by_id = admin.id
    user.approved_at = datetime.now(timezone.utc)
    user.rejection_reason = reason

    db.commit()

    create_audit_log(
    db=db,
    performed_by_id=admin.id,
    action="USER_REJECTED",
    target_user_id=user.id,
    details=f"Rejection reason: {reason}"
    )

    db.refresh(user)

    return user


def update_user_role(
    db: Session,
    user_id: int,
    admin: User,
    new_role: str
):
    """Change the role of an existing user."""

    user = db.query(User).filter(User.id == user_id).first()

    if not user or user.status != "ACTIVE":
        return None

    if admin.role not in ["SUPER_ADMIN", "ADMIN"]:
        raise PermissionError("Insufficient permissions")

    # Prevent users from changing their own roles
    if user.id == admin.id:
        raise PermissionError("You cannot change your own role")

    # Protect Super Admin accounts
    if user.role == "SUPER_ADMIN":
        raise PermissionError(
            "Super Admin accounts cannot be modified"
        )

    # Only Super Admin can modify Admin accounts
    if user.role == "ADMIN" and admin.role != "SUPER_ADMIN":
        raise PermissionError(
            "Only Super Admin can modify Admin accounts"
        )

    if new_role not in ["ADMIN", "ANALYST", "VIEWER"]:
        raise ValueError("Invalid role")

    if new_role == "ADMIN" and admin.role != "SUPER_ADMIN":
        raise PermissionError(
            "Only Super Admin can assign Admin role"
        )

    user.role = new_role

    db.commit()

    create_audit_log(
    db=db,
    performed_by_id=admin.id,
    action="USER_ROLE_UPDATED",
    target_user_id=user.id,
    details=f"New role assigned: {new_role}"
    )

    db.refresh(user)

    return user

def get_all_users(
    db: Session,
    role: str | None = None,
    status: str | None = None,
    search: str | None = None
):
    """Return users with optional role, status, and search filters."""

    query = db.query(User)

    # Filter by role
    if role:
        query = query.filter(User.role == role.upper())

    # Filter by account status
    if status:
        query = query.filter(User.status == status.upper())

    # Search by name or email
    if search:
        search_term = f"%{search.strip()}%"
        query = query.filter(
            (User.full_name.ilike(search_term)) |
            (User.email.ilike(search_term))
        )

    return query.order_by(User.created_at.desc()).all()

def deactivate_user(
    db: Session,
    user_id: int,
    admin: User
):
    """Deactivate an existing user account."""

    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        return None

    if admin.role not in ["SUPER_ADMIN", "ADMIN"]:
        raise PermissionError("Insufficient permissions")

    if user.id == admin.id:
        raise PermissionError(
            "You cannot deactivate your own account"
        )

    if user.role == "SUPER_ADMIN":
        raise PermissionError(
            "Super Admin accounts cannot be deactivated"
        )

    if user.role == "ADMIN" and admin.role != "SUPER_ADMIN":
        raise PermissionError(
            "Only Super Admin can deactivate Admin accounts"
        )

    if user.status != "ACTIVE":
        raise ValueError(
            "Only active accounts can be deactivated"
        )

    user.status = "DEACTIVATED"

    db.commit()

    create_audit_log(
    db=db,
    performed_by_id=admin.id,
    action="USER_DEACTIVATED",
    target_user_id=user.id,
    details="User account deactivated by administrator"
    )

    db.refresh(user)

    return user

def activate_user(
    db: Session,
    user_id: int,
    admin: User
):
    """Reactivate a previously deactivated user account."""

    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        return None

    if admin.role not in ["SUPER_ADMIN", "ADMIN"]:
        raise PermissionError("Insufficient permissions")

    if user.id == admin.id:
        raise PermissionError(
            "You cannot change your own account status"
        )

    if user.role == "SUPER_ADMIN":
        raise PermissionError(
            "Super Admin accounts cannot be modified"
        )

    if user.role == "ADMIN" and admin.role != "SUPER_ADMIN":
        raise PermissionError(
            "Only Super Admin can activate Admin accounts"
        )

    if user.status != "DEACTIVATED":
        raise ValueError(
            "Only deactivated accounts can be activated"
        )

    user.status = "ACTIVE"

    db.commit()

    create_audit_log(
    db=db,
    performed_by_id=admin.id,
    action="USER_ACTIVATED",
    target_user_id=user.id,
    details="User account activated by administrator"
)

    db.refresh(user)

    return user