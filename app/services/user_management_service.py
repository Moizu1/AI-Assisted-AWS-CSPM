from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.user import User


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

    if user.role in ["SUPER_ADMIN", "ADMIN"]:
        if admin.role != "SUPER_ADMIN":
            raise PermissionError(
                "Only Super Admin can modify Admin accounts"
            )

    if new_role not in ["ADMIN", "ANALYST", "VIEWER"]:
        raise ValueError("Invalid role")

    if new_role == "ADMIN" and admin.role != "SUPER_ADMIN":
        raise PermissionError("Only Super Admin can assign Admin role")

    if user.id == admin.id:
        raise PermissionError("You cannot change your own role")

    user.role = new_role

    db.commit()
    db.refresh(user)

    return user