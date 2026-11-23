from sqlalchemy.orm import Session

from app.models.user import User
from app.schemas.auth import UserRegister
from app.core.security import hash_password, verify_password


def register_user(db: Session, user_data: UserRegister):
    """Register a new user with PENDING status."""

    normalized_email = str(user_data.email).strip().lower()

    existing_user = (
        db.query(User)
        .filter(User.email == normalized_email)
        .first()
    )

    if existing_user:
        return None

    new_user = User(
        full_name=user_data.full_name.strip(),
        email=normalized_email,
        hashed_password=hash_password(user_data.password),
        organization=user_data.organization,
        contact_number=user_data.contact_number,
        role="VIEWER",
        status="PENDING",
        is_two_factor_enabled=False
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


def authenticate_user(
    db: Session,
    email: str,
    password: str
):
    """Authenticate a user using email and password."""

    normalized_email = email.strip().lower()

    user = (
        db.query(User)
        .filter(User.email == normalized_email)
        .first()
    )

    if not user:
        return None

    if not verify_password(password, user.hashed_password):
        return None

    return user