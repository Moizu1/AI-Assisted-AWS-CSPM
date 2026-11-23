from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    DateTime,
    CheckConstraint,
    ForeignKey,
)

from app.database.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    full_name = Column(
        String(150),
        nullable=False
    )

    email = Column(
        String(255),
        unique=True,
        index=True,
        nullable=False
    )

    hashed_password = Column(
        String(255),
        nullable=False
    )

    organization = Column(
        String(150),
        nullable=True
    )

    contact_number = Column(
        String(30),
        nullable=True
    )

    role = Column(
        String(30),
        nullable=False,
        default="VIEWER"
    )

    status = Column(
        String(30),
        nullable=False,
        default="PENDING"
    )

    is_two_factor_enabled = Column(
        Boolean,
        default=False,
        nullable=False
    )

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    last_login_at = Column(
        DateTime(timezone=True),
        nullable=True
    )

    __table_args__ = (
        CheckConstraint(
            "role IN ('SUPER_ADMIN', 'ADMIN', 'ANALYST', 'VIEWER')",
            name="check_valid_user_role"
        ),
        CheckConstraint(
            "status IN ('PENDING', 'ACTIVE', 'REJECTED', 'DEACTIVATED')",
            name="check_valid_user_status"
        ),
    )

    approved_by_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=True
    )

    approved_at = Column(
        DateTime(timezone=True),
        nullable=True
    )

    rejection_reason = Column(
        String(500),
        nullable=True
    )

    