from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Float, Integer, String
from app.database.database import Base
from sqlalchemy.orm import relationship


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)

    started_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    completed_at = Column(
        DateTime(timezone=True),
        nullable=True
    )

    status = Column(
        String(20),
        default="RUNNING",
        nullable=False
    )

    region = Column(
        String(50),
        nullable=False,
        default="us-east-1"
    )

    total_findings = Column(
        Integer,
        default=0,
        nullable=False
    )

    risk_score = Column(
        Float,
        nullable=True
    )

    error_message = Column(
        String,
        nullable=True
    )
    findings = relationship(
    "FindingRecord",
    back_populates="scan",
    cascade="all, delete-orphan",
    )