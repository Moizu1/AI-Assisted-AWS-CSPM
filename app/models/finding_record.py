from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    Float,
    DateTime,
    ForeignKey,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship
from datetime import datetime, timezone

from app.database.database import Base


class FindingRecord(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)

    scan_id = Column(
        Integer,
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    resource_type = Column(String(100), nullable=False)
    resource_name = Column(String(255), nullable=False)
    check = Column(String(150), nullable=False)
    severity = Column(String(20), nullable=False)
    recommendation = Column(String, nullable=True)

    exposure = Column(Integer, nullable=True)
    asset_sensitivity = Column(Integer, nullable=True)
    exploitability = Column(Integer, nullable=True)

    score = Column(Float, nullable=True)
    risk_level = Column(String(20), nullable=True)

    issue_resolved = Column(Boolean, default=False, nullable=False)

    first_detected_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    last_detected_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    scan = relationship("Scan", back_populates="findings")

    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "resource_type",
            "resource_name",
            "check",
            name="uq_finding_per_scan",
        ),
    )