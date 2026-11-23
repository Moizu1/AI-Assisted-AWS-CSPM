from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.scan import Scan
from app.models.finding_record import FindingRecord

def get_dashboard_summary(db: Session):
    total_scans = db.query(func.count(Scan.id)).scalar()
    total_findings = db.query(func.count(FindingRecord.id)).scalar()
    critical_findings = db.query(func.count(FindingRecord.id)).filter(
    FindingRecord.risk_level == "Critical"
    ).scalar()
    high_findings = db.query(func.count(FindingRecord.id)).filter(
    FindingRecord.risk_level == "High"
    ).scalar()
    medium_findings = db.query(func.count(FindingRecord.id)).filter(
    FindingRecord.risk_level == "Medium"
    ).scalar()
    low_findings = db.query(func.count(FindingRecord.id)).filter(
    FindingRecord.risk_level == "Low"
    ).scalar()

    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "medium_findings": medium_findings,
        "low_findings": low_findings
    }

def get_recent_scans(db: Session, limit: int = 5):
    recent_scans = (
        db.query(Scan)
        .order_by(Scan.started_at.desc())
        .limit(limit)
        .all()
    )

    return recent_scans

def get_risk_distribution(db: Session): 
    risk_distribution = (
        db.query(FindingRecord.risk_level, func.count(FindingRecord.id))
        .group_by(FindingRecord.risk_level)
        .all()
    )

    return {
    "Critical": 0,
    "High": 0,
    "Medium": 0,
    "Low": 0,
    **{risk_level: count for risk_level, count in risk_distribution if risk_level}
    }