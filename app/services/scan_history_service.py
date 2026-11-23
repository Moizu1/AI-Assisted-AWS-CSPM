from sqlalchemy.orm import Session
from app.models.scan import Scan
from app.models.finding_record import FindingRecord

def get_scan_history(db: Session, limit: int = 10):
    return db.query(Scan).order_by(Scan.started_at.desc()).limit(limit).all()

def get_scan_by_id(db: Session, scan_id: int):
    return db.query(Scan).filter(Scan.id == scan_id).first()

def get_findings_by_scan_id(db: Session, scan_id: int):
    return db.query(FindingRecord).filter(FindingRecord.scan_id == scan_id).all()