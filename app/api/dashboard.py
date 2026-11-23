from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database.dependencies import get_db
from app.schemas.scan_schema import ScanResponse
from app.services.dashboard_service import (
    get_dashboard_summary,
    get_recent_scans,
    get_risk_distribution
)

router = APIRouter()

@router.get("/summary")
def dashboard_summary(db: Session = Depends(get_db)):
    return get_dashboard_summary(db)

@router.get("/recent-scans", response_model=list[ScanResponse])
def recent_scans(
    db: Session = Depends(get_db),
    limit: int = 5
):
    return get_recent_scans(db, limit=limit)

@router.get("/risk-distribution")
def risk_distribution(db: Session = Depends(get_db)):
    return get_risk_distribution(db)
