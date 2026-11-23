from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database.dependencies import get_db
from app.services.scan_history_service import get_scan_history, get_scan_by_id, get_findings_by_scan_id
from app.schemas.scan_schema import ScanResponse, ScanRequest
from app.schemas.finding_schema import FindingResponse
from app.services.scan_orchestrator import run_full_scan

router = APIRouter()

@router.get("/scan-history", response_model=list[ScanResponse])
def read_scan_history(
    db: Session = Depends(get_db),
    limit: int = 10,
):
    return get_scan_history(db, limit=limit)


@router.get("/{scan_id}", response_model=ScanResponse)
def read_scan_by_id(
    scan_id: int,
    db: Session = Depends(get_db),
):
    scan = get_scan_by_id(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@router.get("/{scan_id}/findings", response_model=list[FindingResponse])
def read_findings_by_scan_id(
    scan_id: int,
    db: Session = Depends(get_db),
):
    scan = get_scan_by_id(db, scan_id)

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    findings = get_findings_by_scan_id(db, scan_id)

    return findings


@router.post("/run")
def trigger_scan(request: ScanRequest):
    scan, findings, scanner_errors = run_full_scan(
        region=request.region
    )

    return {
        "scan_id": scan.id,
        "status": scan.status,
        "region": scan.region,
        "total_findings": len(findings),
        "risk_score": scan.risk_score,
        "scanner_errors": scanner_errors
    }