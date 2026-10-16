from app.database.database import SessionLocal
from app.models.scan import Scan
from app.models.finding_record import FindingRecord
from app.models.finding import Finding
from app.services.scan_service import save_scan_results
from app.services.risk_scoring import RiskScoringService


def test_save_scan_results():
    db = SessionLocal()

    try:
        # Create a sample finding.
        finding = Finding(
            resource_type="S3 Bucket",
            resource_name="test-bucket",
            check="S3 PUBLIC ACCESS BLOCK",
            severity="High",
            recommendation="Block public access to the bucket.",
        )

        # Calculate its risk score using your existing service.
        risk_scoring_service = RiskScoringService()
        risk_scoring_service.process_finding(finding)

        # Save the finding and scan to PostgreSQL.
        scan = save_scan_results(
            db=db,
            findings=[finding],
            region="us-east-1",
        )

        # Verify the scan was saved.
        saved_scan = db.query(Scan).filter_by(id=scan.id).first()

        assert saved_scan is not None
        assert saved_scan.status == "COMPLETED"
        assert saved_scan.total_findings == 1
        assert saved_scan.region == "us-east-1"

        # Verify the finding was saved.
        saved_finding = (
            db.query(FindingRecord)
            .filter_by(scan_id=scan.id)
            .first()
        )

        assert saved_finding is not None
        assert saved_finding.resource_name == "test-bucket"
        assert saved_finding.check == "S3 PUBLIC ACCESS BLOCK"
        assert saved_finding.score is not None

        print(f"\nScan saved successfully. Scan ID: {scan.id}")
        print(f"Risk score: {saved_scan.risk_score}")
        print(f"Finding score: {saved_finding.score}")

    finally:
        db.close()