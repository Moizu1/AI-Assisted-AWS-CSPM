from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.scan import Scan
from app.models.finding_record import FindingRecord


def save_scan_results(
    db: Session,
    findings: list,
    status: str = "COMPLETED",
    region: str = "us-east-1",
) -> Scan:
   

    try:
        # 1. Calculate the overall scan risk score.
        scores = [
            finding.score
            for finding in findings
            if finding.score is not None
        ]

        overall_risk_score = max(scores) if scores else None

        # 2. Create the scan record.
        scan = Scan(
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            status=status,
            region=region,
            total_findings=len(findings),
            risk_score=overall_risk_score,
        )

        db.add(scan)

        # Assign an ID to the scan before saving its findings.
        db.flush()

        # 3. Convert application findings into database records.
        for finding in findings:
            finding_record = FindingRecord(
                scan_id=scan.id,
                resource_type=finding.resource_type,
                resource_name=finding.resource_name,
                check=finding.check,
                severity=finding.severity,
                recommendation=finding.recommendation,
                exposure=finding.exposure,
                asset_sensitivity=finding.asset_sensitivity,
                exploitability=finding.exploitability,
                score=finding.score,
                risk_level=finding.risk_level,
                issue_resolved=finding.issue_resolved,
            )

            db.add(finding_record)

        # 4. Save the scan and all findings together.
        db.commit()
        db.refresh(scan)

        return scan

    except Exception:
        # Undo partial database changes if anything fails.
        db.rollback()
        raise