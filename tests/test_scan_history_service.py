from datetime import datetime, timezone, timedelta

from app.database.database import SessionLocal
from app.models.scan import Scan
from app.models.finding_record import FindingRecord
from app.services.scan_history_service import (
    get_scan_history,
    get_scan_by_id,
    get_findings_by_scan_id,
)


def test_get_scan_history():
    db = SessionLocal()
    older_id = None
    newer_id = None

    try:
        # Use future dates so existing database records
        # cannot push these test scans outside the limit.
        now = datetime.now(timezone.utc) + timedelta(days=365)

        older_scan = Scan(
            started_at=now,
            completed_at=now,
            status="COMPLETED",
            region="us-east-1",
            total_findings=3,
            risk_score=60.0,
        )

        newer_scan = Scan(
            started_at=now + timedelta(seconds=1),
            completed_at=now + timedelta(seconds=1),
            status="COMPLETED",
            region="us-east-1",
            total_findings=5,
            risk_score=80.0,
        )

        db.add_all([older_scan, newer_scan])
        db.commit()

        older_id = older_scan.id
        newer_id = newer_scan.id

        scans = get_scan_history(db, limit=1000)
        scan_ids = [scan.id for scan in scans]

        assert newer_id in scan_ids
        assert older_id in scan_ids
        assert scan_ids.index(newer_id) < scan_ids.index(older_id)

    finally:
        if newer_id is not None:
            db.query(Scan).filter(Scan.id == newer_id).delete()

        if older_id is not None:
            db.query(Scan).filter(Scan.id == older_id).delete()

        db.commit()
        db.close()


def test_get_scan_by_id():
    db = SessionLocal()
    scan_id = None

    try:
        scan = Scan(
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            status="COMPLETED",
            region="us-east-1",
            total_findings=0,
            risk_score=None,
        )

        db.add(scan)
        db.commit()

        scan_id = scan.id

        result = get_scan_by_id(db, scan_id)

        assert result is not None
        assert result.id == scan_id

    finally:
        if scan_id is not None:
            db.query(Scan).filter(Scan.id == scan_id).delete()
            db.commit()

        db.close()


def test_get_scan_by_id_not_found():
    db = SessionLocal()

    try:
        result = get_scan_by_id(db, -1)

        assert result is None

    finally:
        db.close()


def test_get_findings_by_scan_id():
    db = SessionLocal()
    scan_id = None

    try:
        scan = Scan(
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            status="COMPLETED",
            region="us-east-1",
            total_findings=1,
            risk_score=80.0,
        )

        db.add(scan)
        db.flush()

        scan_id = scan.id

        finding = FindingRecord(
            scan_id=scan_id,
            resource_type="S3 Bucket",
            resource_name="history-test-bucket",
            check="S3 PUBLIC ACCESS BLOCK",
            severity="High",
            recommendation="Block public access to the bucket.",
            exposure=5,
            asset_sensitivity=4,
            exploitability=4,
            score=80.0,
            risk_level="Critical",
            issue_resolved=False,
        )

        db.add(finding)
        db.commit()

        findings = get_findings_by_scan_id(db, scan_id)

        assert len(findings) == 1
        assert findings[0].scan_id == scan_id
        assert findings[0].resource_name == "history-test-bucket"

    finally:
        if scan_id is not None:
            db.query(FindingRecord).filter(
                FindingRecord.scan_id == scan_id
            ).delete()

            db.query(Scan).filter(
                Scan.id == scan_id
            ).delete()

            db.commit()

        db.close()


def test_get_findings_by_scan_id_returns_empty_list():
    db = SessionLocal()

    try:
        findings = get_findings_by_scan_id(db, -1)

        assert findings == []

    finally:
        db.close()