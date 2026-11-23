from app.database.database import SessionLocal
from app.services.dashboard_service import get_dashboard_summary


def test_get_dashboard_summary():
    db = SessionLocal()

    try:
        result = get_dashboard_summary(db)

        assert "total_scans" in result
        assert "total_findings" in result
        assert "critical_findings" in result
        assert "high_findings" in result
        assert "medium_findings" in result
        assert "low_findings" in result

        assert result["total_scans"] >= 0
        assert result["total_findings"] >= 0

        print(result)

    finally:
        db.close()