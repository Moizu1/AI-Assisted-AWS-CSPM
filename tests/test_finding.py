from app.models.finding import Finding
import pytest



def test_critical():

    finding = Finding(
        resource_type="RDS Instance",
        resource_name="test-db",
        check="RDS PUBLIC ACCESS",
        severity="Critical",
        recommendation="Test"
    )

    assert finding.severity == "Critical"
    assert finding.score is None
    assert finding.risk_level is None

def test_issue_resolved():
    finding = Finding("Resource1", "IAM user", "MFA NOT ENABLED", "Critical", "Enable MFA for all IAM users to enhance security.")
    assert finding.issue_resolved == False

def test_invalid_severity():

    finding = Finding(
        resource_type="Test",
        resource_name="test",
        check="Test",
        severity="Invalid",
        recommendation="Test"
    )

    assert finding.severity == "Invalid"