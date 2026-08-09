from app.models.finding import Finding
import pytest



def test_critical():
    finding = Finding("Resource1", "IAM user", "MFA NOT ENABLED", "Critical", "Enable MFA for all IAM users to enhance security.")
    assert finding.score == 100

def test_issue_resolved():
    finding = Finding("Resource1", "IAM user", "MFA NOT ENABLED", "Critical", "Enable MFA for all IAM users to enhance security.")
    assert finding.issue_resolved == False

def test_invalid_severity():
    with pytest.raises(ValueError):
        Finding("Resource1", "IAM user", "MFA NOT ENABLED", "InvalidSeverity", "Enable MFA for all IAM users to enhance security.")