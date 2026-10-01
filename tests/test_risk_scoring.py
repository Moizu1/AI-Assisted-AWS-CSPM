import pytest

from app.models.finding import Finding
from app.services.risk_scoring import RiskScoringService


def test_process_finding():

    finding = Finding(
        resource_type="RDS Instance",
        resource_name="test-db",
        check="RDS PUBLIC ACCESS",
        severity="High",
        recommendation="Test"
    )

    service = RiskScoringService()

    processed_finding = service.process_finding(finding)

    assert processed_finding.exposure == 5
    assert processed_finding.asset_sensitivity == 5
    assert processed_finding.exploitability == 5

    assert processed_finding.score == 94
    assert processed_finding.risk_level == "Critical"


def test_low_risk_finding():
    finding = Finding(
        resource_type="EBS",
        resource_name="vol-test",
        check="Attachment",
        severity="Low",
        recommendation="Review volume attachment",
        exposure=1,
        asset_sensitivity=1,
        exploitability=1
    )

    service = RiskScoringService()

    score = service.calculate_score(finding)

    assert score == 26


def test_invalid_severity():
    finding = Finding(
        resource_type="S3",
        resource_name="test-bucket",
        check="Encryption",
        severity="Unknown",
        recommendation="Enable encryption",
        exposure=3,
        asset_sensitivity=3,
        exploitability=3
    )

    service = RiskScoringService()

    with pytest.raises(ValueError):
        service.calculate_score(finding)


def test_missing_risk_factor():
    finding = Finding(
    resource_type="RDS Instance",
    resource_name="test-db",
    check="RDS PUBLIC ACCESS",
    severity="High",
    recommendation="Test"
    )

    service = RiskScoringService()

    with pytest.raises(ValueError):
        service.calculate_score(finding)

def test_risk_level_informational():
    service = RiskScoringService()
    assert service.calculate_risk_level(19) == "Informational"


def test_risk_level_low():
    service = RiskScoringService()
    assert service.calculate_risk_level(20) == "Low"
    assert service.calculate_risk_level(39) == "Low"


def test_risk_level_medium():
    service = RiskScoringService()
    assert service.calculate_risk_level(40) == "Medium"
    assert service.calculate_risk_level(59) == "Medium"


def test_risk_level_high():
    service = RiskScoringService()
    assert service.calculate_risk_level(60) == "High"
    assert service.calculate_risk_level(79) == "High"


def test_risk_level_critical():
    service = RiskScoringService()
    assert service.calculate_risk_level(80) == "Critical"
    assert service.calculate_risk_level(100) == "Critical"

def test_risk_factor_integration():

    service = RiskScoringService()

    finding = Finding(
        resource_type="S3 Bucket",
        resource_name="test-bucket",
        check="S3 PUBLIC ACCESS BLOCK",
        severity="High",
        recommendation="Enable Public Access Block"
    )

    processed_finding = service.process_finding(finding)

    assert processed_finding.exposure == 5
    assert processed_finding.asset_sensitivity == 5
    assert processed_finding.exploitability == 5

    assert processed_finding.score == 94
    assert processed_finding.risk_level == "Critical"