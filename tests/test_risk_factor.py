from app.services.risk_factor import RiskFactorService


def test_all_risk_factors_exist():

    service = RiskFactorService()

    for (resource_type, check), expected_factors in service.RISK_FACTORS.items():

        factors = service.get_factors(
            resource_type,
            check
        )

        assert factors == expected_factors


def test_mfa_risk_factors():

    service = RiskFactorService()

    factors = service.get_factors(
        "IAM User",
        "MFA ENABLED"
    )

    assert factors == (3, 5, 4)


def test_s3_public_access_risk_factors():

    service = RiskFactorService()

    factors = service.get_factors(
        "S3 Bucket",
        "S3 PUBLIC ACCESS BLOCK"
    )

    assert factors == (5, 5, 5)


def test_cloudtrail_logging_risk_factors():

    service = RiskFactorService()

    factors = service.get_factors(
        "CloudTrail",
        "Logging Enabled"
    )

    assert factors == (2, 5, 3)


def test_rds_public_access_risk_factors():

    service = RiskFactorService()

    factors = service.get_factors(
        "RDS Instance",
        "RDS PUBLIC ACCESS"
    )

    assert factors == (5, 5, 5)


def test_ebs_encryption_risk_factors():

    service = RiskFactorService()

    factors = service.get_factors(
        "EBS Volume",
        "EBS ENCRYPTION"
    )

    assert factors == (2, 4, 3)


def test_unknown_finding_returns_none():

    service = RiskFactorService()

    factors = service.get_factors(
        "Unknown Resource",
        "Unknown Check"
    )

    assert factors is None

def test_all_risk_factors_are_valid():

    service = RiskFactorService()

    for (resource_type, check), factors in service.RISK_FACTORS.items():

        assert resource_type
        assert check

        assert len(factors) == 3

        exposure, asset_sensitivity, exploitability = factors

        assert 1 <= exposure <= 5
        assert 1 <= asset_sensitivity <= 5
        assert 1 <= exploitability <= 5