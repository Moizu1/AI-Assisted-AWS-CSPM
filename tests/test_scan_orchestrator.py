from unittest.mock import patch, MagicMock

from app.services.scan_orchestrator import run_full_scan


@patch("app.services.scan_orchestrator.SessionLocal")
@patch("app.services.scan_orchestrator.save_scan_results")
@patch("app.services.scan_orchestrator.EBSScanner")
@patch("app.services.scan_orchestrator.CloudTrailScanner")
@patch("app.services.scan_orchestrator.S3Scanner")
@patch("app.services.scan_orchestrator.RDSScanner")
@patch("app.services.scan_orchestrator.EC2Scanner")
@patch("app.services.scan_orchestrator.IAMScanner")
@patch("app.services.scan_orchestrator.AWSClient")
def test_scan_partial_when_scanner_fails(
    mock_aws_client,
    mock_iam,
    mock_ec2,
    mock_rds,
    mock_s3,
    mock_cloudtrail,
    mock_ebs,
    mock_save,
    mock_session,
):
    # Mock the database session.
    mock_db = mock_session.return_value

    # Make IAM return one sample finding.
    sample_finding = MagicMock()
    sample_finding.resource_name = "test-user"
    mock_iam.return_value.scan.return_value = [sample_finding]

    # Simulate an RDS scanner failure.
    mock_rds.return_value.scan.side_effect = Exception(
        "Simulated RDS scan failure"
    )

    # Make the other scanners succeed with no findings.
    mock_ec2.return_value.scan.return_value = []
    mock_s3.return_value.scan.return_value = []
    mock_cloudtrail.return_value.scan.return_value = []
    mock_ebs.return_value.scan.return_value = []

    # Mock the risk-scoring service.
    with patch(
        "app.services.scan_orchestrator.RiskScoringService"
    ) as mock_risk_service:
        # Mock the saved scan record.
        mock_scan = MagicMock()
        mock_scan.id = 101
        mock_scan.status = "PARTIAL"
        mock_scan.risk_score = 80.0
        mock_save.return_value = mock_scan

        # Execute the orchestrator.
        scan, all_findings, scanner_errors = run_full_scan(
            region="us-east-1"
        )

    # Verify the scan status and recorded failure.
    assert scan.status == "PARTIAL"
    assert "MagicMock" in scanner_errors
    assert scanner_errors["MagicMock"] == "Simulated RDS scan failure"

    # Verify the successful IAM finding was retained.
    assert len(all_findings) == 1
    assert all_findings[0] is sample_finding

    # Verify scanners after RDS still ran.
    mock_s3.return_value.scan.assert_called_once()
    mock_cloudtrail.return_value.scan.assert_called_once()
    mock_ebs.return_value.scan.assert_called_once()

    # Verify results were saved with PARTIAL status.
    mock_save.assert_called_once()
    assert mock_save.call_args.kwargs["status"] == "PARTIAL"

    # Verify the database session was closed.
    mock_db.close.assert_called_once()


@patch("app.services.scan_orchestrator.SessionLocal")
@patch("app.services.scan_orchestrator.save_scan_results")
@patch("app.services.scan_orchestrator.EBSScanner")
@patch("app.services.scan_orchestrator.CloudTrailScanner")
@patch("app.services.scan_orchestrator.S3Scanner")
@patch("app.services.scan_orchestrator.RDSScanner")
@patch("app.services.scan_orchestrator.EC2Scanner")
@patch("app.services.scan_orchestrator.IAMScanner")
@patch("app.services.scan_orchestrator.AWSClient")
def test_scan_completed_when_all_scanners_succeed(
    mock_aws_client,
    mock_iam,
    mock_ec2,
    mock_rds,
    mock_s3,
    mock_cloudtrail,
    mock_ebs,
    mock_save,
    mock_session,
):
    # Mock the database session.
    mock_db = mock_session.return_value

    # Make every scanner succeed without findings.
    mock_iam.return_value.scan.return_value = []
    mock_ec2.return_value.scan.return_value = []
    mock_rds.return_value.scan.return_value = []
    mock_s3.return_value.scan.return_value = []
    mock_cloudtrail.return_value.scan.return_value = []
    mock_ebs.return_value.scan.return_value = []

    # Mock the saved scan record.
    mock_scan = MagicMock()
    mock_scan.id = 102
    mock_scan.status = "COMPLETED"
    mock_scan.risk_score = None
    mock_save.return_value = mock_scan

    # Execute the orchestrator.
    scan, all_findings, scanner_errors = run_full_scan(
        region="us-east-1"
    )

    # Verify successful completion.
    assert scan.status == "COMPLETED"
    assert scanner_errors == {}
    assert all_findings == []

    # Verify all six scanners ran.
    mock_iam.return_value.scan.assert_called_once()
    mock_ec2.return_value.scan.assert_called_once()
    mock_rds.return_value.scan.assert_called_once()
    mock_s3.return_value.scan.assert_called_once()
    mock_cloudtrail.return_value.scan.assert_called_once()
    mock_ebs.return_value.scan.assert_called_once()

    # Verify results were saved with COMPLETED status.
    mock_save.assert_called_once()
    assert mock_save.call_args.kwargs["status"] == "COMPLETED"

    # Verify the database session was closed.
    mock_db.close.assert_called_once()