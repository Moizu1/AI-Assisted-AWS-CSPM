from app.scanners.iam_scanner import IAMScanner
from app.scanners.ec2_scanner import EC2Scanner
from app.scanners.rds_scanner import RDSScanner
from app.scanners.s3_scanner import S3Scanner
from app.scanners.cloudtrail_scanner import CloudTrailScanner
from app.scanners.ebs_scanner import EBSScanner
from app.clients.aws_client import AWSClient
from app.database.database import SessionLocal
from app.services.risk_scoring import RiskScoringService
from app.services.scan_service import save_scan_results

def run_full_scan(region = "us-east-1"):
    aws_client = AWSClient(region_name=region)
    scanners = [
        IAMScanner(aws_client),
        EC2Scanner(aws_client),
        RDSScanner(aws_client),
        S3Scanner(aws_client),
        CloudTrailScanner(aws_client),
        EBSScanner(aws_client)
    ]

    all_findings = []
    scanner_errors = {}
    for scanner in scanners:
        try:
            findings = scanner.scan()
            all_findings.extend(findings)
        except Exception as e:
            scanner_errors[scanner.__class__.__name__] = str(e)
            print(f"Error occurred while scanning with {scanner.__class__.__name__}: {e}")

    if not scanner_errors:
        scanner_status = "COMPLETED"
    else:
        scanner_status = "PARTIAL"

    risk_scoring_service = RiskScoringService()
    for finding in all_findings:
        try:
            risk_scoring_service.process_finding(finding)
        except ValueError as e:
             print(f"Error processing finding {finding.resource_name}: {e}")
            

    db = SessionLocal()
    try:    
        scan = save_scan_results(
            db=db,
            findings=all_findings,
            region=region,
            status=scanner_status
        )
        print(f"\nScan saved successfully. Scan ID: {scan.id}")
        print(f"Total findings: {len(all_findings)}")
        print(f"Risk score: {scan.risk_score}")
        if scanner_errors:
            print("\nErrors occurred during scanning:")
            for scanner_name, error_msg in scanner_errors.items():
                print(f"{scanner_name}: {error_msg}")
    finally:
        db.close()

    return scan, all_findings, scanner_errors