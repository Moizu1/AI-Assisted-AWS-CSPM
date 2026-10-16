from app.clients.aws_client import AWSClient
from app.scanners.rds_scanner import RDSScanner

aws_client = AWSClient()
scanner = RDSScanner(aws_client)

findings = scanner.scan()

print("\n========== REAL AWS RDS SCAN ==========")
print(f"Total findings: {len(findings)}")

for finding in findings:
    print("\n------------------------------")
    print(f"Resource: {finding.resource_name}")
    print(f"Type: {finding.resource_type}")
    print(f"Check: {finding.check}")
    print(f"Severity: {finding.severity}")
    print(f"Description: {finding.recommendation}")  