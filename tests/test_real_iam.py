from app.clients.aws_client import AWSClient
from app.scanners.iam_scanner import IAMScanner

aws_client = AWSClient()
scanner = IAMScanner(aws_client)

findings = scanner.scan()

print("\n========== REAL AWS IAM SCAN ==========")
print(f"Total findings: {len(findings)}")

for finding in findings:
    print("\n------------------------------")
    print(f"Resource: {finding.resource_name}")
    print(f"Type: {finding.resource_type}")
    print(f"Check: {finding.check}")
    print(f"Severity: {finding.severity}")
    print(f"Description: {finding.recommendation}")  