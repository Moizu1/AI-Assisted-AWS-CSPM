from app.clients.aws_client import AWSClient
from app.scanners.s3_scanner import S3Scanner

aws_client = AWSClient()
scanner = S3Scanner(aws_client)

findings = scanner.scan()

print("\n========== REAL AWS S3 SCAN ==========")
print(f"Total findings: {len(findings)}")

for finding in findings:
    print("\n------------------------------")
    print(f"Resource: {finding.resource_name}")
    print(f"Type: {finding.resource_type}")
    print(f"Finding details: {finding.__dict__}")