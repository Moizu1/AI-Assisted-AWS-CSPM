from app.clients.aws_client import AWSClient
from app.scanners.ec2_scanner import EC2Scanner

aws_client = AWSClient()
scanner = EC2Scanner(aws_client)

findings = scanner.scan()

print("\n========== REAL AWS EC2 SCAN ==========")
print(f"Total findings: {len(findings)}")

for finding in findings:
    print("\n------------------------------")
    print(f"Resource: {finding.resource_name}")
    print(f"Type: {finding.resource_type}")
    print(f"Finding details: {finding.__dict__}")