from app.clients.aws_client import AWSClient
from app.scanners.ebs_scanner import EBSScanner

aws_client = AWSClient()
scanner = EBSScanner(aws_client)

findings = scanner.scan()

print("\n========== REAL AWS EBS SCAN ==========")
print(f"Total findings: {len(findings)}")

for index, finding in enumerate(findings, start=1):
    print(f"\n{'=' * 50}")
    print(f"FINDING #{index}")
    print(f"{'=' * 50}")
    print(f"Resource Type:  {finding.resource_type}")
    print(f"Resource Name:  {finding.resource_name}")
    print(f"Security Check: {finding.check}")
    print(f"Severity:       {finding.severity}")
    print(f"Recommendation: {finding.recommendation}")
    print(f"Risk Score:     {finding.score}")
    print(f"Risk Level:     {finding.risk_level}")
    print(f"Resolved:       {finding.issue_resolved}")
    print(f"{'=' * 50}")