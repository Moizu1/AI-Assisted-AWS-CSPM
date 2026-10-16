from app.services.scan_orchestrator import run_full_scan

if __name__ == "__main__":
    region = "us-east-1"  # You can change this to any AWS region you want to scan.
    scan, all_findings, scanner_errors = run_full_scan(region=region)

    print("\n========== SCAN SUMMARY ==========")
    print(f"Scan ID: {scan.id}")
    print(f"Region: {scan.region}")
    print(f"Status: {scan.status}")
    print(f"Total findings: {len(all_findings)}")
    print(f"Risk score: {scan.risk_score}")

    if scanner_errors:
        print("\nErrors occurred during scanning:")
        for scanner_name, error_msg in scanner_errors.items():
            print(f"{scanner_name}: {error_msg}")