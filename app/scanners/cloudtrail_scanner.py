

from app.models.finding import Finding


class CloudTrailScanner:
    def __init__(self, awsclient):
        self.awsclient = awsclient

    def scan(self):
     findings = []
     trails = self.awsclient.cloudtrail.describe_trails()["trailList"]

     for trail in trails:

        if not self.check_logging_enabled(trail):
            findings.append(Finding(
                resource_type="CloudTrail",
                resource_name=trail["Name"],
                check="Logging Enabled",
                severity="Critical",
                recommendation="Enable logging for the CloudTrail."
            ))

        if not self.check_multi_region(trail):
            findings.append(Finding(
                resource_type="CloudTrail",
                resource_name=trail["Name"],
                check="Multi-Region Trail",
                severity="High",
                recommendation="Enable multi-region trail for the CloudTrail."
            ))

        if not self.check_log_file_validation(trail):
            findings.append(Finding(
                resource_type="CloudTrail",
                resource_name=trail["Name"],
                check="Log File Validation",
                severity="Medium",
                recommendation="Enable log file validation for the CloudTrail."
            ))

        if not self.check_s3_bucket(trail):
            findings.append(Finding(
                resource_type="CloudTrail",
                resource_name=trail["Name"],
                check="S3 Bucket Configured",
                severity="High",
                recommendation="Configure an S3 bucket for the CloudTrail."
            ))

        if not self.check_cloudwatch_logs(trail):
            findings.append(Finding(
                resource_type="CloudTrail",
                resource_name=trail["Name"],
                check="CloudWatch Logs Configured",
                severity="Medium",
                recommendation="Configure CloudWatch Logs for the CloudTrail."
            ))

        if not self.check_management_events(trail):
            findings.append(Finding(
                resource_type="CloudTrail",
                resource_name=trail["Name"],
                check="Management Events Enabled",
                severity="High",
                recommendation="Enable management events for the CloudTrail."
            ))

     return findings
    
    def check_logging_enabled(self, trail):
        response = self.awsclient.cloudtrail.get_trail_status(
        Name=trail["Name"]
        )
        return response.get("IsLogging", False)

    def check_multi_region(self, trail):
        return trail.get("IsMultiRegionTrail", False)

    def check_log_file_validation(self, trail):
        return trail.get("LogFileValidationEnabled", False)

    def check_s3_bucket(self, trail):
        return bool(trail.get("S3BucketName", False))

    def check_cloudwatch_logs(self, trail):
        return bool(trail.get("CloudWatchLogsLogGroupArn", False))

    def check_management_events(self, trail):
        for selector in self.awsclient.cloudtrail.get_event_selectors(Name=trail["Name"])["EventSelectors"]:
            if selector.get("IncludeManagementEvents", False):
                return True
        return False