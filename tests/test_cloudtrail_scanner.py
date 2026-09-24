from app.scanners.cloudtrail_scanner import CloudTrailScanner


class FakeCloudTrailClient:

    def describe_trails(self):
        return {
            "trailList": [
                {
                    "Name": "test-trail",
                    "HomeRegion": "us-east-1",
                    "IsMultiRegionTrail": True,
                    "LogFileValidationEnabled": True,
                    "S3BucketName": "test-bucket",
                    "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:123456789012:log-group:test-log-group",
                }
            ]
        }
    def get_event_selectors(self, Name):
        if Name == "test-trail":
            Management_event = True
        elif Name == "test-trail-no-management":
            Management_event = False
        return {
            "EventSelectors": [
                {
                    "ReadWriteType": "All",
                    "IncludeManagementEvents": Management_event
                    
                }
            ]
        }

    def get_trail_status(self, Name):
        return {
            "IsLogging": True
        }


class FakeAWSClient:

    def __init__(self):
        self.cloudtrail = FakeCloudTrailClient()


def test_check_logging_enabled():

    awsclient = FakeAWSClient()
    scanner = CloudTrailScanner(awsclient)

    trail = {"Name": "test-trail"}

    assert scanner.check_logging_enabled(trail) == True

def test_check_multi_region():

    awsclient = FakeAWSClient()
    scanner = CloudTrailScanner(awsclient)

    trail = {
        "Name": "test-trail",
        "IsMultiRegionTrail": True
    }

    assert scanner.check_multi_region(trail) == True

def test_check_log_file_validation():

    awsclient = FakeAWSClient()
    scanner = CloudTrailScanner(awsclient)

    trail = {
        "Name": "test-trail",
        "LogFileValidationEnabled": True
    }

    assert scanner.check_log_file_validation(trail) == True

def test_check_s3_bucket():

    awsclient = FakeAWSClient()
    scanner = CloudTrailScanner(awsclient)

    trail = {
        "Name": "test-trail",
        "S3BucketName": "TestBucket"
    }
    trail2 = {
        "Name": "test-trail"
    }

    assert scanner.check_s3_bucket(trail) == True
    assert scanner.check_s3_bucket(trail2) == False

def test_check_cloudwatch_logs():

    awsclient = FakeAWSClient()
    scanner = CloudTrailScanner(awsclient)

    trail = {
        "Name": "test-trail",
        "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:123456789012:log-group:test-log-group"
    }
    trail2 = {
        "Name": "test-trail"
    }

    assert scanner.check_cloudwatch_logs(trail) == True
    assert scanner.check_cloudwatch_logs(trail2) == False

def test_check_management_events():

    awsclient = FakeAWSClient()
    scanner = CloudTrailScanner(awsclient)

    trail = {
        "Name": "test-trail",
        "EventSelectors": [
            {
                "ReadWriteType": "All",
                "IncludeManagementEvents": True
            }
        ]
    }
    trail2 = {
        "Name": "test-trail-no-management",
        "EventSelectors": [
            {
                "ReadWriteType": "All",
                "IncludeManagementEvents": False
            }
        ]
    }

    assert scanner.check_management_events(trail) == True
    assert scanner.check_management_events(trail2) == False

def test_scan():

    awsclient = FakeAWSClient()
    scanner = CloudTrailScanner(awsclient)

    findings = scanner.scan()

    assert len(findings) == 0