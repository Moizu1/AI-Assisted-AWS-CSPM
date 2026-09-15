from app.scanners.cloudtrail_scanner import CloudTrailScanner


class FakeCloudTrailClient:

    def describe_trails(self):
        return {
            "trailList": [
                {
                    "Name": "test-trail",
                    "HomeRegion": "us-east-1"
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