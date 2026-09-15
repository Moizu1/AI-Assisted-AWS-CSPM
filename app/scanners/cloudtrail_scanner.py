
class CloudTrailScanner:
    def __init__(self, awsclient):
        self.awsclient = awsclient

    def check_logging_enabled(self, trail):
        response = self.awsclient.cloudtrail.get_trail_status(
        Name=trail["Name"]
        )
        return response.get("IsLogging", False)