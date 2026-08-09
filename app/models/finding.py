class Finding:
    def __init__(self, resource_type, resource_name, check, severity, recommendation):
        self.resource_type = resource_type
        self.resource_name = resource_name
        self.check = check
        self.severity = severity
        self.recommendation = recommendation
        self.issue_resolved = False
        self.score = self._calculate_score(severity)

    def _calculate_score(self, severity):
        severity_scores = {
            "Critical": 100,
            "High": 75,
            "Medium": 50,
            "Low": 25,
            "Info": 0
        }
        if severity not in severity_scores:
            raise ValueError(f"Invalid severity level: {severity}")
        return severity_scores[severity]
    