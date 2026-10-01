class Finding:
    def __init__(self, resource_type, resource_name, check, severity, recommendation, exposure=None, asset_sensitivity=None, exploitability=None):
        self.resource_type = resource_type
        self.resource_name = resource_name
        self.check = check
        self.severity = severity
        self.recommendation = recommendation
        self.exposure = exposure
        self.asset_sensitivity = asset_sensitivity
        self.exploitability = exploitability
        self.issue_resolved = False
        self.risk_level = None
        self.score = None

   
    