from app.services.risk_factor import RiskFactorService

class RiskScoringService:

    def __init__(self):
       self.risk_factor_service = RiskFactorService()
       

    def convert_severity_to_score(self, severity):
        severity_scores = {
            "Critical": 5,
            "High": 4,
            "Medium": 3,
            "Low": 2,
            "Info": 1
        }

        if severity not in severity_scores:
            raise ValueError(f"Invalid severity level: {severity}")

        return severity_scores[severity]

    def calculate_score(self, finding):
        severity_score = self.convert_severity_to_score(finding.severity)

        exposure = finding.exposure
        asset_sensitivity = finding.asset_sensitivity
        exploitability = finding.exploitability

        if None in (exposure, asset_sensitivity, exploitability):
            raise ValueError("All risk factors must be provided")

        weighted_score = (
            severity_score * 0.30
            + exposure * 0.25
            + asset_sensitivity * 0.25
            + exploitability * 0.20
        )

        final_score = weighted_score * 20

        return round(final_score, 2)

    def calculate_risk_level(self, final_score):

       if final_score >= 80:
        risk_level = "Critical"

       elif final_score >= 60:
        risk_level = "High"

       elif final_score >= 40:
        risk_level = "Medium"

       elif final_score >= 20:
        risk_level = "Low"

       else:
        risk_level = "Informational"

       return risk_level

    def process_finding(self, finding):

        factors = self.risk_factor_service.get_factors(
        finding.resource_type,
        finding.check
        )

        if factors is None:
            raise ValueError(
            f"No risk factors found for "
            f"{finding.resource_type} - {finding.check}"
         )

        finding.exposure = factors[0]
        finding.asset_sensitivity = factors[1]
        finding.exploitability = factors[2]

        final_score = self.calculate_score(finding)
        risk_level = self.calculate_risk_level(final_score)

        finding.score = final_score
        finding.risk_level = risk_level

        return finding 

    