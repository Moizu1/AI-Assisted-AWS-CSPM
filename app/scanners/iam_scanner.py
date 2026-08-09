from app.clients.aws_client import AWSClient
from app.models.finding import Finding


class IAMScanner:

    def __init__(self, awsclient):
        self.awsclient = awsclient

    def scan(self):
        findings = []
        users = self.list_users()
        for user in users:
            if not self.check_mfa_enabled(user):
                finding = Finding(
                    resource_type="IAM User",
                    resource_name=user["UserName"],
                    check="MFA ENABLED",
                    severity="High",
                    recommendation="Enable MFA for all IAM users to enhance security."
                )
                findings.append(finding)

        return findings            
        

    def list_users(self):

        response = self.awsclient.iam.list_users()

        return response["Users"]

    def check_mfa_enabled(self, user):
        username = user["UserName"]
        response = self.awsclient.iam.list_mfa_devices(UserName=username)
        return len(response["MFADevices"]) > 0
    def check_password_policy(self):
        response = self.awsclient.iam.get_account_password_policy()
        findings = []
        policy = response.get("PasswordPolicy", {})
        minimumPasswordLength= policy.get("MinimumPasswordLength", 0)
        if minimumPasswordLength < 14:
            finding = Finding(
                resource_type="IAM Account",
                resource_name="Account Password Policy",
                check="Minimum Password Length",
                severity="High",
                recommendation="Set the minimum password length to at least 14 characters."
            )
            findings.append(finding)
        return findings
           


