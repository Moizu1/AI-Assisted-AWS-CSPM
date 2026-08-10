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
        findings.extend(self.check_password_policy())

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
        minimum_password_length= policy.get("MinimumPasswordLength", 0)
        if minimum_password_length < 14:
            finding = Finding(
                resource_type="IAM Account",
                resource_name="Account Password Policy",
                check="Minimum Password Length",
                severity="High",
                recommendation="Set the minimum password length to at least 14 characters."
            )
            findings.append(finding)
        required_uppercaseCharacters = policy.get("RequireUppercaseCharacters", False)
        if not required_uppercaseCharacters:
            finding = Finding(
                resource_type="IAM Account",
                resource_name="Account Password Policy",
                check="Require Uppercase Characters",
                severity="High",
                recommendation="Require at least one uppercase character in passwords."
            )
            findings.append(finding)
        required_lowercaseCharacters = policy.get("RequireLowercaseCharacters", False)
        if not required_lowercaseCharacters:
            finding = Finding(
                resource_type="IAM Account",
                resource_name="Account Password Policy",
                check="Require Lowercase Characters",
                severity="High",
                recommendation="Require at least one lowercase character in passwords."
            )
            findings.append(finding)
        required_numbers = policy.get("RequireNumbers", False)
        if not required_numbers:
            finding = Finding(
                resource_type="IAM Account",
                resource_name="Account Password Policy",
                check="Require Numbers",
                severity="High",
                recommendation="Require at least one number in passwords."
            )
            findings.append(finding)
        required_symbols = policy.get("RequireSymbols", False)
        if not required_symbols:
            finding = Finding(
                resource_type="IAM Account",
                resource_name="Account Password Policy",
                check="Require Symbols",
                severity="High",
                recommendation="Require at least one symbol in passwords."
            )
            findings.append(finding)
        password_reuse_prevention = policy.get("PasswordReusePrevention", 0)
        if password_reuse_prevention < 5:
            finding = Finding(
                resource_type="IAM Account",
                resource_name="Account Password Policy",
                check="Password Reuse Prevention",
                severity="High",
                recommendation="Set password reuse prevention to at least 5."
            )
            findings.append(finding)
        password_expiration = policy.get("ExpirePasswords", False)
        if not password_expiration:
            finding = Finding(
                resource_type="IAM Account",
                resource_name="Account Password Policy",
                check="Password Expiration",
                severity="High",
                recommendation="Set a password expiration policy to ensure regular password changes."
            )
            findings.append(finding)

        return findings
           


