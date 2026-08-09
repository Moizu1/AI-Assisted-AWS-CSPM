from app.models.finding import Finding
from app.scanners.iam_scanner import IAMScanner

class FakeIAM: 
    def list_users(self):
        users = [
            {"UserName": "user1"},
            {"UserName": "user2"},
            {"UserName": "user3"}
        ]
        return {"Users": users}
    def list_mfa_devices(self, UserName):
        if UserName == "user1":
            return {"MFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/user1"}]}
        else:
            return {"MFADevices": []}
    def get_account_password_policy(self):
        return {"PasswordPolicy": {"MinimumPasswordLength": 8, "RequireSymbols": True, "RequireNumbers": True, "RequireUppercaseCharacters": True, "RequireLowercaseCharacters": True, "AllowUsersToChangePassword": True, "ExpirePasswords": True, "MaxPasswordAge": 90, "PasswordReusePrevention": 5}}

class FakeAWSClient:
    def __init__(self):
        self.iam = FakeIAM()

def test_iam_scanner():
    fake_aws_client = FakeAWSClient()
    scanner = IAMScanner(fake_aws_client)
    findings = scanner.scan()

    assert len(findings) == 2
    resource_names = [finding.resource_name for finding in findings]
    assert "user2" in resource_names
    assert "user3" in resource_names

    assert findings[0].resource_type == "IAM User"
    assert findings[0].check == "MFA ENABLED"
    assert findings[0].severity == "High"
    assert findings[0].recommendation == "Enable MFA for all IAM users to enhance security."
    assert findings[0].issue_resolved is False
    assert findings[0].score == 75
    assert findings[0].resource_name == "user2"

    password_check = scanner.check_password_policy()
    assert len(password_check) == 1