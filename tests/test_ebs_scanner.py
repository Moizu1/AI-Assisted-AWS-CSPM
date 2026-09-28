from app.scanners.ebs_scanner import EBSScanner

class FakeEC2:

    def describe_volumes(self):
        return {
            "Volumes": [

                # Fully secure volume → 0 findings
                {
                    "VolumeId": "vol-secure",
                    "Encrypted": True,
                    "Attachments": [
                        {
                            "InstanceId": "i-secure",
                            "State": "attached",
                            "DeleteOnTermination": True
                        }
                    ]
                },

                # Multiple issues → 3 findings
                {
                    "VolumeId": "vol-insecure",
                    "Encrypted": False,
                    "Attachments": [
                        {
                            "InstanceId": "i-insecure",
                            "State": "attached",
                            "DeleteOnTermination": False
                        }
                    ]
                },

                # Unattached volume → 1 finding
                {
                    "VolumeId": "vol-unattached",
                    "Encrypted": True,
                    "Attachments": []
                }
            ]
        }


class FakeAWSClient:

    def __init__(self):
        self.ec2 = FakeEC2()

def test_check_encryption():
    awsclient = FakeAWSClient()
    scanner = EBSScanner(awsclient)

    volumes = scanner.awsclient.ec2.describe_volumes()["Volumes"]

    assert scanner.check_encryption(volumes[0]) == True
    assert scanner.check_encryption(volumes[1]) == False

def check_list_volumes():
    awsclient = FakeAWSClient()
    scanner = EBSScanner(awsclient)

    volumes = scanner.list_volumes()

    assert len(volumes) == 2
    assert volumes[0]["VolumeId"] == "vol-secure"
    assert volumes[1]["VolumeId"] == "vol-insecure"

def test_check_attachment():
    awsclient = FakeAWSClient()
    scanner = EBSScanner(awsclient)

    volume_with_attachment = {
        "VolumeId": "vol-attached",
        "Attachments": [
            {
                "InstanceId": "i-1234567890abcdef0",
                "State": "attached"
            }
        ]
    }

    volume_without_attachment = {
        "VolumeId": "vol-detached",
        "Attachments": []
    }

    assert scanner.check_attachment(volume_with_attachment) == True
    assert scanner.check_attachment(volume_without_attachment) == False

def test_check_delete_on_termination():
    awsclient = FakeAWSClient()
    scanner = EBSScanner(awsclient)

    volume_with_delete_on_termination = {
        "VolumeId": "vol-delete-on-termination",
        "Attachments": [
            {
                "InstanceId": "i-1234567890abcdef0",
                "DeleteOnTermination": True
            }
        ]
    }

    volume_without_delete_on_termination = {
        "VolumeId": "vol-no-delete-on-termination",
        "Attachments": [
            {
                "InstanceId": "i-1234567890abcdef0",
                "DeleteOnTermination": False
            }
        ]
    }

    assert scanner.check_delete_on_termination(volume_with_delete_on_termination) == True
    assert scanner.check_delete_on_termination(volume_without_delete_on_termination) == False

def test_scan():
    awsclient = FakeAWSClient()
    scanner = EBSScanner(awsclient)

    findings = scanner.scan()

    assert len(findings) == 3 

    
    finding_checks = [finding.check for finding in findings]
    assert "EBS ENCRYPTION" in finding_checks
    assert "EBS ATTACHMENT" in finding_checks
    assert "EBS DELETE ON TERMINATION" in finding_checks
    