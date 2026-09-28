from app.models.finding import Finding

class EBSScanner:

    def __init__(self, awsclient):
        self.awsclient = awsclient

    def scan(self):
        findings = []
        volumes = self.list_volumes()
        for volume in volumes:
            volume_id = volume["VolumeId"]
            if not self.check_encryption(volume):
                finding = Finding(
                    resource_type="EBS Volume",
                    resource_name=volume_id,
                    check="EBS ENCRYPTION",
                    severity="High",
                    recommendation="Enable encryption for the EBS volume to enhance security."
                )
                findings.append(finding)
            if not self.check_attachment(volume):
                finding = Finding(
                    resource_type="EBS Volume",
                    resource_name=volume_id,
                    check="EBS ATTACHMENT",
                    severity="Medium",
                    recommendation="Review unattached EBS volumes and remove unused volumes to reduce unnecessary resource exposure and cost."
                )
                findings.append(finding)
            if not self.check_delete_on_termination(volume):
                finding = Finding(
                    resource_type="EBS Volume",
                    resource_name=volume_id,
                    check="EBS DELETE ON TERMINATION",
                    severity="Medium",
                    recommendation="Enable delete on termination for the EBS volume to prevent orphaned volumes."
                )
                findings.append(finding)
        return findings

    def check_encryption(self, volume):
        return bool(volume.get("Encrypted", False))

    def list_volumes(self):
        response = self.awsclient.ec2.describe_volumes()
        return response["Volumes"]

    def check_attachment(self, volume):
        return bool(volume.get("Attachments", []))

    def check_delete_on_termination(self, volume):
        attachments = volume.get("Attachments", [])
        for attachment in attachments:
            if not attachment.get("DeleteOnTermination", True):
                return False
        return True