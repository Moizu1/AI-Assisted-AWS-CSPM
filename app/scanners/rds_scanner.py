from app.models.finding import Finding

class RDSScanner:

    def __init__(self, awsclient):
        self.awsclient = awsclient

    def scan(self):
        findings = []
        db_instances = self.list_db_instances()
        for db_instance in db_instances:
            db_instance_id = db_instance["DBInstanceIdentifier"]
            if not self.check_public_access(db_instance):
                finding = Finding(
                    resource_type="RDS Instance",
                    resource_name=db_instance_id,
                    check="RDS PUBLIC ACCESS",
                    severity="High",
                    recommendation="Disable public access for the RDS instance to enhance security."
                )
                findings.append(finding)
            if not self.check_encryption(db_instance):
                finding = Finding(
                    resource_type="RDS Instance",
                    resource_name=db_instance_id,
                    check="RDS ENCRYPTION",
                    severity="High",
                    recommendation="Enable encryption for the RDS instance to enhance security."
                )
                findings.append(finding)
            if not self.check_deletion_protection(db_instance):
                finding = Finding(
                    resource_type="RDS Instance",
                    resource_name=db_instance_id,
                    check="RDS DELETION PROTECTION",
                    severity="High",
                    recommendation="Enable deletion protection for the RDS instance to prevent accidental deletion."
                )
                findings.append(finding)
            if not self.check_backup_retention(db_instance):
                finding = Finding(
                    resource_type="RDS Instance",
                    resource_name=db_instance_id,
                    check="RDS BACKUP RETENTION",
                    severity="High",
                    recommendation="Enable backup retention for the RDS instance to ensure data recovery."
                )
                findings.append(finding)
            if not self.check_multi_az(db_instance):
                finding = Finding(
                    resource_type="RDS Instance",
                    resource_name=db_instance_id,
                    check="RDS MULTI-AZ DEPLOYMENT",
                    severity="High",
                    recommendation="Enable Multi-AZ deployment for the RDS instance to enhance availability and fault tolerance."
                )
                findings.append(finding)
        return findings


    def check_public_access(self, db_instance):
        return not db_instance.get("PubliclyAccessible", False)

    def list_db_instances(self):
        response = self.awsclient.rds.describe_db_instances()
        return response["DBInstances"]

    def check_encryption(self, db_instance):
        return bool(db_instance.get("StorageEncrypted", False))

    def check_deletion_protection(self, db_instance):
        return bool(db_instance.get("DeletionProtection", False))

    def check_backup_retention(self, db_instance):
        return db_instance.get("BackupRetentionPeriod", 0) > 0

    def check_multi_az(self, db_instance):
        return db_instance.get("MultiAZ", False)

    