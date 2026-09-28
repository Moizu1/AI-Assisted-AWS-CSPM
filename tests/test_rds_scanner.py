from app.models.finding import Finding
from app.scanners.rds_scanner import RDSScanner

class FakeRDS:

    def describe_db_instances(self):
        db_instances = [

            # Fully secure RDS instance
            {
                "DBInstanceIdentifier": "db-secure",
                "PubliclyAccessible": False,
                "StorageEncrypted": True,
                "DeletionProtection": True,
                "BackupRetentionPeriod": 7,
                "MultiAZ": True
            },

            # RDS instance with multiple security issues
            {
                "DBInstanceIdentifier": "db-insecure",
                "PubliclyAccessible": True,
                "StorageEncrypted": False,
                "DeletionProtection": False,
                "BackupRetentionPeriod": 0,
                "MultiAZ": False
            },

            # RDS instance with some security issues
            {
                "DBInstanceIdentifier": "db-partial",
                "PubliclyAccessible": False,
                "StorageEncrypted": True,
                "DeletionProtection": False,
                "BackupRetentionPeriod": 7,
                "MultiAZ": False
            }
        ]

        return {"DBInstances": db_instances}
     



class FakeAWSClient:
    def __init__(self):
        self.rds = FakeRDS()

def test_check_public_access():
    awsclient = FakeAWSClient()
    scanner = RDSScanner(awsclient)

    assert scanner.check_public_access({"PubliclyAccessible": True}) == False
    assert scanner.check_public_access({"PubliclyAccessible": False}) == True

def test_list_db_instances():
    awsclient = FakeAWSClient()
    scanner = RDSScanner(awsclient)

    db_instances = scanner.list_db_instances()

    assert len(db_instances) == 3
    assert db_instances[0]["DBInstanceIdentifier"] == "db-secure"
    assert db_instances[1]["DBInstanceIdentifier"] == "db-insecure"
    assert db_instances[2]["DBInstanceIdentifier"] == "db-partial"

def test_check_encryption():
    awsclient = FakeAWSClient()
    scanner = RDSScanner(awsclient)

    assert scanner.check_encryption({"StorageEncrypted": True}) == True
    assert scanner.check_encryption({"StorageEncrypted": False}) == False

def test_check_deletion_protection():
    awsclient = FakeAWSClient()
    scanner = RDSScanner(awsclient)

    assert scanner.check_deletion_protection({"DeletionProtection": True}) == True
    assert scanner.check_deletion_protection({"DeletionProtection": False}) == False

def test_check_backup_retention():
    awsclient = FakeAWSClient()
    scanner = RDSScanner(awsclient)

    assert scanner.check_backup_retention({"BackupRetentionPeriod": 7}) == True
    assert scanner.check_backup_retention({"BackupRetentionPeriod": 0}) == False

def test_check_multi_az():
    awsclient = FakeAWSClient()
    scanner = RDSScanner(awsclient)

    assert scanner.check_multi_az({"MultiAZ": True}) == True
    assert scanner.check_multi_az({"MultiAZ": False}) == False

def test_scan():
    awsclient = FakeAWSClient()
    scanner = RDSScanner(awsclient)

    findings = scanner.scan()
    assert len(findings) == 7  


    assert isinstance(findings, list)