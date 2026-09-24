from app.models.finding import Finding
from app.scanners.rds_scanner import RDSScanner

class FakeRDS:
    def describe_db_instances(self):
        db_instances = [
            {"DBInstanceIdentifier": "db1", "PubliclyAccessible": True},
            {"DBInstanceIdentifier": "db2", "PubliclyAccessible": False},
            {"DBInstanceIdentifier": "db3", "PubliclyAccessible": True}
        ]
        return {"DBInstances": db_instances}

class FakeAWSClient:
    def __init__(self):
        self.rds = FakeRDS()

def test_check_public_access():
    awsclient = FakeAWSClient()
    scanner = RDSScanner(awsclient)

    assert scanner.check_public_access({"PubliclyAccessible": True}) == True
    assert scanner.check_public_access({"PubliclyAccessible": False}) == False