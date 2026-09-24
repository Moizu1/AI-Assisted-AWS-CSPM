from app.models.finding import Finding

class RDSScanner:

    def __init__(self, awsclient):
        self.awsclient = awsclient

    def check_public_access(self, db_instance):
        return db_instance.get("PubliclyAccessible", False)
    
    