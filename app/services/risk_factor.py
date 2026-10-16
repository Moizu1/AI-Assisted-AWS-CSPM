class RiskFactorService:

    RISK_FACTORS = {

        # IAM
        ("IAM User", "MFA ENABLED"): (3, 5, 4),
        ("IAM Account", "Minimum Password Length"): (2, 5, 3),
        ("IAM Account", "Require Uppercase Characters"): (2, 5, 3),
        ("IAM Account", "Require Lowercase Characters"): (2, 5, 3),
        ("IAM Account", "Require Numbers"): (2, 5, 3),
        ("IAM Account", "Require Symbols"): (2, 5, 3),
        ("IAM Account", "Password Reuse Prevention"): (2, 5, 3),
        ("IAM Account", "Password Expiration"): (2, 5, 3),

        # S3
        ("S3 Bucket", "S3 PUBLIC ACCESS BLOCK"): (5, 5, 5),
        ("S3 Bucket", "S3 ENCRYPTION"): (3, 4, 4),
        ("S3 Bucket", "S3 VERSIONING"): (2, 3, 2),
        ("S3 Bucket", "S3 LOGGING"): (2, 4, 2),

        # EC2 / Security Groups
        ("EC2 Security Group", "SSH OPEN TO THE WORLD"): (5, 4, 5),
        ("EC2 Security Group", "RDP OPEN TO THE WORLD"): (5, 4, 5),
        ("EC2 Security Group", "ALL PORTS OPEN TO THE WORLD"): (5, 5, 5),
        ("EC2 Security Group", "DANGEROUS PORTS OPEN TO THE WORLD"): (5, 5, 5),
        ("EC2 Security Group", "SSH OPEN TO THE WORLD (IPv6)"): (5, 4, 5),

        # CloudTrail
        ("CloudTrail", "Logging Enabled"): (2, 5, 3),
        ("CloudTrail", "Multi-Region Trail"): (2, 4, 2),
        ("CloudTrail", "Log File Validation"): (2, 4, 2),
        ("CloudTrail", "S3 Bucket Configured"): (2, 4, 2),
        ("CloudTrail", "CloudWatch Logs Configured"): (2, 4, 2),
        ("CloudTrail", "CloudTrail Trail Exists"): (2, 5, 3),
        ("CloudTrail", "Management Events Enabled"): (2, 5, 3),

        # RDS
        ("RDS Instance", "RDS PUBLIC ACCESS"): (5, 5, 5),
        ("RDS Instance", "RDS ENCRYPTION"): (3, 5, 4),
        ("RDS Instance", "RDS DELETION PROTECTION"): (3, 5, 3),
        ("RDS Instance", "RDS BACKUP RETENTION"): (2, 5, 3),
        ("RDS Instance", "RDS MULTI-AZ DEPLOYMENT"): (2, 4, 2),

        # EBS
        ("EBS Volume", "EBS ENCRYPTION"): (2, 4, 3),
        ("EBS Volume", "EBS ATTACHMENT"): (1, 2, 1),
        ("EBS Volume", "EBS DELETE ON TERMINATION"): (2, 3, 2),
    }

    def get_factors(self, resource_type, check):
        return self.RISK_FACTORS.get((resource_type, check))