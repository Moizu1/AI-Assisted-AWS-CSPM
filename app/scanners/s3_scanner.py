from app.models.finding import Finding
from botocore.exceptions import ClientError

class S3Scanner:
  def __init__(self, awsclient):
    self.awsclient = awsclient
  def scan(self):
    findings = []
    buckets = self.list_buckets()
    for bucket in buckets:
        bucket_name = bucket["Name"]
        if not self.check_public_access(bucket_name):
                finding = Finding(
                          resource_type="S3 Bucket",
                          resource_name=bucket_name,
                          check="S3 PUBLIC ACCESS BLOCK",
                          severity="High",
                          recommendation="Enable Public Access Block for the S3 bucket to enhance security."
                        )
                findings.append(finding)
        if not self.check_encryption(bucket_name):
                finding = Finding(
                  resource_type="S3 Bucket",
                  resource_name=bucket_name,
                  check="S3 ENCRYPTION",
                  severity="High",
                  recommendation="Enable encryption for the S3 bucket to enhance security."
                )
                findings.append(finding)
        if not self.check_versioning(bucket_name):
                finding = Finding(
                  resource_type="S3 Bucket",
                  resource_name=bucket_name,
                  check="S3 VERSIONING",
                  severity="High",
                  recommendation="Enable versioning for the S3 bucket to enhance data protection."
                )
                findings.append(finding)
        if not self.check_logging(bucket_name):
                finding = Finding(
                  resource_type="S3 Bucket",
                  resource_name=bucket_name,
                  check="S3 LOGGING",
                  severity="High",
                  recommendation="Enable logging for the S3 bucket to enhance monitoring and auditing."
                )
                findings.append(finding)
    return findings
  
  def list_buckets(self):
    try:
        response = self.awsclient.s3.list_buckets()
        return response.get("Buckets", [])

    except ClientError as error:
        error_code = error.response.get("Error", {}).get("Code", "Unknown")
        print(f"Failed to list S3 buckets. AWS error: {error_code}")
        raise

    except ClientError as error:
        error_code = error.response.get("Error", {}).get("Code", "Unknown")
        raise RuntimeError(
            f"Failed to list S3 buckets. AWS error: {error_code}"
        ) from error
  
  def check_public_access(self, bucket):
    try:
        response = self.awsclient.s3.get_public_access_block(
            Bucket=bucket
        )

        config = response.get("PublicAccessBlockConfiguration", {})

        required_settings = [
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        ]

        return all(config.get(setting) is True for setting in required_settings)

    except ClientError as error:
        error_code = error.response.get("Error", {}).get("Code")

        if error_code == "NoSuchPublicAccessBlockConfiguration":
            return False

        raise
  
  def check_encryption(self, bucket):
    try:
        response = self.awsclient.s3.get_bucket_encryption(
            Bucket=bucket
        )
        if response is None:
            raise RuntimeError(
                f"Unexpected empty encryption response for bucket: {bucket}"
            )  

        encryption_config = (
            response.get("ServerSideEncryptionConfiguration") or {}
        )

        rules = encryption_config.get("Rules") or []

        return len(rules) > 0

    except ClientError as error:
        error_code = error.response.get("Error", {}).get("Code")

        if error_code == "ServerSideEncryptionConfigurationNotFoundError":
            # S3 applies default SSE-S3 encryption to objects.
            return True

        raise
    
  def check_versioning(self, bucket):
    response = self.awsclient.s3.get_bucket_versioning(Bucket=bucket)
    return response.get("Status") == "Enabled"
  
  def check_logging(self, bucket):
    response = self.awsclient.s3.get_bucket_logging(
        Bucket=bucket
    )

    logging_config = response.get("LoggingEnabled")

    return isinstance(logging_config, dict) and bool(logging_config)

    