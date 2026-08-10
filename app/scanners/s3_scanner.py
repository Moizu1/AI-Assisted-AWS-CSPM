from app.models.finding import Finding

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
    return findings
  def list_buckets(self):
    response = self.awsclient.s3.list_buckets()
    return response["Buckets"]
  def check_public_access(self, bucket):
    response = self.awsclient.s3.get_public_access_block(Bucket=bucket)
    return all(
    value is True
    for value in response["PublicAccessBlockConfiguration"].values()
     )
  def check_encryption(self, bucket):
    response = self.awsclient.s3.get_bucket_encryption(Bucket=bucket)
    if response is None:
        return False
    else:
        return "ServerSideEncryptionConfiguration" in response

    