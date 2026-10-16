from botocore.exceptions import ClientError

from app.scanners.s3_scanner import S3Scanner


class FakeS3Client:
    def list_buckets(self):
        return {
            "Buckets": [
                {"Name": "bucket1"},
                {"Name": "bucket2"},
                {"Name": "bucket3"},
            ]
        }

    def get_public_access_block(self, Bucket):
        configs = {
            "bucket1": {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            },
            "bucket2": {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                }
            },
            "bucket3": {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            },
        }

        return configs[Bucket]

    def get_bucket_encryption(self, Bucket):
        if Bucket == "bucket1":
            return {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "AES256"
                            }
                        }
                    ]
                }
            }

        elif Bucket == "bucket2":
            raise ClientError(
                {
                    "Error": {
                        "Code": (
                            "ServerSideEncryptionConfigurationNotFoundError"
                        ),
                        "Message": (
                            "The server-side encryption configuration "
                            "was not found."
                        ),
                    }
                },
                "GetBucketEncryption",
            )

        else:
            return {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "aws:kms"
                            }
                        }
                    ]
                }
            }

    def get_bucket_versioning(self, Bucket):
        if Bucket == "bucket1":
            return {"Status": "Enabled"}

        elif Bucket == "bucket2":
            return {"Status": "Suspended"}

        else:
            return {}

    def get_bucket_logging(self, Bucket):
        if Bucket == "bucket1":
            return {
                "LoggingEnabled": {
                    "TargetBucket": "log-bucket",
                    "TargetPrefix": "bucket1-logs/",
                }
            }

        elif Bucket == "bucket2":
            return {}

        else:
            return {
                "LoggingEnabled": {
                    "TargetBucket": "log-bucket",
                    "TargetPrefix": "bucket3-logs/",
                }
            }


class FakeAWSClient:
    def __init__(self):
        self.s3 = FakeS3Client()


def test_s3_scanner():
    fake_aws_client = FakeAWSClient()
    scanner = S3Scanner(fake_aws_client)

    # Test bucket listing
    buckets = scanner.list_buckets()

    assert len(buckets) == 3

    bucket_names = [bucket["Name"] for bucket in buckets]

    assert "bucket1" in bucket_names
    assert "bucket2" in bucket_names
    assert "bucket3" in bucket_names

    # Test Public Access Block configurations
    bucket1_config = fake_aws_client.s3.get_public_access_block(
        Bucket="bucket1"
    )
    bucket2_config = fake_aws_client.s3.get_public_access_block(
        Bucket="bucket2"
    )
    bucket3_config = fake_aws_client.s3.get_public_access_block(
        Bucket="bucket3"
    )

    assert (
        bucket1_config["PublicAccessBlockConfiguration"]["BlockPublicAcls"]
        is True
    )
    assert (
        bucket2_config["PublicAccessBlockConfiguration"]["BlockPublicAcls"]
        is False
    )
    assert (
        bucket3_config["PublicAccessBlockConfiguration"]["BlockPublicAcls"]
        is True
    )

    assert scanner.check_public_access("bucket1") is True
    assert scanner.check_public_access("bucket2") is False
    assert scanner.check_public_access("bucket3") is True

    # Test encryption configurations
    bucket1_encryption = fake_aws_client.s3.get_bucket_encryption(
        Bucket="bucket1"
    )

    with __import__("pytest").raises(ClientError) as error:
        fake_aws_client.s3.get_bucket_encryption(Bucket="bucket2")

    assert (
        error.value.response["Error"]["Code"]
        == "ServerSideEncryptionConfigurationNotFoundError"
    )

    bucket3_encryption = fake_aws_client.s3.get_bucket_encryption(
        Bucket="bucket3"
    )

    assert (
        bucket1_encryption["ServerSideEncryptionConfiguration"]["Rules"][0][
            "ApplyServerSideEncryptionByDefault"
        ]["SSEAlgorithm"]
        == "AES256"
    )

    assert (
        bucket3_encryption["ServerSideEncryptionConfiguration"]["Rules"][0][
            "ApplyServerSideEncryptionByDefault"
        ]["SSEAlgorithm"]
        == "aws:kms"
    )

    # The scanner should handle the missing explicit configuration.
    # S3 applies default SSE-S3 encryption to objects.
    assert scanner.check_encryption("bucket1") is True
    assert scanner.check_encryption("bucket2") is True
    assert scanner.check_encryption("bucket3") is True

    # Test versioning
    assert scanner.check_versioning("bucket1") is True
    assert scanner.check_versioning("bucket2") is False
    assert scanner.check_versioning("bucket3") is False

    # Test logging
    assert scanner.check_logging("bucket1") is True
    assert scanner.check_logging("bucket2") is False
    assert scanner.check_logging("bucket3") is True

    # Test all findings
    findings = scanner.scan()

    assert len(findings) == 4

    # Verify the first finding
    assert findings[0].resource_type == "S3 Bucket"
    assert findings[0].resource_name == "bucket2"
    assert findings[0].check == "S3 PUBLIC ACCESS BLOCK"
    assert findings[0].severity == "High"
    assert findings[0].issue_resolved is False

    # Verify all expected findings
    expected_findings = {
        ("bucket2", "S3 PUBLIC ACCESS BLOCK"),
        ("bucket2", "S3 VERSIONING"),
        ("bucket2", "S3 LOGGING"),
        ("bucket3", "S3 VERSIONING"),
    }

    actual_findings = {
        (finding.resource_name, finding.check)
        for finding in findings
    }

    assert actual_findings == expected_findings