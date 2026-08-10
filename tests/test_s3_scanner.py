from app.scanners.s3_scanner import S3Scanner

class FakeS3Client:
    def list_buckets(self):
        return {
            "Buckets": [
                {"Name": "bucket1"},
                {"Name": "bucket2"},
                {"Name": "bucket3"}
            ]
        }
    def get_public_access_block(self,Bucket):
          configs = {
                "bucket1": {
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True}
                          },
                "bucket2": {
                    "PublicAccessBlockConfiguration": { 
                         
                        "BlockPublicAcls": False,
                        "IgnorePublicAcls": False,
                        "BlockPublicPolicy": False,
                        "RestrictPublicBuckets": False}
                          },
                "bucket3": {
                    "PublicAccessBlockConfiguration": { 
                         
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True}
                          }
                    }
          return configs[Bucket]
    def get_bucket_encryption(self, Bucket):
        if Bucket == "bucket1":
            return {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}
        elif Bucket == "bucket2":
            return None  
        else:
            return {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]}}
        

    

class FakeAWSClient:
    def __init__(self):
        self.s3 = FakeS3Client()


def test_s3_scanner():
            fake_aws_client = FakeAWSClient()
            scanner = S3Scanner(fake_aws_client)
            buckets = scanner.list_buckets()
    
            assert len(buckets) == 3
            bucket_names = [bucket["Name"] for bucket in buckets]
            assert "bucket1" in bucket_names
            assert "bucket2" in bucket_names
            assert "bucket3" in bucket_names

            bucket1_config = fake_aws_client.s3.get_public_access_block("bucket1")
            bucket2_config = fake_aws_client.s3.get_public_access_block("bucket2")
            bucket3_config = fake_aws_client.s3.get_public_access_block("bucket3")
            assert bucket1_config["PublicAccessBlockConfiguration"]["BlockPublicAcls"] is True
            assert bucket2_config["PublicAccessBlockConfiguration"]["BlockPublicAcls"] is False
            assert bucket3_config["PublicAccessBlockConfiguration"]["BlockPublicAcls"] is True
            assert scanner.check_public_access("bucket1") is True
            assert scanner.check_public_access("bucket2") is False 
            assert scanner.check_public_access("bucket3") is True

            findings = scanner.scan()
            assert len(findings) == 1
            assert findings[0].resource_type == "S3 Bucket"
            assert findings[0].resource_name == "bucket2"
            assert findings[0].check == "S3 PUBLIC ACCESS BLOCK"
            assert findings[0].severity == "High"
            assert findings[0].issue_resolved is False

            bucket1_config = fake_aws_client.s3.get_bucket_encryption(Bucket="bucket1")
            bucket2_config = fake_aws_client.s3.get_bucket_encryption(Bucket="bucket2")
            bucket3_config = fake_aws_client.s3.get_bucket_encryption(Bucket="bucket3")
            assert bucket1_config["ServerSideEncryptionConfiguration"]["Rules"][0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] == "AES256"
            assert bucket2_config is None
            assert bucket3_config["ServerSideEncryptionConfiguration"]["Rules"][0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] == "aws:kms"

            assert scanner.check_encryption("bucket1") is True
            assert scanner.check_encryption("bucket2") is False
            assert scanner.check_encryption("bucket3") is True