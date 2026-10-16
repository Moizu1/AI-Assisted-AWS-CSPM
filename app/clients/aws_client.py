import boto3


class AWSClient:

    def __init__(self, region_name="us-east-1"):
        self.iam = boto3.client("iam")
        self.s3 = boto3.client("s3", region_name=region_name)
        self.ec2 = boto3.client("ec2", region_name=region_name)
        self.rds = boto3.client("rds", region_name=region_name)
        self.cloudtrail = boto3.client("cloudtrail", region_name=region_name)