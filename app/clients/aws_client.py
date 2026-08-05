import boto3


class AWSClient:

    def __init__(self):
        self.iam = boto3.client("iam")
        self.s3 = boto3.client("s3")
        self.ec2 = boto3.client("ec2")