from app.scanners.iam_scanner import IAMScanner
from app.clients.aws_client import AWSClient

awsclient = AWSClient()

scanner = IAMScanner(awsclient)

